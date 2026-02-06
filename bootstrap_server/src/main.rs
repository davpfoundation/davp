use anyhow::Result;
use clap::Parser;
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use davp_bootstrap_server::start_server_with_shutdown;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use std::io::{stdout, Stdout};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::signal;
use tokio::sync::watch;

#[derive(Parser, Debug)]
#[command(name = "davp_bootstrap_server")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:9100")]
    bind: SocketAddr,

    #[arg(long)]
    public_ip: IpAddr,

    #[arg(long, default_value_t = 60)]
    ttl_seconds: i64,

    #[arg(long, default_value_t = true, help = "Allow loopback/private addresses for local testing")] 
    allow_loopback: bool,

    #[arg(long, default_value_t = false, help = "Run a libp2p gossipsub hub for NAT-friendly proof propagation")]
    p2p_hub: bool,

    #[arg(long, default_value = "0.0.0.0:4002", help = "Bind address for the libp2p hub (tcp)")]
    p2p_bind: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = start_server_with_shutdown(
        cli.bind,
        cli.ttl_seconds,
        shutdown_rx.clone(),
        cli.allow_loopback,
        Some(cli.public_ip),
    )
    .await?;

    let p2p_handle = if cli.p2p_hub {
        let mut shutdown_rx_p2p = shutdown_rx.clone();
        let bind = cli.p2p_bind;
        Some(tokio::spawn(async move {
            let _ = davp_bootstrap_server::run_p2p_hub(bind, &mut shutdown_rx_p2p).await;
        }))
    } else {
        None
    };

    let tui_setup = (|| -> Result<Terminal<CrosstermBackend<Stdout>>> {
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;
        Ok(Terminal::new(CrosstermBackend::new(stdout()))?)
    })();

    let res = match tui_setup {
        Ok(mut terminal) => {
            let res = run_tui(&mut terminal, cli.bind, cli.ttl_seconds, server).await;
            let _ = disable_raw_mode();
            let _ = stdout().execute(LeaveAlternateScreen);
            let _ = terminal.show_cursor();
            res
        }
        Err(e) => {
            let _ = disable_raw_mode();
            let _ = stdout().execute(LeaveAlternateScreen);
            eprintln!("CNT TUI failed to start: {}", e);
            eprintln!("CNT server is running in headless mode. Press Ctrl+C to stop.");
            signal::ctrl_c().await?;
            Ok(())
        }
    };

    let _ = shutdown_tx.send(true);
    if let Some(h) = p2p_handle {
        let _ = h.await;
    }
    res
}

async fn run_tui(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    bind: SocketAddr,
    ttl_seconds: i64,
    server: davp_bootstrap_server::CntServerHandle,
) -> Result<()> {
    loop {
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(k) = event::read()? {
                if k.code == KeyCode::Char('q') {
                    break;
                }
            }
        }

        let entries = server.entries().await;
        let now = chrono::Utc::now();

        terminal.draw(|f| {
            let area = f.area();
            let block = Block::default()
                .title(format!(
                    "DAVP CNT (Tracker) | bind={} | ttl={}s | q=quit",
                    bind,
                    ttl_seconds.max(5)
                ))
                .borders(Borders::ALL);
            let inner = block.inner(area);
            f.render_widget(block, area);

            let header = Row::new(vec![
                Cell::from("addr"),
                Cell::from("uptime_s"),
                Cell::from("first_seen"),
                Cell::from("expires_in_ms"),
                Cell::from("stable"),
                Cell::from("connected"),
                Cell::from("known"),
                Cell::from("last_seen"),
            ])
            .style(Style::default().add_modifier(Modifier::BOLD));

            let rows = entries.iter().map(|e| {
                let expires_ms = (e.expires_at - now).num_milliseconds().max(0);
                Row::new(vec![
                    Cell::from(e.addr.to_string()),
                    Cell::from(e.uptime_seconds.to_string()),
                    Cell::from(e.first_seen.to_rfc3339()),
                    Cell::from(expires_ms.to_string()),
                    Cell::from(if e.stable { "yes" } else { "no" }),
                    Cell::from(e.connected_peers.len().to_string()),
                    Cell::from(e.known_peers.len().to_string()),
                    Cell::from(e.last_seen.to_rfc3339()),
                ])
            });

            let table = Table::new(
                rows,
                [
                    Constraint::Length(22),
                    Constraint::Length(10),
                    Constraint::Min(20),
                    Constraint::Length(14),
                    Constraint::Length(7),
                    Constraint::Length(10),
                    Constraint::Length(10),
                    Constraint::Min(20),
                ],
            )
            .header(header)
            .block(Block::default().borders(Borders::ALL).title("Active peers"));

            f.render_widget(table, inner);
        })?;

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    Ok(())
}
