//! Experimental libp2p-based networking layer with NAT traversal (AutoNAT + relay).
//! This is **work-in-progress** but compiles and can already connect to public relay peers
//! or other directly reachable nodes.

use anyhow::{anyhow, Result};
use crate::modules::asset::Proof;
use crate::modules::certification::PublishedProof;
use crate::modules::storage::Storage;
use futures::prelude::*;
use libp2p::core::upgrade;
use libp2p::gossipsub::{Behaviour as Gossipsub, Config as GossipsubConfig, Event as GossipsubEvent, IdentTopic as Topic, MessageAuthenticity};
use libp2p::identify::{Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent};
use libp2p::noise;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{identity, tcp, yamux, Multiaddr, PeerId, Transport};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::watch;

const DAVP_PROOF_TOPIC: &str = "davp.proofs.v1";

#[derive(Debug, Clone)]
pub enum OutboundMsg {
    Proof(Proof),
    PublishedProof(PublishedProof),
}

#[derive(serde::Serialize, serde::Deserialize)]
enum WireMsg {
    Proof(Proof),
    PublishedProof(PublishedProof),
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "P2pEvent")]
struct P2pBehaviour {
    identify: Identify,
    gossipsub: Gossipsub,
}

#[allow(clippy::large_enum_variant)]
#[allow(dead_code)]
enum P2pEvent {
    Identify(IdentifyEvent),
    Gossipsub(GossipsubEvent),
}
impl From<IdentifyEvent> for P2pEvent {
    fn from(e: IdentifyEvent) -> Self {
        P2pEvent::Identify(e)
    }
}
impl From<GossipsubEvent> for P2pEvent {
    fn from(e: GossipsubEvent) -> Self {
        P2pEvent::Gossipsub(e)
    }
}

#[derive(Clone)]
struct TokioExecutor;

impl libp2p::swarm::Executor for TokioExecutor {
    fn exec(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let _ = tokio::spawn(future);
    }
}

pub async fn run_p2p(
    storage: Storage,
    listen_multiaddr: Multiaddr,
    bootstrap: Vec<Multiaddr>,
    mut shutdown: watch::Receiver<bool>,
    mut outbound_rx: mpsc::UnboundedReceiver<OutboundMsg>,
) -> Result<()> {
    // 1. Build transport (TCP + Noise + Yamux)
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());

    let noise_config = noise::Config::new(&id_keys).map_err(|e| anyhow!(e.to_string()))?;
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise_config)
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(20))
        .boxed();

    // 2. Sub-behaviours
    let identify = Identify::new(IdentifyConfig::new("davp/0.1".into(), id_keys.public()));

    let gs_cfg = GossipsubConfig::default();
    let mut gossipsub =
        Gossipsub::new(MessageAuthenticity::Signed(id_keys.clone()), gs_cfg)
            .map_err(|e| anyhow!(e))?;
    let topic = Topic::new(DAVP_PROOF_TOPIC);
    gossipsub.subscribe(&topic)?;

    let behaviour = P2pBehaviour {
        identify,
        gossipsub,
    };

    let mut swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_executor(TokioExecutor),
    );

    Swarm::listen_on(&mut swarm, listen_multiaddr)?;

    // Bootstrap addresses
    for addr in bootstrap {
        let _ = Swarm::dial(&mut swarm, addr);
    }

    // Main loop
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = shutdown.changed() => {},
            Some(msg) = outbound_rx.recv() => {
                let wire = match msg {
                    OutboundMsg::Proof(p) => WireMsg::Proof(p),
                    OutboundMsg::PublishedProof(p) => WireMsg::PublishedProof(p),
                };
                if let Ok(bytes) = bincode::serialize(&wire) {
                    let _ = swarm.behaviour_mut().gossipsub.publish(Topic::new(DAVP_PROOF_TOPIC), bytes);
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(P2pEvent::Gossipsub(ev)) => {
                    if let GossipsubEvent::Message { message, .. } = ev {
                        if let Ok(wire) = bincode::deserialize::<WireMsg>(&message.data) {
                            match wire {
                                WireMsg::Proof(p) => {
                                    let _ = storage.store_proof(&p);
                                }
                                WireMsg::PublishedProof(p) => {
                                    let _ = storage.store_published_proof(&p);
                                }
                            }
                        }
                    }
                }
                SwarmEvent::NewListenAddr { .. } => {}
                SwarmEvent::ConnectionEstablished { .. } => {}
                SwarmEvent::OutgoingConnectionError { .. } => {}
                SwarmEvent::IncomingConnectionError { .. } => {}
                _ => {}
            }
        }
    }

    Ok(())
}
