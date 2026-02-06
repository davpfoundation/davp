use crate::modules::asset::Proof;
use crate::modules::certification::PublishedProof;
use crate::modules::storage::Storage;
use anyhow::{Context, Result};
use futures::{prelude::*, select};
use libp2p::gossipsub::{self, Gossipsub, GossipsubConfig, GossipsubEvent, IdentTopic, MessageAuthenticity};
use libp2p::identity;
use libp2p::kad::{record::store::MemoryStore, Kademlia};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Transport};
use libp2p::{tcp, yamux, noise};
use std::time::Duration;
use tokio::sync::mpsc;

/// Commands the application can send to the P2P subsystem.
#[derive(Debug)]
pub enum P2pCommand {
    PublishProof(Proof),
    PublishPublishedProof(PublishedProof),
}

/// Events emitted from the P2P subsystem to the application.
#[derive(Debug)]
pub enum P2pEvent {}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "P2pBehaviourEvent")]
struct P2pBehaviour {
    gossipsub: Gossipsub,
    kademlia: Kademlia<MemoryStore>,
}

enum P2pBehaviourEvent {
    Gossipsub(GossipsubEvent),
    Kademlia(()), // placeholder
}

impl From<GossipsubEvent> for P2pBehaviourEvent {
    fn from(e: GossipsubEvent) -> Self {
        Self::Gossipsub(e)
    }
}

impl From<()> for P2pBehaviourEvent {
    fn from(_: ()) -> Self {
        Self::Kademlia(())
    }
}

/// Starts a libp2p node bound on the given port. Returns a handle that can be used
/// by the application to interact with the network.
pub async fn start_p2p(
    storage: Storage,
    port: u16,
    seed_peers: Vec<Multiaddr>,
) -> Result<mpsc::UnboundedSender<P2pCommand>> {
    // Generate a random peer identity each start. TODO: persist identity.
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());
    println!("Local peer id: {}", peer_id);

    // Set up an encrypted TCP transport over the Mplex/Yamux protocol.
    let transport = tcp::tokio::Transport::default()
        .upgrade(libp2p::core::upgrade::Version::V1Lazy)
        .authenticate(noise::NoiseAuthenticated::xx(&id_keys).context("noise")?)
        .multiplex(yamux::YamuxConfig::default())
        .boxed();

    // Create gossipsub.
    let mut gossipsub_config = GossipsubConfig::default();
    gossipsub_config.max_transmit_size = 1_048_576; // 1 MiB
    gossipsub_config.validation_mode = gossipsub::ValidationMode::Anonymous;
    let mut gossipsub = Gossipsub::new(MessageAuthenticity::Anonymous, gossipsub_config)?;

    let proof_topic = IdentTopic::new("davp-proof");
    let published_topic = IdentTopic::new("davp-published-proof");
    gossipsub.subscribe(&proof_topic)?;
    gossipsub.subscribe(&published_topic)?;

    // Kademlia for peer discovery.
    let store = MemoryStore::new(peer_id);
    let mut kademlia = Kademlia::new(peer_id, store);

    // Combine behaviours.
    let behaviour = P2pBehaviour { gossipsub, kademlia };

    let mut swarm = Swarm::with_tokio_executor(transport, behaviour, peer_id);

    // Listen on all interfaces & the configured port.
    Swarm::listen_on(&mut swarm, format!("/ip4/0.0.0.0/tcp/{port}").parse()?)?;

    // Dial bootstrap peers.
    for addr in seed_peers {
        swarm.dial(addr.clone())?;
    }

    // Channels for command/event.
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<P2pCommand>();

    // Spawn swarm event loop.
    tokio::spawn(async move {
        // Wrap storage in Arc for sharing.
        let storage = std::sync::Arc::new(storage);
        loop {
            select! {
                event = swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(P2pBehaviourEvent::Gossipsub(e)) => {
                        if let GossipsubEvent::Message{ message, .. } = e {
                            if message.topic == proof_topic.hash() {
                                if let Ok(p) = bincode::deserialize::<Proof>(&message.data) {
                                    if !storage.contains(&p.verification_id) {
                                        if let Err(e) = storage.store_proof(&p) {
                                            eprintln!("store proof error: {e}");
                                        }
                                    }
                                }
                            } else if message.topic == published_topic.hash() {
                                if let Ok(pubp) = bincode::deserialize::<PublishedProof>(&message.data) {
                                    if !storage.contains(&pubp.proof.verification_id) {
                                        let _ = storage.store_published_proof(&pubp);
                                    }
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(P2pBehaviourEvent::Kademlia(_)) => {},
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("Listening on {address}");
                    }
                    _ => {}
                },
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        P2pCommand::PublishProof(p) => {
                            let _ = swarm.behaviour_mut().gossipsub.publish(proof_topic.clone(), bincode::serialize(&p).unwrap());
                        },
                        P2pCommand::PublishPublishedProof(pp) => {
                            let _ = swarm.behaviour_mut().gossipsub.publish(published_topic.clone(), bincode::serialize(&pp).unwrap());
                        },
                    }
                }
            }
        }
    });

    Ok(cmd_tx)
}
