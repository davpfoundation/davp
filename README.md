> [!WARNING]
> This is not feature-complete and its protocol, storage, and networking behavior may change without notice. Do not rely on it for production or long-term guarantees yet. Support state will indicated when the first release publishes.

# DAVP

Decentralized Asset Verification Protocol. DAVP is a program and protocol implementation for creating, storing, verifying, and replicating cryptographic proofs about arbitrary digital content (assets).

> DAVP was created because there wasn’t a simple way to prove that a file or piece of content really came from someone at a certain time. Most systems rely on **central servers** or **authorities**, which can **go down**, **be hacked**, or **lie**. With DAVP, you can create a proof locally, sign it with your key, and anyone can check it later, or even offline. You can also share proofs with other peers or link them to known issuers, **without** the need for a blockchain or a central authority. 


## Demonstration
<p align="center">
  <img src="https://raw.githubusercontent.com/davpfoundation/davp/refs/heads/main/docs/davp_demonstration.png">
</p>
<p align="center"><i>Demo representation of DAVP in GUI mode</i></p>



## How it works

- An asset is treated as opaque bytes (typically a file).
- DAVP computes a BLAKE3 hash of the bytes and binds it to metadata and a UTC timestamp.
- The binding is signed with an Ed25519 keypair.
- The resulting proof is stored locally and can be looked up by a 64-character `verification_id`.


## What a proof contains

- Asset hash (BLAKE3)
- Creator public key (Ed25519)
- Timestamp (UTC)
- Asset type and an `ai_assisted` flag
- Metadata (tags, optional description, optional parent verification id)
- Signature (Ed25519) over a serialized signing payload

The `verification_id` is a lookup identifier. Authenticity comes from the signature. Asset binding is performed when the verifier provides the asset bytes and the hash check matches.

## What “valid” means

A proof is cryptographically valid if:

- The Ed25519 signature verifies against the reconstructed signing payload and embedded public key.
- If asset bytes are provided, their BLAKE3 hash matches the hash embedded in the proof.

## What DAVP is NOT

- No global consensus, ordering, or finality
- No blockchain, mining, or consensus mechanism
- No global immutability guarantees across the network
- No truth claims about metadata or real-world identity of a key
- No global namespace or authority for verification IDs

DAVP avoids global consensus, blockchains, and trusted authorities. It is a simple, local-first protocol for cryptographic proofs.

## Issuer certificates

Optional identity labels that do not affect cryptographic validity. Certificates are fetched off-chain and can be used to associate proofs with known issuers.

Issuer certificates are an optional identity label layer. They do not change what makes a proof cryptographically valid.

- Valid proof: signature verifies (and if asset bytes are provided, hash matches).
- Certified proof: valid proof + issuer certificate validation succeeds for the referenced issuer_certificate_id.
- Uncertified proof: valid proof + no issuer_certificate_id, or certificate validation fails/not found.

Certificates are fetched from https://davpfoundation.github.io/certs.json by default. *We will soon migrate to a dedicated repository server*


## Networking and CNT

Nodes can replicate proofs over a simple TCP protocol (bincode messages) and gossip peer lists. CNT is a tracker/bootstrap server for peer discovery. Nodes report:

- Their listening address
- Their known peers
- Their currently connected peers

The server stores these reports with a TTL and returns a list of peer entries to help nodes find each other. CNT is discovery-only: it does not sign, certify, or validate proofs, and it has no authority over validity.

CNT is not a trusted authority. It is a hint system only.

- **Discovery is not trust.** Proof authenticity is verified locally by each node.
- **Fake peers are expected.** A Sybil attacker can flood CNT with random/unreachable addresses. This does not break proof security; it only wastes connection attempts.

Node behavior:

- Always try connecting to a peer before treating it as usable.
- Drop peers that fail to respond.
- Keep a small local set of peers that actually responded recently.
- Gossip/report only peers that were recently reachable.

CNT hygiene:

- Reports are stored with a short TTL (minutes, configurable).
- CNT rate-limits reports per source IP.
- CNT caps total stored entries to prevent unbounded growth.
