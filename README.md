# DAVP

Decentralized Asset Verification Protocol. DAVP is a program and protocol implementation for creating, storing, verifying, and replicating cryptographic proofs about arbitrary digital content (assets).

## How it works

- An asset is treated as opaque bytes (typically a file).
- DAVP computes a BLAKE3 hash of the bytes and binds it to metadata and a UTC timestamp.
- The binding is signed with an Ed25519 keypair.
- The resulting proof is stored locally and can be looked up by a 64-character `verification_id`.

## Demonstration
<img align="center" width="80%" src="https://github.com/davpfoundation/davp/blob/main/docs/davp_demo.png">
<p align="center"><i>Demo representation of DAVP in GUI mode</i></p>


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

## What DAVP does not try to do

- No blockchain, consensus, global ordering, or finality
- No global immutability guarantee across the network
- No claim of real-world identity or truth of metadata
- No global uniqueness guarantee for `verification_id`
  
## Issuer certificates

DAVP can label a proof creator key as certified by resolving an issuer certificate id against a `certs.json` bundle and verifying a CA signature plus validity window. This does not change the proof’s cryptographic validity; it is an additional identity layer.

## Networking and CNT

Nodes can replicate proofs over a simple TCP protocol (bincode messages) and gossip peer lists. CNT is a tracker/bootstrap server for peer discovery. Nodes report:

- Their listening address
- Their known peers
- Their currently connected peers

The server stores these reports with a TTL and returns a list of peer entries to help nodes find each other. CNT is discovery-only: it does not sign, certify, or validate proofs, and it has no authority over validity.


