pub mod proof_storage {
    use std::fs::{File, OpenOptions, metadata};
    use std::io::{self, Write, BufReader, Read, Seek};
    use std::path::Path;
    use std::collections::HashMap;

    const SEGMENT_SIZE: usize = 256 * 1024 * 1024; // 256 MB
    const RECORD_SIZE: usize = 105; // 105 bytes per proof

    pub struct ProofRecord {
        pub proof_hash: [u8; 32],
        pub issuer_cert_id_hash: [u8; 32],
        pub creator_pubkey_hash: [u8; 32],
        pub timestamp: u64,
        pub flags: u8,
    }

    impl ProofRecord {
        pub fn to_bytes(&self) -> [u8; RECORD_SIZE] {
            let mut bytes = [0u8; RECORD_SIZE];
            bytes[..32].copy_from_slice(&self.proof_hash);
            bytes[32..64].copy_from_slice(&self.issuer_cert_id_hash);
            bytes[64..96].copy_from_slice(&self.creator_pubkey_hash);
            bytes[96..104].copy_from_slice(&self.timestamp.to_le_bytes());
            bytes[104] = self.flags;
            bytes
        }
    }

    pub struct ProofIndex {
        index: HashMap<[u8; 32], (u32, u64)>,
    }

    impl ProofIndex {
        pub fn new() -> Self {
            ProofIndex {
                index: HashMap::new(),
            }
        }

        pub fn rebuild_index(&mut self) -> io::Result<()> {
            let mut segment_id = 1;
            loop {
                let segment_file = format!("data/proofs/segment_{:04}.dat", segment_id);
                let path = Path::new(&segment_file);
                if !path.exists() {
                    break;
                }

                let file = File::open(path)?;
                let mut reader = BufReader::new(file);
                let mut offset = 0u64;
                let mut buffer = [0u8; RECORD_SIZE];

                while reader.read_exact(&mut buffer).is_ok() {
                    let proof_hash = &buffer[..32];
                    self.index.insert(proof_hash.try_into().unwrap(), (segment_id, offset));
                    offset += RECORD_SIZE as u64;
                }

                segment_id += 1;
            }
            Ok(())
        }
    }

    pub fn get_index() -> ProofIndex {
        let mut index = ProofIndex::new();
        index.rebuild_index().unwrap();
        index
    }

    pub fn append_proof(proof: ProofRecord, segment_id: u32) -> io::Result<()> {
        let segment_file = format!("data/proofs/segment_{:04}.dat", segment_id);
        let path = Path::new(&segment_file);
        let mut file = if path.exists() {
            OpenOptions::new().append(true).open(path)?
        } else {
            File::create(path)?
        };

        file.write_all(&proof.to_bytes())?;
        Ok(())
    }

    pub fn write_proof(proof: ProofRecord, index: &mut ProofIndex) -> io::Result<()> {
        let mut segment_id = 1;
        let mut offset = 0u64;

        loop {
            let segment_file = format!("data/proofs/segment_{:04}.dat", segment_id);
            let path = Path::new(&segment_file);

            if path.exists() {
                let metadata = metadata(path)?;
                if metadata.len() + RECORD_SIZE as u64 <= SEGMENT_SIZE as u64 {
                    offset = metadata.len();
                    append_proof(proof, segment_id)?;
                    index.index.insert(proof.proof_hash, (segment_id, offset));
                    break;
                }
            } else {
                append_proof(proof, segment_id)?;
                index.index.insert(proof.proof_hash, (segment_id, offset));
                break;
            }

            segment_id += 1;
        }

        Ok(())
    }

    pub fn verify_proof(proof_hash: &[u8; 32], index: &ProofIndex) -> Result<(), &'static str> {
        if let Some(&(segment_id, offset)) = index.index.get(proof_hash) {
            let segment_file = format!("data/proofs/segment_{:04}.dat", segment_id);
            let path = Path::new(&segment_file);
            let file = File::open(path).map_err(|_| "Segment file not found")?;
            let mut reader = BufReader::new(file);
            reader.seek(io::SeekFrom::Start(offset)).map_err(|_| "Seek failed")?;

            let mut buffer = [0u8; RECORD_SIZE];
            reader.read_exact(&mut buffer).map_err(|_| "Read failed")?;

            // Verify signature and fetch issuer cert (pseudo-code)
            if verify_signature(&buffer) && fetch_issuer_cert(&buffer) {
                return Ok(());
            } else {
                return Err("Verification failed");
            }
        }
        Err("Proof not found")
    }

    fn verify_signature(_buffer: &[u8]) -> bool {
        // Placeholder for signature verification logic
        true
    }

    fn fetch_issuer_cert(_buffer: &[u8]) -> bool {
        // Placeholder for fetching issuer certificate logic
        true
    }
}
