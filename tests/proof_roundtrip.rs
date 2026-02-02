use davp::modules::asset::create_proof_from_bytes;
use davp::modules::metadata::{AssetType, Metadata};
use davp::modules::storage::Storage;
use davp::modules::verification::verify_proof;
use davp::KeypairBytes;
use rand::Rng;
use std::path::PathBuf;

#[test]
fn proof_roundtrip_store_and_verify() {
    let content = b"hello davp";
    let keypair = KeypairBytes::generate();

    let metadata = Metadata::new(
        Some(vec!["tag1".to_string()]),
        Some("desc".to_string()),
        None,
    );
    let proof =
        create_proof_from_bytes(content, AssetType::Text, false, metadata, &keypair).unwrap();

    verify_proof(&proof, Some(content)).unwrap();

    let mut rng = rand::thread_rng();
    let dir = std::env::temp_dir().join(format!("davp_test_{}", rng.gen::<u64>()));
    let storage = Storage::new(PathBuf::from(&dir));
    storage.store_proof(&proof).unwrap();

    let loaded = storage.retrieve_proof(&proof.verification_id).unwrap();
    verify_proof(&loaded, Some(content)).unwrap();

    let _ = std::fs::remove_dir_all(dir);
}
