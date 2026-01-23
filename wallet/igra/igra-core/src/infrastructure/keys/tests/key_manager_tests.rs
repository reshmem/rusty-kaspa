use crate::infrastructure::keys::{backends::EnvSecretStore, LocalKeyManager, NoopAuditLogger};
use crate::infrastructure::keys::{KeyManager, KeyRef, SignatureScheme, SigningPayload};
use std::sync::Arc;

#[tokio::test]
async fn local_key_manager_schnorr_signing() {
    std::env::set_var("IGRA_SECRET__test__schnorr_key", "hex:0000000000000000000000000000000000000000000000000000000000000001");
    let secret_store = Arc::new(EnvSecretStore::new());
    let audit_log = Arc::new(NoopAuditLogger);
    let key_manager = Arc::new(LocalKeyManager::new(secret_store, audit_log));

    let key_ref = KeyRef::new("test", "schnorr_key");
    let signature =
        key_manager.sign(&key_ref, SignatureScheme::Secp256k1Schnorr, SigningPayload::Message(b"hello world")).await.unwrap();
    assert_eq!(signature.len(), 64);

    let pubkey = key_manager.public_key(&key_ref, SignatureScheme::Secp256k1Schnorr).await.unwrap();
    assert_eq!(pubkey.len(), 32);
}
