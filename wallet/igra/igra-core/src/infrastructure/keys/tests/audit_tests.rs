use crate::infrastructure::keys::{backends::EnvSecretStore, FileAuditLogger, KeyManagerContext, LocalKeyManager, NoopAuditLogger};
use crate::infrastructure::keys::{KeyRef, SignatureScheme, SigningPayload};
use std::sync::Arc;

#[tokio::test]
async fn key_manager_context_writes_audit_log() {
    let temp_dir = tempfile::tempdir().unwrap();
    let audit_path = temp_dir.path().join("audit.log");

    std::env::set_var("IGRA_SECRET__test__key", "hex:0000000000000000000000000000000000000000000000000000000000000001");

    let secret_store = Arc::new(EnvSecretStore::new());
    let audit_log = Arc::new(FileAuditLogger::new(&audit_path).unwrap());
    let key_manager = Arc::new(LocalKeyManager::new(secret_store, Arc::new(NoopAuditLogger)));

    let ctx = KeyManagerContext::with_new_request_id(key_manager, audit_log);
    let key_ref = KeyRef::new("test", "key");
    let _sig = ctx.sign_with_audit(&key_ref, SignatureScheme::Secp256k1Schnorr, SigningPayload::Message(b"test")).await.unwrap();

    let content = std::fs::read_to_string(&audit_path).unwrap();
    assert!(content.contains("\"event_type\":\"signing\""));
    assert!(content.contains("test.key"));
}
