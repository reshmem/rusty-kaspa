use igra_core::infrastructure::keys::{FileSecretStore, SecretBytes, SecretName, SecretStore};
use tempfile::TempDir;

#[tokio::test]
async fn secret_cache_ttl_allows_reload_after_expiry() {
    let temp_dir = TempDir::new().expect("test setup: temp dir");
    let secrets_path = temp_dir.path().join("secrets.bin");

    let store = FileSecretStore::create(&secrets_path, "test-passphrase").await.expect("create store");
    let name = SecretName::new("igra.test.secret_cache_ttl");
    let value = SecretBytes::from_slice(b"integration_test_value");

    store.set(name.clone(), value.clone()).await.expect("set secret");
    store.save().await.expect("save");

    let first = store.get(&name).await.expect("get secret");
    assert_eq!(first.expose_secret(), value.expose_secret());

    store.expire_cache_entry_for_test(&name).await;

    let second = store.get(&name).await.expect("get after expiry");
    assert_eq!(second.expose_secret(), value.expose_secret());
}
