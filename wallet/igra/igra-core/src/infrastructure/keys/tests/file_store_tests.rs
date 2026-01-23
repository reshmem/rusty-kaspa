use crate::infrastructure::keys::backends::FileSecretStore;
use crate::infrastructure::keys::secret_store::SecretBytes;
use crate::infrastructure::keys::secret_store::SecretStore;
use crate::infrastructure::keys::types::SecretName;

#[tokio::test]
async fn file_secret_store_roundtrip() {
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("secrets.bin");

    let store = FileSecretStore::create(&file_path, "testpass").await.unwrap();
    store.set(SecretName::new("test.key"), SecretBytes::new(b"secret_value".to_vec())).await.unwrap();
    store.save("testpass").await.unwrap();

    let store2 = FileSecretStore::open(&file_path, "testpass").await.unwrap();
    let secret = store2.get(&SecretName::new("test.key")).await.unwrap();
    assert_eq!(secret.expose_secret(), b"secret_value");
}
