use crate::infrastructure::keys::backends::EnvSecretStore;
use crate::infrastructure::keys::types::SecretName;

#[test]
fn env_secret_store_parses_namespace_with_underscore() {
    std::env::set_var(
        "IGRA_SECRET__igra_signer__mnemonic_signer_01",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    let store = EnvSecretStore::new();
    let secret = store.get_cached(&SecretName::new("igra.signer.mnemonic_signer_01")).expect("secret present");
    assert!(!secret.expose_secret().is_empty());
}
