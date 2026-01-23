use crate::infrastructure::keys::backends::EnvSecretStore;
use crate::infrastructure::keys::types::SecretName;

#[test]
fn env_secret_store_parses_namespace_with_underscore() {
    std::env::set_var("IGRA_SECRET__igra_hd__wallet_secret", "plain_secret");
    let store = EnvSecretStore::new();
    let secret = store.get_cached(&SecretName::new("igra.hd.wallet_secret")).expect("secret present");
    assert_eq!(secret.expose_secret(), b"plain_secret");
}
