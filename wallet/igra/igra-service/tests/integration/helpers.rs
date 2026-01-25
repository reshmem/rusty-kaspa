use igra_core::foundation::ThresholdError;
use igra_core::infrastructure::keys::{
    KeyAuditLogger, KeyManager, LocalKeyManager, NoopAuditLogger, SecretBytes, SecretName, SecretStore,
};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub struct MapSecretStore {
    secrets: HashMap<SecretName, SecretBytes>,
}

impl MapSecretStore {
    pub fn new(secrets: HashMap<SecretName, SecretBytes>) -> Self {
        Self { secrets }
    }
}

impl SecretStore for MapSecretStore {
    fn backend(&self) -> &'static str {
        "map"
    }

    fn get<'a>(&'a self, name: &'a SecretName) -> Pin<Box<dyn Future<Output = Result<SecretBytes, ThresholdError>> + Send + 'a>> {
        Box::pin(async move { self.secrets.get(name).cloned().ok_or_else(|| ThresholdError::secret_not_found(name.as_str(), "map")) })
    }

    fn list_secrets<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Vec<SecretName>, ThresholdError>> + Send + 'a>> {
        Box::pin(async move { Ok(self.secrets.keys().cloned().collect()) })
    }
}

pub fn key_manager_with_secrets(secrets: HashMap<SecretName, SecretBytes>) -> (Arc<dyn KeyManager>, Arc<dyn KeyAuditLogger>) {
    let audit_log: Arc<dyn KeyAuditLogger> = Arc::new(NoopAuditLogger);
    let secret_store = Arc::new(MapSecretStore::new(secrets));
    let key_manager: Arc<dyn KeyManager> = Arc::new(LocalKeyManager::new(secret_store, audit_log.clone()));
    (key_manager, audit_log)
}

pub fn key_manager_with_signer_mnemonic(profile: &str, mnemonic: &str) -> (Arc<dyn KeyManager>, Arc<dyn KeyAuditLogger>) {
    let name = SecretName::new(format!("igra.signer.mnemonic_{}", profile.trim()));
    let secrets = HashMap::from([(name, SecretBytes::new(mnemonic.as_bytes().to_vec()))]);
    key_manager_with_secrets(secrets)
}
