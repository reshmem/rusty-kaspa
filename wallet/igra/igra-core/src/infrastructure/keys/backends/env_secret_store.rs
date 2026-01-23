//! Environment variable based secret store (devnet/CI only).

use crate::foundation::ThresholdError;
use crate::infrastructure::keys::secret_store::{SecretBytes, SecretStore};
use crate::infrastructure::keys::types::SecretName;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

pub const ENV_PREFIX: &str = "IGRA_SECRET__";

pub struct EnvSecretStore {
    cache: HashMap<SecretName, SecretBytes>,
}

impl EnvSecretStore {
    pub fn new() -> Self {
        let mut cache = HashMap::new();

        for (key, value) in std::env::vars() {
            if let Some(raw_name) = key.strip_prefix(ENV_PREFIX) {
                if let Some(secret_name) = Self::parse_env_name(raw_name) {
                    match Self::decode_value(&value) {
                        Ok(bytes) => {
                            log::debug!("loaded secret from env name={}", secret_name);
                            cache.insert(secret_name, bytes);
                        }
                        Err(err) => {
                            log::warn!("failed to decode env secret name={} error={}", secret_name, err);
                        }
                    }
                }
            }
        }

        // Legacy compatibility: `KASPA_IGRA_WALLET_SECRET` -> `igra.hd.wallet_secret`
        if let Ok(value) = std::env::var(crate::infrastructure::config::HD_WALLET_SECRET_ENV) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                cache.entry(SecretName::new("igra.hd.wallet_secret")).or_insert_with(|| SecretBytes::new(trimmed.as_bytes().to_vec()));
            }
        }

        log::info!("EnvSecretStore loaded {} secrets", cache.len());
        Self { cache }
    }

    fn parse_env_name(raw: &str) -> Option<SecretName> {
        let mut parts = raw.split("__");
        let namespace = parts.next()?.trim();
        if namespace.is_empty() {
            return None;
        }
        let namespace = namespace.replace('_', ".");
        let rest: Vec<&str> = parts.filter(|s| !s.trim().is_empty()).collect();
        if rest.is_empty() {
            return None;
        }
        Some(SecretName::new(format!("{}.{}", namespace, rest.join("."))))
    }

    fn decode_value(value: &str) -> Result<SecretBytes, ThresholdError> {
        if let Some(hex_data) = value.strip_prefix("hex:") {
            let bytes = hex::decode(hex_data)
                .map_err(|e| ThresholdError::secret_decode_failed("env_var", "hex", format!("hex decode failed: {}", e)))?;
            Ok(SecretBytes::new(bytes))
        } else if let Some(b64_data) = value.strip_prefix("b64:") {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            let bytes = STANDARD
                .decode(b64_data)
                .map_err(|e| ThresholdError::secret_decode_failed("env_var", "base64", format!("base64 decode failed: {}", e)))?;
            Ok(SecretBytes::new(bytes))
        } else {
            Ok(SecretBytes::new(value.as_bytes().to_vec()))
        }
    }

    pub fn get_cached(&self, name: &SecretName) -> Option<SecretBytes> {
        self.cache.get(name).cloned()
    }
}

impl Default for EnvSecretStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for EnvSecretStore {
    fn backend(&self) -> &'static str {
        "env"
    }

    fn get<'a>(&'a self, name: &'a SecretName) -> Pin<Box<dyn Future<Output = Result<SecretBytes, ThresholdError>> + Send + 'a>> {
        Box::pin(async move { self.cache.get(name).cloned().ok_or_else(|| ThresholdError::secret_not_found(name.as_str(), "env")) })
    }

    fn list_secrets<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Vec<SecretName>, ThresholdError>> + Send + 'a>> {
        Box::pin(async move { Ok(self.cache.keys().cloned().collect()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex() {
        std::env::set_var("IGRA_SECRET__test__hex_key", "hex:deadbeef");
        let store = EnvSecretStore::new();
        let secret = store.get_cached(&SecretName::new("test.hex_key")).unwrap();
        assert_eq!(secret.expose_secret(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_decode_base64() {
        std::env::set_var("IGRA_SECRET__test__b64_key", "b64:aGVsbG8=");
        let store = EnvSecretStore::new();
        let secret = store.get_cached(&SecretName::new("test.b64_key")).unwrap();
        assert_eq!(secret.expose_secret(), b"hello");
    }

    #[test]
    fn test_decode_utf8() {
        std::env::set_var("IGRA_SECRET__test__utf8_key", "plain_secret");
        let store = EnvSecretStore::new();
        let secret = store.get_cached(&SecretName::new("test.utf8_key")).unwrap();
        assert_eq!(secret.expose_secret(), b"plain_secret");
    }
}
