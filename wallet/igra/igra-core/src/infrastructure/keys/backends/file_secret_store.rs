//! Encrypted file-based secret store.

use crate::foundation::ThresholdError;
use crate::infrastructure::keys::backends::file_format::{Argon2Params, SecretFile, SecretMap};
use crate::infrastructure::keys::secret_store::{SecretBytes, SecretStore};
use crate::infrastructure::keys::types::SecretName;
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

pub struct FileSecretStore {
    file_path: PathBuf,
    cache: tokio::sync::RwLock<HashMap<SecretName, SecretBytes>>,
}

impl FileSecretStore {
    pub async fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, ThresholdError> {
        let path = path.as_ref();
        #[cfg(target_family = "unix")]
        Self::validate_file_permissions(path)?;

        let data = tokio::fs::read(path)
            .await
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to read secrets file: {}", e)))?;

        let file = SecretFile::from_bytes(&data)?;
        let mut secret_map = file.decrypt(passphrase)?;
        let mut cache = HashMap::new();
        for (name, bytes) in secret_map.secrets.drain() {
            cache.insert(name, SecretBytes::new(bytes));
        }
        log::info!("Loaded {} secrets from {}", cache.len(), path.display());
        Ok(Self { file_path: path.to_path_buf(), cache: tokio::sync::RwLock::new(cache) })
    }

    pub async fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, ThresholdError> {
        let path = path.as_ref();
        if path.exists() {
            return Err(ThresholdError::secret_store_unavailable("file", format!("Secrets file already exists: {}", path.display())));
        }
        let secret_map = SecretMap { secrets: HashMap::new() };
        let file = SecretFile::encrypt(&secret_map, passphrase, Argon2Params::default())?;
        let bytes = file.to_bytes()?;
        tokio::fs::write(path, &bytes)
            .await
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to write secrets file: {}", e)))?;
        #[cfg(target_family = "unix")]
        Self::set_file_permissions(path)?;
        log::info!("Created new secrets file: {}", path.display());
        Ok(Self { file_path: path.to_path_buf(), cache: tokio::sync::RwLock::new(HashMap::new()) })
    }

    pub async fn open_or_create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, ThresholdError> {
        let path = path.as_ref();
        if path.exists() {
            Self::open(path, passphrase).await
        } else {
            Self::create(path, passphrase).await
        }
    }

    pub async fn set(&self, name: SecretName, secret: SecretBytes) -> Result<(), ThresholdError> {
        let mut cache = self.cache.write().await;
        cache.insert(name, secret);
        Ok(())
    }

    pub async fn remove(&self, name: &SecretName) -> Result<(), ThresholdError> {
        let mut cache = self.cache.write().await;
        cache.remove(name);
        Ok(())
    }

    pub async fn save(&self, passphrase: &str) -> Result<(), ThresholdError> {
        let cache = self.cache.read().await;
        let mut secret_map = SecretMap { secrets: HashMap::new() };
        for (name, bytes) in cache.iter() {
            secret_map.secrets.insert(name.clone(), bytes.expose_secret().to_vec());
        }
        let file = SecretFile::encrypt(&secret_map, passphrase, Argon2Params::default())?;
        let bytes = file.to_bytes()?;

        let temp_path = self.file_path.with_extension("tmp");
        tokio::fs::write(&temp_path, &bytes)
            .await
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to write secrets file: {}", e)))?;
        tokio::fs::rename(&temp_path, &self.file_path)
            .await
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to rename secrets file: {}", e)))?;
        #[cfg(target_family = "unix")]
        Self::set_file_permissions(&self.file_path)?;
        Ok(())
    }

    #[cfg(target_family = "unix")]
    fn validate_file_permissions(path: &Path) -> Result<(), ThresholdError> {
        use std::os::unix::fs::MetadataExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to stat secrets file: {}", e)))?
            .mode()
            & 0o777;
        if mode != 0o600 {
            return Err(ThresholdError::InsecureFilePermissions { path: path.display().to_string(), mode });
        }
        Ok(())
    }

    #[cfg(target_family = "unix")]
    fn set_file_permissions(path: &Path) -> Result<(), ThresholdError> {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to stat secrets file: {}", e)))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to set secrets file permissions: {}", e)))?;
        Ok(())
    }
}

impl SecretStore for FileSecretStore {
    fn backend(&self) -> &'static str {
        "file"
    }

    fn get<'a>(&'a self, name: &'a SecretName) -> Pin<Box<dyn Future<Output = Result<SecretBytes, ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            let cache = self.cache.read().await;
            cache.get(name).cloned().ok_or_else(|| ThresholdError::secret_not_found(name.as_str(), "file"))
        })
    }

    fn list_secrets<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Vec<SecretName>, ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            let cache = self.cache.read().await;
            Ok(cache.keys().cloned().collect())
        })
    }
}
