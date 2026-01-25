//! Encrypted file-based secret store.

use crate::foundation::ThresholdError;
use crate::infrastructure::keys::backends::file_format::{Argon2Params, RotationMetadata, SecretFile, SecretMap};
use crate::infrastructure::keys::secret_store::{SecretBytes, SecretStore};
use crate::infrastructure::keys::types::SecretName;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Time-to-live for cached secrets in memory (production).
#[cfg(not(test))]
const PRODUCTION_CACHE_TTL_SECS: u64 = 300;

/// Time-to-live for cached secrets in memory (tests).
#[cfg(test)]
const TEST_CACHE_TTL_SECS: u64 = 2;

/// Interval for background cache cleanup task (production).
#[cfg(not(test))]
const PRODUCTION_CLEANUP_INTERVAL_SECS: u64 = 60;

/// Interval for background cache cleanup task (tests).
#[cfg(test)]
const TEST_CLEANUP_INTERVAL_SECS: u64 = 1;

/// Grace period after TTL before forcing eviction (production).
#[cfg(not(test))]
const PRODUCTION_GRACE_PERIOD_SECS: u64 = 5;

/// Grace period after TTL before forcing eviction (tests).
#[cfg(test)]
const TEST_GRACE_PERIOD_SECS: u64 = 1;

/// Active TTL based on build configuration.
#[cfg(not(test))]
const SECRET_CACHE_TTL_SECS: u64 = PRODUCTION_CACHE_TTL_SECS;
#[cfg(test)]
const SECRET_CACHE_TTL_SECS: u64 = TEST_CACHE_TTL_SECS;

/// Active cleanup interval based on build configuration.
#[cfg(not(test))]
const CACHE_CLEANUP_INTERVAL_SECS: u64 = PRODUCTION_CLEANUP_INTERVAL_SECS;
#[cfg(test)]
const CACHE_CLEANUP_INTERVAL_SECS: u64 = TEST_CLEANUP_INTERVAL_SECS;

/// Active grace period based on build configuration.
#[cfg(not(test))]
const CACHE_GRACE_PERIOD_SECS: u64 = PRODUCTION_GRACE_PERIOD_SECS;
#[cfg(test)]
const CACHE_GRACE_PERIOD_SECS: u64 = TEST_GRACE_PERIOD_SECS;

/// Maximum number of secrets to cache before forcing eviction.
const MAX_CACHED_SECRETS: usize = 100;

/// Keep fraction numerator when evicting LRU entries (keep 90%).
const CACHE_KEEP_NUM: usize = 9;

/// Keep fraction denominator when evicting LRU entries (keep 90%).
const CACHE_KEEP_DEN: usize = 10;

/// Maximum time to wait for cleanup task shutdown in Drop (milliseconds).
#[cfg(test)]
const DROP_CLEANUP_WAIT_MS: u64 = 100;

/// Duration to expire cache entries in tests (seconds).
#[cfg(any(test, feature = "test-utils"))]
const TEST_CACHE_EXPIRE_OFFSET_SECS: u64 = 1;

/// Duration to wait for cleanup task shutdown in tests (milliseconds).
#[cfg(any(test, feature = "test-utils"))]
const TEST_CLEANUP_SHUTDOWN_WAIT_MS: u64 = 50;

/// Number of test secrets to create in cleanup test.
#[cfg(test)]
const TEST_SECRET_COUNT: usize = 10;

/// Number of extra secrets beyond max to test LRU eviction.
#[cfg(test)]
const TEST_OVERFILL_SECRET_COUNT: usize = 10;

#[derive(Clone)]
struct CachedSecret {
    value: SecretBytes,
    expires_at: Instant,
    access_count: u64,
}

impl CachedSecret {
    fn new(value: SecretBytes) -> Self {
        Self { value, expires_at: Instant::now() + Duration::from_secs(SECRET_CACHE_TTL_SECS), access_count: 0 }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    fn is_in_grace_period(&self) -> bool {
        if !self.is_expired() {
            return false;
        }
        let grace_deadline = self.expires_at + Duration::from_secs(CACHE_GRACE_PERIOD_SECS);
        Instant::now() <= grace_deadline
    }

    fn access(&mut self) -> &SecretBytes {
        self.access_count = self.access_count.saturating_add(1);
        &self.value
    }
}

pub struct FileSecretStore {
    file_path: PathBuf,
    passphrase: SecretString,
    kdf_params: Argon2Params,
    rotation: RotationMetadata,
    cache: Arc<tokio::sync::RwLock<HashMap<SecretName, CachedSecret>>>,
    cleanup_shutdown: watch::Sender<bool>,
    cleanup_task: tokio::task::JoinHandle<()>,
    pending_ops: tokio::sync::RwLock<HashMap<SecretName, PendingOp>>,
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
        let rotation = file.rotation_metadata();
        let kdf_params = file.kdf_params.clone();
        let mut secret_map = file.decrypt(passphrase)?;
        let mut cache = HashMap::new();
        for (name, bytes) in secret_map.secrets.drain() {
            cache.insert(name, CachedSecret::new(SecretBytes::new(bytes)));
        }

        let cache = Arc::new(tokio::sync::RwLock::new(cache));
        let (cleanup_shutdown, shutdown_rx) = watch::channel(false);
        let cleanup_task = Self::spawn_cache_cleanup(Arc::clone(&cache), shutdown_rx);

        log::info!("Loaded {} secrets from {}", cache.read().await.len(), path.display());
        Ok(Self {
            file_path: path.to_path_buf(),
            passphrase: SecretString::new(passphrase.to_string()),
            kdf_params,
            rotation,
            cache,
            cleanup_shutdown,
            cleanup_task,
            pending_ops: tokio::sync::RwLock::new(HashMap::new()),
        })
    }

    pub async fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, ThresholdError> {
        let path = path.as_ref();
        if path.exists() {
            return Err(ThresholdError::secret_store_unavailable("file", format!("Secrets file already exists: {}", path.display())));
        }
        let secret_map = SecretMap { secrets: HashMap::new() };
        let kdf_params = Argon2Params::default();
        let file = SecretFile::encrypt(&secret_map, passphrase, kdf_params.clone())?;
        let rotation = file.rotation_metadata();
        let bytes = file.to_bytes()?;
        tokio::fs::write(path, &bytes)
            .await
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to write secrets file: {}", e)))?;
        #[cfg(target_family = "unix")]
        Self::set_file_permissions(path)?;
        log::info!("Created new secrets file: {}", path.display());

        let cache = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
        let (cleanup_shutdown, shutdown_rx) = watch::channel(false);
        let cleanup_task = Self::spawn_cache_cleanup(Arc::clone(&cache), shutdown_rx);

        Ok(Self {
            file_path: path.to_path_buf(),
            passphrase: SecretString::new(passphrase.to_string()),
            kdf_params,
            rotation,
            cache,
            cleanup_shutdown,
            cleanup_task,
            pending_ops: tokio::sync::RwLock::new(HashMap::new()),
        })
    }

    pub async fn open_or_create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, ThresholdError> {
        let path = path.as_ref();
        if path.exists() {
            Self::open(path, passphrase).await
        } else {
            Self::create(path, passphrase).await
        }
    }

    pub async fn rotate_passphrase(path: impl AsRef<Path>, old_passphrase: &str, new_passphrase: &str) -> Result<u64, ThresholdError> {
        let path = path.as_ref();
        if new_passphrase.trim().is_empty() {
            return Err(ThresholdError::secret_store_unavailable("file", "new passphrase must not be empty".to_string()));
        }

        #[cfg(target_family = "unix")]
        Self::validate_file_permissions(path)?;

        let data = tokio::fs::read(path)
            .await
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to read secrets file: {}", e)))?;

        let file = SecretFile::from_bytes(&data)?;
        let secrets = file.decrypt(old_passphrase)?;

        let now = crate::foundation::now_nanos();
        let age_before_days = file.rotation_metadata().age_days(now);
        let rotated_metadata = RotationMetadata::new(file.created_at_nanos, now);

        let rotated = SecretFile::encrypt_with_metadata(&secrets, new_passphrase, file.kdf_params, rotated_metadata)?;
        let bytes = rotated.to_bytes()?;

        // Verify before replacing.
        let verify = SecretFile::from_bytes(&bytes)?;
        verify.decrypt(new_passphrase)?;

        let temp_path = path.with_extension("tmp");
        tokio::fs::write(&temp_path, &bytes)
            .await
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to write secrets file: {}", e)))?;
        #[cfg(target_family = "unix")]
        Self::set_file_permissions(&temp_path)?;
        tokio::fs::rename(&temp_path, path)
            .await
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to rename secrets file: {}", e)))?;
        #[cfg(target_family = "unix")]
        Self::set_file_permissions(path)?;

        Ok(age_before_days)
    }

    pub async fn set(&self, name: SecretName, secret: SecretBytes) -> Result<(), ThresholdError> {
        let mut cache = self.cache.write().await;
        cache.insert(name.clone(), CachedSecret::new(secret.clone()));
        self.pending_ops.write().await.insert(name, PendingOp::Set(secret));
        Ok(())
    }

    pub async fn remove(&self, name: &SecretName) -> Result<(), ThresholdError> {
        let mut cache = self.cache.write().await;
        cache.remove(name);
        self.pending_ops.write().await.insert(name.clone(), PendingOp::Remove);
        Ok(())
    }

    pub async fn save(&self) -> Result<(), ThresholdError> {
        let mut secret_map = self.load_from_file().await?;

        let pending = std::mem::take(&mut *self.pending_ops.write().await);
        for (name, op) in pending {
            match op {
                PendingOp::Set(bytes) => {
                    secret_map.secrets.insert(name, bytes.expose_secret().to_vec());
                }
                PendingOp::Remove => {
                    secret_map.secrets.remove(&name);
                }
            }
        }

        let file =
            SecretFile::encrypt_with_metadata(&secret_map, self.passphrase.expose_secret(), self.kdf_params.clone(), self.rotation)?;
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

    pub async fn cache_stats(&self) -> CacheStats {
        let cache = self.cache.read().await;

        let total_entries = cache.len();
        let expired_entries = cache.values().filter(|c| c.is_expired()).count();
        let grace_period_entries = cache.values().filter(|c| c.is_in_grace_period()).count();

        CacheStats {
            total_entries,
            expired_entries,
            grace_period_entries,
            max_entries: MAX_CACHED_SECRETS,
            ttl_seconds: SECRET_CACHE_TTL_SECS,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub async fn expire_cache_entry_for_test(&self, name: &SecretName) {
        let mut cache = self.cache.write().await;
        if let Some(entry) = cache.get_mut(name) {
            let now = Instant::now();
            entry.expires_at = now.checked_sub(Duration::from_secs(TEST_CACHE_EXPIRE_OFFSET_SECS)).unwrap_or(now);
        }
    }

    /// Force cleanup of expired entries and shutdown cleanup task (tests only).
    ///
    /// Use this before dropping FileSecretStore in tests to ensure
    /// background cleanup task is properly terminated without delays.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn force_cleanup_and_shutdown(&self) {
        // Run cleanup immediately
        Self::cleanup_expired_entries(&self.cache).await;

        // Signal shutdown
        let _ = self.cleanup_shutdown.send(true);

        // Give task time to see signal and terminate
        tokio::time::sleep(Duration::from_millis(TEST_CLEANUP_SHUTDOWN_WAIT_MS)).await;
    }

    fn spawn_cache_cleanup(
        cache: Arc<tokio::sync::RwLock<HashMap<SecretName, CachedSecret>>>,
        mut shutdown: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CACHE_CLEANUP_INTERVAL_SECS));
            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_ok() && *shutdown.borrow() {
                            log::debug!("secret cache cleanup task shutting down");
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        Self::cleanup_expired_entries(&cache).await;
                    }
                }
            }
        })
    }

    async fn cleanup_expired_entries(cache: &Arc<tokio::sync::RwLock<HashMap<SecretName, CachedSecret>>>) {
        let mut cache_write = cache.write().await;

        let before_count = cache_write.len();
        cache_write.retain(|_name, cached| !cached.is_expired() || cached.is_in_grace_period());
        let after_count = cache_write.len();

        let removed = before_count.saturating_sub(after_count);
        if removed > 0 {
            log::debug!("cache cleanup: removed {} expired secret(s)", removed);
        }

        if cache_write.len() > MAX_CACHED_SECRETS {
            Self::evict_lru_entries(&mut cache_write);
        }
    }

    fn evict_lru_entries(cache: &mut HashMap<SecretName, CachedSecret>) {
        let target_count = MAX_CACHED_SECRETS.saturating_mul(CACHE_KEEP_NUM).saturating_div(CACHE_KEEP_DEN);
        let excess = cache.len().saturating_sub(target_count);
        if excess == 0 {
            return;
        }

        let mut entries = cache.iter().map(|(name, cached)| (name.clone(), cached.access_count)).collect::<Vec<_>>();
        entries.sort_by_key(|(_, count)| *count);

        for (name, _) in entries.into_iter().take(excess) {
            cache.remove(&name);
        }

        log::warn!("cache over limit: evicted {} least-recently-used secret(s)", excess);
    }

    async fn load_from_file(&self) -> Result<SecretMap, ThresholdError> {
        let data = tokio::fs::read(&self.file_path)
            .await
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to read secrets file: {}", e)))?;
        let file = SecretFile::from_bytes(&data)?;
        file.decrypt(self.passphrase.expose_secret())
    }

    async fn reload_single_secret(&self, name: &SecretName) -> Result<SecretBytes, ThresholdError> {
        Self::reload_single_secret_from_disk(self.file_path.clone(), self.passphrase.clone(), Arc::clone(&self.cache), name.clone())
            .await
    }

    async fn reload_single_secret_from_disk(
        file_path: PathBuf,
        passphrase: SecretString,
        cache: Arc<tokio::sync::RwLock<HashMap<SecretName, CachedSecret>>>,
        name: SecretName,
    ) -> Result<SecretBytes, ThresholdError> {
        let data = tokio::fs::read(&file_path)
            .await
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to read secrets file: {}", e)))?;
        let file = SecretFile::from_bytes(&data)?;
        let secret_map = file.decrypt(passphrase.expose_secret())?;
        let bytes = secret_map.secrets.get(&name).cloned().ok_or_else(|| ThresholdError::secret_not_found(name.as_str(), "file"))?;

        let secret_bytes = SecretBytes::new(bytes);
        let mut cache_write = cache.write().await;
        cache_write.insert(name.clone(), CachedSecret::new(secret_bytes.clone()));
        log::debug!("secret reloaded from file secret_name={}", name.as_str());
        Ok(secret_bytes)
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
            {
                let mut cache = self.cache.write().await;
                if let Some(cached) = cache.get_mut(name) {
                    if !cached.is_expired() {
                        return Ok(cached.access().clone());
                    }
                    if cached.is_in_grace_period() {
                        let value = cached.access().clone();
                        let file_path = self.file_path.clone();
                        let passphrase = self.passphrase.clone();
                        let cache = Arc::clone(&self.cache);
                        let name = name.clone();
                        tokio::spawn(async move {
                            if let Err(err) = Self::reload_single_secret_from_disk(file_path, passphrase, cache, name.clone()).await {
                                log::warn!("failed to reload secret secret_name={} error={}", name.as_str(), err);
                            }
                        });
                        return Ok(value);
                    }
                }
            }

            self.reload_single_secret(name).await
        })
    }

    fn list_secrets<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Vec<SecretName>, ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            let mut names = self.cache.read().await.keys().cloned().collect::<Vec<_>>();
            match self.load_from_file().await {
                Ok(map) => {
                    for name in map.secrets.keys() {
                        if !names.contains(name) {
                            names.push(name.clone());
                        }
                    }
                }
                Err(err) => {
                    log::warn!("failed to list secrets from file path={} error={}", self.file_path.display(), err);
                }
            }
            Ok(names)
        })
    }
}

impl Drop for FileSecretStore {
    fn drop(&mut self) {
        // Signal shutdown to cleanup task
        if self.cleanup_shutdown.send(true).is_err() {
            log::debug!("secret cache cleanup already stopped");
        }

        // Abort the cleanup task
        self.cleanup_task.abort();

        // In tests, wait briefly to ensure task has time to cancel
        // This prevents background tasks from hanging test suite
        #[cfg(test)]
        {
            std::thread::sleep(std::time::Duration::from_millis(DROP_CLEANUP_WAIT_MS));
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub expired_entries: usize,
    pub grace_period_entries: usize,
    pub max_entries: usize,
    pub ttl_seconds: u64,
}

#[derive(Clone)]
enum PendingOp {
    Set(SecretBytes),
    Remove,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::keys::types::SecretName;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let temp_dir = TempDir::new().expect("test setup: temp dir");
        let secrets_path = temp_dir.path().join("secrets.bin");

        let store = FileSecretStore::create(&secrets_path, "test-passphrase").await.expect("create");

        let name = SecretName::new("test.secret");
        let value = SecretBytes::from_slice(b"test_value");
        store.set(name.clone(), value.clone()).await.expect("set");
        store.save().await.expect("save");

        let retrieved = store.get(&name).await.expect("get");
        assert_eq!(retrieved.expose_secret(), value.expose_secret());

        {
            let mut cache = store.cache.write().await;
            let cached = cache.get_mut(&name).expect("cached entry exists");
            cached.expires_at = Instant::now() - Duration::from_secs(TEST_CACHE_EXPIRE_OFFSET_SECS);
        }

        let retrieved_after_expiry = store.get(&name).await.expect("get after expiry");
        assert_eq!(retrieved_after_expiry.expose_secret(), value.expose_secret());

        // Cleanup before drop to prevent background task delays
        store.force_cleanup_and_shutdown().await;
    }

    #[tokio::test]
    async fn test_cache_cleanup_removes_expired() {
        let temp_dir = TempDir::new().expect("test setup: temp dir");
        let secrets_path = temp_dir.path().join("secrets.bin");
        let store = FileSecretStore::create(&secrets_path, "test-passphrase").await.expect("create");

        for idx in 0..TEST_SECRET_COUNT {
            let name = SecretName::new(format!("test.secret_{idx}"));
            let value = SecretBytes::new(format!("value_{idx}").into_bytes());
            store.set(name, value).await.expect("set");
        }

        let stats = store.cache_stats().await;
        assert_eq!(stats.total_entries, TEST_SECRET_COUNT);

        {
            let mut cache = store.cache.write().await;
            for cached in cache.values_mut() {
                cached.expires_at =
                    Instant::now() - Duration::from_secs(CACHE_GRACE_PERIOD_SECS.saturating_add(TEST_CACHE_EXPIRE_OFFSET_SECS));
            }
        }

        FileSecretStore::cleanup_expired_entries(&store.cache).await;

        let stats_after = store.cache_stats().await;
        assert_eq!(stats_after.total_entries, 0);

        // Cleanup before drop to prevent background task delays
        store.force_cleanup_and_shutdown().await;
    }

    #[tokio::test]
    async fn test_cache_lru_eviction() {
        let temp_dir = TempDir::new().expect("test setup: temp dir");
        let secrets_path = temp_dir.path().join("secrets.bin");
        let store = FileSecretStore::create(&secrets_path, "test-passphrase").await.expect("create");

        let overfill_count = MAX_CACHED_SECRETS.saturating_add(TEST_OVERFILL_SECRET_COUNT);
        for idx in 0..overfill_count {
            let name = SecretName::new(format!("test.secret_{idx}"));
            let value = SecretBytes::new(format!("value_{idx}").into_bytes());
            store.set(name, value).await.expect("set");
        }

        FileSecretStore::cleanup_expired_entries(&store.cache).await;

        let stats = store.cache_stats().await;
        assert!(stats.total_entries <= MAX_CACHED_SECRETS);

        // Cleanup before drop to prevent background task delays
        store.force_cleanup_and_shutdown().await;
    }
}
