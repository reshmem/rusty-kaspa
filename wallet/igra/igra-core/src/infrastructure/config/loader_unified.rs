//! Unified configuration loader with clear precedence:
//! 1. Defaults
//! 2. Config file (INI/TOML)
//! 3. Persisted DB config
//! 4. Environment overrides

use super::{env, loader, persistence, AppConfig};
use crate::foundation::ThresholdError;
use std::path::{Path, PathBuf};

pub struct ConfigLoader {
    data_dir: PathBuf,
}

impl ConfigLoader {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self { data_dir: data_dir.into() }
    }

    /// Load configuration using default precedence.
    pub fn load(&self) -> Result<AppConfig, ThresholdError> {
        let mut config = self.load_defaults()?;

        if let Some(file) = env::resolve_config_path(&self.data_dir).ok() {
            if file.exists() {
                if let Ok(file_cfg) = Self::load_from_path(&file, &self.data_dir) {
                    config.merge_from(&file_cfg);
                }
            }
        }

        if let Some(db_cfg) = persistence::load_config_from_db(&self.data_dir)? {
            config.merge_from(&db_cfg);
        }

        env::apply_env_overrides(&mut config)?;
        if let Err(errors) = config.validate() {
            return Err(ThresholdError::ConfigError(format!("config validation failed: {:?}", errors)));
        }
        persistence::store_config_in_db(&self.data_dir, &config)?;
        Ok(config)
    }

    /// Load configuration from an explicit path (INI/TOML), apply env overrides and validate.
    pub fn load_from_file(&self, path: &Path) -> Result<AppConfig, ThresholdError> {
        let mut config = Self::load_from_path(path, &self.data_dir)?;
        env::apply_env_overrides(&mut config)?;
        if let Err(errors) = config.validate() {
            return Err(ThresholdError::ConfigError(format!("config validation failed: {:?}", errors)));
        }
        Ok(config)
    }

    /// Load configuration from a specific INI profile, apply env overrides and validate.
    pub fn load_from_profile(&self, path: &Path, profile: &str) -> Result<AppConfig, ThresholdError> {
        let mut config = loader::load_from_ini_profile(path, &self.data_dir, profile)?;
        env::apply_env_overrides(&mut config)?;
        if let Err(errors) = config.validate() {
            return Err(ThresholdError::ConfigError(format!("config validation failed: {:?}", errors)));
        }
        Ok(config)
    }

    fn load_defaults(&self) -> Result<AppConfig, ThresholdError> {
        loader::load_default(&self.data_dir)
    }

    fn load_from_path(path: &Path, data_dir: &Path) -> Result<AppConfig, ThresholdError> {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("toml") => loader::load_from_toml(path, data_dir),
            _ => loader::load_from_ini(path, data_dir),
        }
    }
}
