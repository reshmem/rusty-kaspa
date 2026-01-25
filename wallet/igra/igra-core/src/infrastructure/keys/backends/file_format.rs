//! Encrypted secrets file format (Argon2id + XChaCha20-Poly1305).

use crate::foundation::ThresholdError;
use crate::infrastructure::keys::types::SecretName;
use argon2::{Argon2, ParamsBuilder, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

const MAGIC: [u8; 4] = *b"ISEC";
const VERSION: u8 = 1;
const LEGACY_HEADER_LEN: usize = 4 + 1 + 12 + 32 + 24;
const ROTATION_TAG: [u8; 4] = *b"RTM1";
const HEADER_LEN: usize = LEGACY_HEADER_LEN + 4 + 8 + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationMetadata {
    pub created_at_nanos: u64,
    pub last_rotated_at_nanos: u64,
}

impl RotationMetadata {
    pub const fn new(created_at_nanos: u64, last_rotated_at_nanos: u64) -> Self {
        Self { created_at_nanos, last_rotated_at_nanos }
    }

    pub fn age_days(&self, now_nanos: u64) -> u64 {
        let age_nanos = now_nanos.saturating_sub(self.last_rotated_at_nanos);
        age_nanos / crate::foundation::NANOS_PER_DAY
    }
}

#[derive(Debug)]
pub struct SecretFile {
    pub version: u8,
    pub kdf_params: Argon2Params,
    pub salt: [u8; 32],
    pub nonce: [u8; 24],
    pub created_at_nanos: u64,
    pub last_rotated_at_nanos: u64,
    pub ciphertext_and_tag: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self { m_cost: 65536, t_cost: 3, p_cost: 4 }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SecretMap {
    pub secrets: HashMap<SecretName, Vec<u8>>,
}

impl Drop for SecretMap {
    fn drop(&mut self) {
        for value in self.secrets.values_mut() {
            value.zeroize();
        }
    }
}

impl SecretFile {
    pub fn encrypt(secrets: &SecretMap, passphrase: &str, kdf_params: Argon2Params) -> Result<Self, ThresholdError> {
        let now = crate::foundation::now_nanos();
        Self::encrypt_with_metadata(secrets, passphrase, kdf_params, RotationMetadata::new(now, now))
    }

    pub fn encrypt_with_metadata(
        secrets: &SecretMap,
        passphrase: &str,
        kdf_params: Argon2Params,
        rotation: RotationMetadata,
    ) -> Result<Self, ThresholdError> {
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 24];
        let mut rng = OsRng;
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);

        let key = Self::derive_key(passphrase, &salt, &kdf_params)?;
        let plaintext = bincode::serialize(secrets)
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to serialize secrets: {}", e)))?;

        let header_aad = Self {
            version: VERSION,
            kdf_params: kdf_params.clone(),
            salt,
            nonce,
            created_at_nanos: rotation.created_at_nanos,
            last_rotated_at_nanos: rotation.last_rotated_at_nanos,
            ciphertext_and_tag: Vec::new(),
        }
        .aad_bytes()?;

        let cipher = XChaCha20Poly1305::new(&key.into());
        let ciphertext_and_tag = cipher
            .encrypt(&nonce.into(), chacha20poly1305::aead::Payload { msg: plaintext.as_ref(), aad: header_aad.as_ref() })
            .map_err(|e| ThresholdError::SecretDecryptFailed {
                backend: "file".to_string(),
                details: format!("Encryption failed: {}", e),
                source: None,
            })?;

        Ok(Self {
            version: VERSION,
            kdf_params,
            salt,
            nonce,
            created_at_nanos: rotation.created_at_nanos,
            last_rotated_at_nanos: rotation.last_rotated_at_nanos,
            ciphertext_and_tag,
        })
    }

    pub fn decrypt(&self, passphrase: &str) -> Result<SecretMap, ThresholdError> {
        if self.version != VERSION {
            return Err(ThresholdError::secret_store_unavailable("file", format!("Unsupported file version: {}", self.version)));
        }
        let key = Self::derive_key(passphrase, &self.salt, &self.kdf_params)?;
        let header_aad = self.aad_bytes()?;
        let cipher = XChaCha20Poly1305::new(&key.into());
        let plaintext = cipher
            .decrypt(
                &self.nonce.into(),
                chacha20poly1305::aead::Payload { msg: self.ciphertext_and_tag.as_ref(), aad: header_aad.as_ref() },
            )
            .map_err(|e| ThresholdError::SecretDecryptFailed {
                backend: "file".to_string(),
                details: format!("Decryption failed (wrong passphrase?): {}", e),
                source: None,
            })?;
        let secrets: SecretMap = bincode::deserialize(&plaintext)
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to deserialize secrets: {}", e)))?;
        Ok(secrets)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
        let mut buf = self.aad_bytes()?;
        buf.extend_from_slice(&self.ciphertext_and_tag);
        Ok(buf)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ThresholdError> {
        if data.len() < LEGACY_HEADER_LEN {
            return Err(ThresholdError::secret_store_unavailable("file", "File too short to be valid secret file".to_string()));
        }
        if &data[0..4] != &MAGIC {
            return Err(ThresholdError::secret_store_unavailable("file", "Invalid magic bytes (not an Igra secret file)".to_string()));
        }
        let version = data[4];
        if version != VERSION {
            return Err(ThresholdError::secret_store_unavailable("file", format!("Unsupported file version: {}", version)));
        }
        if data.len() < HEADER_LEN || data[73..77] != ROTATION_TAG {
            return Err(ThresholdError::unsupported_secret_file_format(
                "secrets file uses an older incompatible format; regenerate secrets.bin with secrets-admin init".to_string(),
            ));
        }
        let m_cost = u32::from_le_bytes(
            data[5..9]
                .try_into()
                .map_err(|_| ThresholdError::secret_store_unavailable("file", "Invalid Argon2 m_cost bytes".to_string()))?,
        );
        let t_cost = u32::from_le_bytes(
            data[9..13]
                .try_into()
                .map_err(|_| ThresholdError::secret_store_unavailable("file", "Invalid Argon2 t_cost bytes".to_string()))?,
        );
        let p_cost = u32::from_le_bytes(
            data[13..17]
                .try_into()
                .map_err(|_| ThresholdError::secret_store_unavailable("file", "Invalid Argon2 p_cost bytes".to_string()))?,
        );
        let kdf_params = Argon2Params { m_cost, t_cost, p_cost };
        let salt: [u8; 32] =
            data[17..49].try_into().map_err(|_| ThresholdError::secret_store_unavailable("file", "Invalid salt bytes".to_string()))?;
        let nonce: [u8; 24] = data[49..73]
            .try_into()
            .map_err(|_| ThresholdError::secret_store_unavailable("file", "Invalid nonce bytes".to_string()))?;
        let created_at_nanos = u64::from_le_bytes(
            data[77..85]
                .try_into()
                .map_err(|_| ThresholdError::secret_store_unavailable("file", "Invalid created_at_nanos bytes".to_string()))?,
        );
        let last_rotated_at_nanos = u64::from_le_bytes(
            data[85..93]
                .try_into()
                .map_err(|_| ThresholdError::secret_store_unavailable("file", "Invalid last_rotated_at_nanos bytes".to_string()))?,
        );
        let ciphertext_and_tag = data[93..].to_vec();
        Ok(Self { version, kdf_params, salt, nonce, created_at_nanos, last_rotated_at_nanos, ciphertext_and_tag })
    }

    pub const fn rotation_metadata(&self) -> RotationMetadata {
        RotationMetadata::new(self.created_at_nanos, self.last_rotated_at_nanos)
    }

    fn aad_bytes(&self) -> Result<Vec<u8>, ThresholdError> {
        let mut buf = Vec::with_capacity(HEADER_LEN);
        buf.extend_from_slice(&MAGIC);
        buf.push(self.version);
        buf.extend_from_slice(&self.kdf_params.m_cost.to_le_bytes());
        buf.extend_from_slice(&self.kdf_params.t_cost.to_le_bytes());
        buf.extend_from_slice(&self.kdf_params.p_cost.to_le_bytes());
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&ROTATION_TAG);
        buf.extend_from_slice(&self.created_at_nanos.to_le_bytes());
        buf.extend_from_slice(&self.last_rotated_at_nanos.to_le_bytes());
        Ok(buf)
    }

    fn derive_key(passphrase: &str, salt: &[u8; 32], params: &Argon2Params) -> Result<[u8; 32], ThresholdError> {
        let mut key = [0u8; 32];
        let argon2_params = ParamsBuilder::new()
            .m_cost(params.m_cost)
            .t_cost(params.t_cost)
            .p_cost(params.p_cost)
            .build()
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Invalid Argon2 parameters: {}", e)))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Key derivation failed: {}", e)))?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut secrets = SecretMap { secrets: HashMap::new() };
        secrets.secrets.insert(SecretName::new("test.key1"), b"secret_value_1".to_vec());
        secrets.secrets.insert(SecretName::new("test.key2"), b"secret_value_2".to_vec());

        let passphrase = "test_passphrase_123";
        let file = SecretFile::encrypt(&secrets, passphrase, Argon2Params::default()).unwrap();
        let decrypted = file.decrypt(passphrase).unwrap();
        assert_eq!(decrypted.secrets.get(&SecretName::new("test.key1")).unwrap(), b"secret_value_1");
        assert_eq!(decrypted.secrets.get(&SecretName::new("test.key2")).unwrap(), b"secret_value_2");
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let mut secrets = SecretMap { secrets: HashMap::new() };
        secrets.secrets.insert(SecretName::new("test.key"), b"secret".to_vec());
        let file = SecretFile::encrypt(&secrets, "correct", Argon2Params::default()).unwrap();
        assert!(file.decrypt("wrong").is_err());
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut secrets = SecretMap { secrets: HashMap::new() };
        secrets.secrets.insert(SecretName::new("test.key"), b"secret".to_vec());
        let file = SecretFile::encrypt(&secrets, "pass", Argon2Params::default()).unwrap();
        let bytes = file.to_bytes().unwrap();
        let file2 = SecretFile::from_bytes(&bytes).unwrap();
        let decrypted = file2.decrypt("pass").unwrap();
        assert_eq!(decrypted.secrets.get(&SecretName::new("test.key")).unwrap(), b"secret");
    }

    #[test]
    fn test_legacy_header_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&[0u8; 12]); // Argon2 params
        bytes.extend_from_slice(&[0u8; 32]); // salt
        bytes.extend_from_slice(&[0u8; 24]); // nonce
        bytes.push(0u8); // ciphertext placeholder

        let err = SecretFile::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ThresholdError::UnsupportedSecretFileFormat { .. }));
    }
}
