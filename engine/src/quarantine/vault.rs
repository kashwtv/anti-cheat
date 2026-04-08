use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Metadata stored alongside each quarantined file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineMetadata {
    pub original_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub threat_name: String,
    pub quarantine_date: String,
}

/// Encrypted vault for quarantined files.
pub struct QuarantineVault {
    vault_path: PathBuf,
    cipher: Aes256Gcm,
}

impl QuarantineVault {
    /// Initialize the vault, creating the directory and loading/generating the encryption key.
    pub fn init(vault_path: impl Into<PathBuf>) -> Result<Self> {
        let vault_path = vault_path.into();
        std::fs::create_dir_all(&vault_path)
            .with_context(|| format!("failed to create vault dir: {}", vault_path.display()))?;

        let key_path = vault_path.join(".vault_key");
        let key_bytes = if key_path.exists() {
            let hex_key = std::fs::read_to_string(&key_path)
                .context("failed to read vault key")?;
            hex::decode(hex_key.trim()).context("invalid vault key")?
        } else {
            let mut key = vec![0u8; 32];
            OsRng.fill_bytes(&mut key);
            std::fs::write(&key_path, hex::encode(&key))
                .context("failed to write vault key")?;
            info!("generated new vault encryption key");
            key
        };

        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        Ok(Self { vault_path, cipher })
    }

    /// Encrypt a file and store it in the vault. Returns the quarantine ID.
    pub fn encrypt_and_store(
        &self,
        source_path: impl AsRef<Path>,
        metadata: QuarantineMetadata,
    ) -> Result<String> {
        let source = source_path.as_ref();
        let data = std::fs::read(source)
            .with_context(|| format!("failed to read: {}", source.display()))?;

        let id = uuid::Uuid::new_v4().to_string();

        // Encrypt
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = self
            .cipher
            .encrypt(nonce, data.as_ref())
            .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

        // Write encrypted data with nonce prefix
        let mut stored = nonce_bytes.to_vec();
        stored.extend_from_slice(&encrypted);
        std::fs::write(self.vault_path.join(format!("{id}.enc")), stored)?;

        // Write metadata
        let meta_json = serde_json::to_string_pretty(&metadata)?;
        std::fs::write(self.vault_path.join(format!("{id}.meta")), meta_json)?;

        debug!(id = %id, "file quarantined and encrypted");
        Ok(id)
    }

    /// Decrypt and restore a quarantined file.
    pub fn decrypt_and_restore(
        &self,
        quarantine_id: &str,
        restore_path: impl AsRef<Path>,
    ) -> Result<()> {
        let enc_path = self.vault_path.join(format!("{quarantine_id}.enc"));
        let stored = std::fs::read(&enc_path)
            .with_context(|| format!("quarantine file not found: {quarantine_id}"))?;

        if stored.len() < 12 {
            anyhow::bail!("corrupted quarantine file");
        }

        let nonce = Nonce::from_slice(&stored[..12]);
        let decrypted = self
            .cipher
            .decrypt(nonce, &stored[12..])
            .map_err(|e| anyhow::anyhow!("decryption failed: {}", e))?;

        std::fs::write(restore_path.as_ref(), decrypted)?;
        debug!(id = %quarantine_id, "file restored from quarantine");
        Ok(())
    }

    /// Delete a quarantined file from the vault.
    pub fn delete(&self, quarantine_id: &str) -> Result<()> {
        let enc = self.vault_path.join(format!("{quarantine_id}.enc"));
        let meta = self.vault_path.join(format!("{quarantine_id}.meta"));
        if enc.exists() {
            std::fs::remove_file(&enc)?;
        }
        if meta.exists() {
            std::fs::remove_file(&meta)?;
        }
        debug!(id = %quarantine_id, "quarantine file deleted");
        Ok(())
    }

    /// Get total size of vault in bytes.
    pub fn get_vault_size(&self) -> u64 {
        walkdir::WalkDir::new(&self.vault_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum()
    }

    /// Read metadata for a quarantined file.
    pub fn read_metadata(&self, quarantine_id: &str) -> Result<QuarantineMetadata> {
        let meta_path = self.vault_path.join(format!("{quarantine_id}.meta"));
        let data = std::fs::read_to_string(&meta_path)?;
        Ok(serde_json::from_str(&data)?)
    }
}

impl std::fmt::Debug for QuarantineVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuarantineVault")
            .field("vault_path", &self.vault_path)
            .finish()
    }
}
