use std::collections::HashMap;
use std::fs;
use std::path::Path;

use bcrypt::{hash, verify, DEFAULT_COST};

use crate::error::{MastError, Result};

/// In-memory store of bcrypt-hashed credentials loaded from a passwd file.
///
/// File format (one entry per line):
/// ```text
/// username:$2b$12$<bcrypt_hash>
/// # lines starting with # are comments
/// ```
pub struct PasswdStore {
    /// username → bcrypt hash
    entries: HashMap<String, String>,
}

impl PasswdStore {
    pub fn empty() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|e| MastError::Config(format!("Cannot read passwd file {:?}: {}", path, e)))?;

        let mut entries = HashMap::new();

        for (idx, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.splitn(2, ':').collect::<Vec<_>>().as_slice() {
                [username, hash] => {
                    entries.insert(username.to_string(), hash.to_string());
                }
                _ => {
                    tracing::warn!("Malformed passwd entry at line {} — skipped", idx + 1);
                }
            }
        }

        Ok(Self { entries })
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let mut lines: Vec<String> = self
            .entries
            .iter()
            .map(|(u, h)| format!("{}:{}", u, h))
            .collect();
        lines.sort();

        let content = lines.join("\n") + "\n";
        fs::write(path, content).map_err(MastError::Io)
    }

    /// Returns `true` if `username` exists and `password` matches its bcrypt hash.
    pub fn verify(&self, username: &str, password: &str) -> bool {
        match self.entries.get(username) {
            Some(stored_hash) => verify(password, stored_hash).unwrap_or(false),
            None => false,
        }
    }

    /// Add or replace a user's password. Hashes with bcrypt DEFAULT_COST.
    pub fn set_password(&mut self, username: &str, password: &str) -> Result<()> {
        let hashed = hash(password, DEFAULT_COST)?;
        self.entries.insert(username.to_string(), hashed);
        Ok(())
    }

    /// Remove a user. Returns `true` if the user existed.
    pub fn delete(&mut self, username: &str) -> bool {
        self.entries.remove(username).is_some()
    }

    /// Sorted list of all usernames.
    pub fn list(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.entries.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
