use std::env;
use std::error::Error;
use std::fmt;
use std::fmt::Formatter;
use std::fs::File;

use serde::{Deserialize, Serialize, Serializer};
use serde_repr::*;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum VaultAuthMethod {
    TokenAuth {
        #[serde(serialize_with = "sanitize")]
        token: String,
    },
    AppRoleAuth {
        #[serde(serialize_with = "sanitize")]
        role_id: String,
        #[serde(serialize_with = "sanitize")]
        secret_id: String,
    }
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Clone, Debug)]
#[repr(u8)]
pub enum EngineVersion {
    V1 = 1,
    V2 = 2,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultHost {
    pub url: String,
    #[serde(flatten)]
    pub auth: Option<VaultAuthMethod>,
    pub token_ttl: Option<u64>,
    pub token_max_ttl: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VaultSource {
    #[serde(flatten)]
    pub host: VaultHost,
    #[serde(default)]
    pub prefix: String,
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default)]
    pub version: EngineVersion,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VaultDestination {
    #[serde(flatten)]
    pub host: VaultHost,
    #[serde(default)]
    pub prefix: String,
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default)]
    pub version: EngineVersion,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VaultSyncConfig {
    pub id: String,
    pub full_sync_interval: u64,
    pub bind: Option<String>,
    pub src: VaultSource,
    pub dst: VaultDestination,
}

#[derive(Debug, Clone)]
pub enum ConfigError {
    AuthRequired,
}

impl Default for EngineVersion {
    fn default() -> Self {
        EngineVersion::V2
    }
}

impl VaultSyncConfig {
    pub fn from_file(file_name: &str) -> Result<VaultSyncConfig, Box<dyn Error>> {
        let file = File::open(file_name)?;
        let mut config: VaultSyncConfig = serde_yaml::from_reader(file)?;
        config.auth_from_env()?;
        Ok(config)
    }

    fn auth_from_env(&mut self) -> Result<(), Box<dyn Error>>{
        if self.src.host.auth.is_none() {
            self.src.host.auth = Some(VaultAuthMethod::from_env("VAULT_SYNC_SRC")?);
        }
        if self.dst.host.auth.is_none() {
            self.dst.host.auth = Some(VaultAuthMethod::from_env("VAULT_SYNC_DST")?);
        }
        Ok(())
    }
}

impl VaultAuthMethod {
    fn from_env(prefix: &str) -> Result<VaultAuthMethod, Box<dyn Error>> {
        let token = env::var(format!("{}_TOKEN", prefix));
        let role_id = env::var(format!("{}_ROLE_ID", prefix));
        let secret_id = env::var(format!("{}_SECRET_ID", prefix));
        if let Ok(token) = token {
            return Ok(VaultAuthMethod::TokenAuth { token })
        }
        if let (Ok(role_id), Ok(secret_id)) = (role_id, secret_id) {
            return Ok(VaultAuthMethod::AppRoleAuth { role_id, secret_id })
        }
        Err(ConfigError::AuthRequired.into())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            ConfigError::AuthRequired =>
                write!(f, "Vault token or both app role id and secret id are required"),
        }
    }
}

impl Error for ConfigError {
}

fn sanitize<S>(_: &str, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    s.serialize_str("***")
}

fn default_backend() -> String {
    "secret".to_string()
}

#[cfg(test)]
mod tests {
    use crate::config::{EngineVersion, VaultSyncConfig};

    #[test]
    fn test_load() {
        let yaml = r#"
            id: vault-sync-id
            full_sync_interval: 60
            bind: 0.0.0.0:8202
            src:
              url: http://127.0.0.1:8200/
              prefix: src
            dst:
              url: http://127.0.0.1:8200/
              prefix: dst
              backend: custom
              version: 1
        "#;
        let config: VaultSyncConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.id, "vault-sync-id");
        assert_eq!(config.bind, Some("0.0.0.0:8202".to_string()));
        assert_eq!(config.src.backend, "secret");
        assert_eq!(config.dst.backend, "custom");
        assert_eq!(config.src.version, EngineVersion::V2);
        assert_eq!(config.dst.version, EngineVersion::V1);
    }
}