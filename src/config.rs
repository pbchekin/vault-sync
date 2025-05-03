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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Backend {
    #[serde(rename = "backend")]
    Backend(String),
    #[serde(rename = "backends")]
    Backends(Vec<String>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultSource {
    #[serde(flatten)]
    pub host: VaultHost,
    #[serde(default)]
    pub prefix: String,
    #[serde(flatten)]
    pub backend: Option<Backend>,
    #[serde(default)]
    pub version: EngineVersion,
    pub namespace: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultDestination {
    #[serde(flatten)]
    pub host: VaultHost,
    #[serde(default)]
    pub prefix: String,
    #[serde(flatten)]
    pub backend: Option<Backend>,
    #[serde(default)]
    pub version: EngineVersion,
    pub namespace: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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
    OneToManyNotSupported,
    ManyToOneNotSupported,
    DifferentNumberOfBackends,
}

// Returns backend or backends as a vector.
pub fn get_backends(backend: &Option<Backend>) -> Vec<String> {
    match backend {
        Some(Backend::Backend(backend)) => vec![backend.into()],
        Some(Backend::Backends(backends)) => backends.clone(),
        _ => panic!("Not implemented"),
    }
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
        config.defaults()?;
        config.validate()?;
        Ok(config)
    }

    fn auth_from_env(&mut self) -> Result<(), Box<dyn Error>> {
        if self.src.host.auth.is_none() {
            self.src.host.auth = Some(VaultAuthMethod::from_env("VAULT_SYNC_SRC")?);
        }
        if self.dst.host.auth.is_none() {
            self.dst.host.auth = Some(VaultAuthMethod::from_env("VAULT_SYNC_DST")?);
        }
        Ok(())
    }

    fn defaults(&mut self) -> Result<(), Box<dyn Error>> {
        if self.src.backend.is_none() {
            self.src.backend = Some(Backend::Backend("secret".into()));
        }
        if self.dst.backend.is_none() {
            self.dst.backend = self.src.backend.clone();
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), Box<dyn Error>> {
        let src_backend = self.src.backend.as_ref().unwrap();
        let dst_backend = self.dst.backend.as_ref().unwrap();

        match &src_backend {
            Backend::Backend(_) => match &dst_backend {
                Backend::Backends(_) => {
                    return Err(ConfigError::OneToManyNotSupported.into());
                },
                _ => {},
            },
            Backend::Backends(src_backends) => match &dst_backend {
                Backend::Backend(_) => {
                    return Err(ConfigError::ManyToOneNotSupported.into());
                },
                Backend::Backends(dst_backends) => {
                    if src_backends.len() != dst_backends.len() {
                        return Err(ConfigError::DifferentNumberOfBackends.into());
                    }
                }
            }
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
            ConfigError::OneToManyNotSupported =>
                write!(f, "Syncing one backend to many not supported"),
            ConfigError::ManyToOneNotSupported =>
                write!(f, "Syncing many backends to one not supported"),
            ConfigError::DifferentNumberOfBackends =>
                write!(f, "Different number of backends for source and destination"),
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

#[cfg(test)]
mod tests {
    use std::error::Error;
    use crate::config::{EngineVersion, VaultSyncConfig, get_backends, ConfigError};

    #[test]
    fn test_load() -> Result<(), Box<dyn Error>> {
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
              version: 1
        "#;
        let mut config: VaultSyncConfig = serde_yaml::from_str(yaml)?;
        config.defaults()?;
        assert_eq!(config.id, "vault-sync-id");
        assert_eq!(config.bind, Some("0.0.0.0:8202".to_string()));
        assert_eq!(config.src.version, EngineVersion::V2);
        assert_eq!(config.dst.version, EngineVersion::V1);
        Ok(())
    }

    fn render_yaml(
        src: Option<&str>,
        dst: Option<&str>,
        src_key: &str,
        dst_key: &str,
    ) -> String {
        format!(
            r#"
                id: vault-sync-id
                full_sync_interval: 60
                src:
                  url: http://127.0.0.1:8200/
                  {}
                dst:
                  url: http://127.0.0.1:8200/
                  {}
            "#,
            src.map_or("".to_string(), |v| format!("{}: {}", src_key, v)),
            dst.map_or("".to_string(), |v| format!("{}: {}", dst_key, v)),
        )
    }

    fn render_backend_yaml(src: Option<&str>, dst: Option<&str>) -> String {
        render_yaml(src, dst, "backend", "backend")
    }

    fn render_backends_yaml(src: Option<&str>, dst: Option<&str>) -> String {
        render_yaml(src, dst, "backends", "backends")
    }

    fn test_single_backend(
        src: Option<&str>,
        dst: Option<&str>,
        expected_src: &str,
        expected_dst: &str,
    ) -> Result<(), Box<dyn Error>> {
        let yaml = render_backend_yaml(src, dst);
        let mut config: VaultSyncConfig = serde_yaml::from_str(&yaml)?;
        config.defaults()?;
        config.validate()?;
        assert_eq!(get_backends(&config.src.backend).first().unwrap(), expected_src);
        assert_eq!(get_backends(&config.dst.backend).first().unwrap(), expected_dst);
        Ok(())
    }

    fn test_many_backends(
        src: Option<&str>,
        dst: Option<&str>,
        expected_src: &[&str],
        expected_dst: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        let yaml = render_backends_yaml(src, dst);
        let mut config: VaultSyncConfig = serde_yaml::from_str(&yaml)?;
        config.defaults()?;
        config.validate()?;
        assert_eq!(get_backends(&config.src.backend), expected_src);
        assert_eq!(get_backends(&config.dst.backend), expected_dst);
        Ok(())
    }

    #[test]
    fn test_backends() -> Result<(), Box<dyn Error>> {
        test_single_backend(None, None, "secret", "secret")?;
        test_single_backend(Some("custom"), None, "custom", "custom")?;
        test_single_backend(None, Some("custom"), "secret", "custom")?;
        test_single_backend(Some("src"), Some("dst"), "src", "dst")?;
        test_many_backends(Some("[foo, baz]"), None, &["foo", "baz"], &["foo", "baz"])?;
        test_many_backends(Some("[foo, baz]"), Some("[bar, qux]"), &["foo", "baz"], &["bar", "qux"])?;
        Ok(())
    }

    #[test]
    fn test_one_to_many_error() -> Result<(), Box<dyn Error>> {
        let yaml = render_yaml(Some(""), Some("[foo, baz]"), "backend", "backends");
        let mut config: VaultSyncConfig = serde_yaml::from_str(&yaml)?;
        config.defaults()?;
        let result = config.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ConfigError::OneToManyNotSupported.to_string());
        Ok(())
    }

    #[test]
    fn test_many_to_one_error() -> Result<(), Box<dyn Error>> {
        let yaml = render_yaml(Some("[foo, baz]"), Some("bar"), "backends", "backend");
        let mut config: VaultSyncConfig = serde_yaml::from_str(&yaml)?;
        config.defaults()?;
        let result = config.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ConfigError::ManyToOneNotSupported.to_string());
        Ok(())
    }

    #[test]
    fn test_different_numbers_of_backend() -> Result<(), Box<dyn Error>> {
        let yaml = render_yaml(Some("[foo]"), Some("[baz, bar]"), "backends", "backends");
        let mut config: VaultSyncConfig = serde_yaml::from_str(&yaml)?;
        config.defaults()?;
        let result = config.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), ConfigError::DifferentNumberOfBackends.to_string());
        Ok(())
    }
}