use std::{thread, time};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hashicorp_vault::client as vault;
use hashicorp_vault::client::{SecretsEngine, TokenData, VaultDuration};
use hashicorp_vault::client::error::Result as VaultResult;
use log::{info, warn};

use crate::config::{EngineVersion, VaultAuthMethod, VaultHost};

pub type VaultClient = hashicorp_vault::client::VaultClient<TokenData>;

pub fn vault_client(host: &VaultHost, version: &EngineVersion,namespace: Option<String>) -> VaultResult<vault::VaultClient<TokenData>> {
    let mut result = match host.auth.as_ref().unwrap() {
        VaultAuthMethod::TokenAuth { token } => {
            VaultClient::new(&host.url, token,namespace)
        },
        VaultAuthMethod::AppRoleAuth { role_id, secret_id} => {
            let client = vault::VaultClient::new_app_role(
                &host.url, role_id, Some(secret_id),namespace.clone())?;
            VaultClient::new(&host.url, client.token,namespace)
        }
    };

    if let Ok(client) = &mut result {
        client.secrets_engine(
            match version {
                EngineVersion::V1 => SecretsEngine::KVV1,
                EngineVersion::V2 => SecretsEngine::KVV2,
            }
        );
    }

    result
}

// Worker to renew a Vault token lease, or to request a new token (for Vault AppRole auth method)
pub fn token_worker(host: &VaultHost, version: &EngineVersion, client: Arc<Mutex<VaultClient>>,namespace: Option<String>) {
    let mut token_age = time::Instant::now();
    loop {
        let info = {
            let client = client.lock().unwrap();
            TokenInfo::from_client(&client)
        };
        info!("Token: {:?}", &info);

        // Override token TTL and max TTL with optional values from config
        let mut plan = info.clone();
        if let Some(token_ttl) = &host.token_ttl {
            match &info.ttl {
                Some(ttl) => {
                    if *token_ttl > 0 && *token_ttl < ttl.as_secs() {
                        plan.ttl = Some(Duration::from_secs(*token_ttl));
                    }
                },
                None => {
                    plan.ttl = Some(Duration::from_secs(*token_ttl))
                }
            }
        }
        if let Some(token_max_ttl) = &host.token_max_ttl {
            match &info.max_ttl {
                Some(max_ttl) => {
                    if *token_max_ttl > 0 && *token_max_ttl < max_ttl.as_secs() {
                        plan.max_ttl = Some(Duration::from_secs(*token_max_ttl));
                    }
                },
                None => {
                    plan.max_ttl = Some(Duration::from_secs(*token_max_ttl))
                }
            }
        }
        info!("Plan: {:?}", &plan);

        if !plan.renewable {
            return;
        } else {
            if let Some(VaultAuthMethod::AppRoleAuth { role_id: _, secret_id: _ }) = &host.auth {
                if plan.max_ttl.is_none() {
                    warn!("Auth method is AppRole, but max_ttl is not set, using 32 days instead");
                    plan.max_ttl = Some(time::Duration::from_secs(32 * 24 * 60 * 60));
                }
            }
            if let Some(VaultAuthMethod::TokenAuth { token: _ }) = &host.auth {
                if plan.max_ttl.is_some() {
                    info!("Auth method is Token, but max_ttl is set, ignoring");
                    plan.max_ttl = None;
                }
            }
        }

        let duration = {
            if plan.ttl.is_none() {
                plan.max_ttl.unwrap()
            } else if plan.max_ttl.is_none() {
                plan.ttl.unwrap()
            } else {
                plan.ttl.unwrap().min(plan.max_ttl.unwrap())
            }
        };
        let duration = time::Duration::from_secs(duration.as_secs() / 2);

        thread::sleep(duration);

        if let Some(max_ttl) = plan.max_ttl {
            let age = token_age.elapsed().as_secs();
            let max_ttl = max_ttl.as_secs();
            if age > max_ttl / 2 {
                if let Some(VaultAuthMethod::AppRoleAuth { role_id: _, secret_id: _ }) = &host.auth {
                    info!("Requesting a new token");
                    match vault_client(&host, &version, namespace.clone()) {
                        Ok(new_client) => {
                            let mut client = client.lock().unwrap();
                            client.token = new_client.token;
                            client.data = new_client.data;
                            token_age = time::Instant::now();
                            continue;
                        },
                        Err(error) => {
                            warn!("Failed to request a new token: {}", error);
                        }
                    }
                }
            }
        }

        if let Some(_) = plan.ttl {
            info!("Renewing token");
            let result = {
                let mut client = client.lock().unwrap();
                client.renew()
            };
            if let Err(error) = result {
                warn!("Failed to renew token: {}", error);
            }
        }
    }
}

#[derive(Debug, Clone)]
struct TokenInfo {
    renewable: bool,
    ttl: Option<Duration>,
    max_ttl: Option<Duration>,
}

impl TokenInfo {
    fn new() -> TokenInfo {
        // Defaults are for the root token, which is not renewable and has no TTL and max TTL
        TokenInfo {
            renewable: false,
            ttl: None,
            max_ttl: None,
        }
    }

    fn from_client(client: &VaultClient) -> TokenInfo {
        let mut info = Self::new();
        if let Some(data) = &client.data {
            if let Some(data) = &data.data {
                let zero_duration = VaultDuration::seconds(0);
                info.renewable = data.renewable.unwrap_or(false);
                let ttl_duration= &data.ttl;
                if ttl_duration.0.as_secs() > 0 {
                    info.ttl = Some(ttl_duration.0);
                }

                let max_ttl_duration = data.explicit_max_ttl.as_ref().unwrap_or(&zero_duration);
                if max_ttl_duration.0.as_secs() > 0 {
                    info.max_ttl = Some(max_ttl_duration.0);
                }
            }
        }
        info
    }
}
