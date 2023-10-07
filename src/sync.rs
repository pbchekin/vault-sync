use std::{thread, time};
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;

use hashicorp_vault::client::{EndpointResponse, HttpVerb};
use log::{debug, info, warn};
use serde_json::Value;

use crate::audit;
use crate::config::EngineVersion;
use crate::vault::VaultClient;

pub fn audit_device_exists(name: &str, client: &VaultClient) -> bool {
    let name = format!("{}/", name);
    match client.call_endpoint::<Value>(HttpVerb::GET, "sys/audit", None, None) {
        Ok(response) => {
            debug!("GET sys/audit: {:?}", response);
            if let EndpointResponse::VaultResponse(response) = response {
                if let Some(Value::Object(map)) = response.data {
                    for (key, _) in &map {
                        if key == &name {
                            return true;
                        }
                    }
                }
            }
        },
        Err(error) => {
            warn!("GET sys/audit: {}", error);
        }
    }
    false
}

pub fn full_sync_worker(
    prefix: &str,
    interval: time::Duration,
    client: Arc<Mutex<VaultClient>>,
    tx: mpsc::Sender<SecretOp>
) {
    info!("FullSync worker started");
    loop {
        full_sync(prefix, client.clone(), tx.clone());
        thread::sleep(interval);
    }
}

struct Item {
    parent: String,
    secrets: Option<Vec<String>>,
    index: usize,
}

pub fn full_sync(prefix: &str, client: Arc<Mutex<VaultClient>>, tx: mpsc::Sender<SecretOp>) {
    let prefix= normalize_prefix(prefix);
    info!("FullSync started");
    let now = time::Instant::now();
    full_sync_internal(&prefix, client, tx);
    info!("FullSync finished in {}ms", now.elapsed().as_millis());
}

fn full_sync_internal(prefix: &str, client: Arc<Mutex<VaultClient>>, tx: mpsc::Sender<SecretOp>) {
    let mut stack: Vec<Item> = Vec::new();
    let item = Item {
        parent: prefix.to_string(),
        secrets: None,
        index: 0,
    };
    stack.push(item);

    'outer: while stack.len() > 0 {
        let len = stack.len();
        let item = stack.get_mut(len - 1).unwrap();
        if item.secrets.is_none() {
            let secrets = {
                let client = client.lock().unwrap();
                client.list_secrets(&item.parent)
            };
            match secrets {
                Ok(secrets) => {
                    item.secrets = Some(secrets);
                },
                Err(error) => {
                    warn!("Failed to list secrets in {}: {}", &item.parent, error);
                }
            }
        }
        if let Some(secrets) = &item.secrets {
            while item.index < secrets.len() {
                let secret = &secrets[item.index];
                item.index += 1;
                if secret.ends_with("/") {
                    let item = Item {
                        // item.parent ends with '/'
                        parent: format!("{}{}", &item.parent, secret),
                        secrets: None,
                        index: 0,
                    };
                    stack.push(item);
                    continue 'outer;
                } else {
                    let full_name = format!("{}{}", &item.parent, &secret);
                    if let Err(error) = tx.send(SecretOp::Create(full_name)) {
                        warn!("Failed to send a secret to a sync thread: {}", error);
                    }
                }
            }
        }
        stack.pop();
    }
    let _ = tx.send(SecretOp::FullSyncFinished);
}

pub fn log_sync(prefix: &str, backend: &str, version: &EngineVersion, stream: TcpStream, tx: mpsc::Sender<SecretOp>) {
    match stream.peer_addr() {
        Ok(peer_addr) => {
            info!("New connection from {}", peer_addr);
        },
        Err(_) => {
            info!("New connection");
        }
    }
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // EOF
                break;
            },
            Ok(_) => {
                debug!("Log: '{}'", line.trim());
                let audit_log: Result<audit::AuditLog, _> = serde_json::from_str(&line);
                match audit_log {
                    Ok(audit_log) => {
                        if let Some(op) = audit_log_op(backend, prefix, version, &audit_log) {
                            if let Err(error) = tx.send(op) {
                                warn!("Failed to send a secret to a sync thread: {}", error);
                            }
                        }
                    },
                    Err(error) => {
                        warn!("Failed to deserialize: {}, response: {}", error, &line);
                    }
                }
            },
            Err(error) => {
                warn!("Error: {}", error);
                break;
            }
        }
    }
    debug!("Closed connection");
}


#[derive(Debug)]
pub enum SecretOp {
    Create(String),
    Update(String),
    Delete(String),
    FullSyncFinished,
}

struct SyncStats {
    updated: u64,
    deleted: u64,
}

impl SyncStats {
    fn new() -> SyncStats {
        SyncStats { updated: 0, deleted: 0 }
    }
    fn reset(&mut self) {
        self.updated = 0;
        self.deleted = 0;
    }
}

pub fn sync_worker(
    rx: mpsc::Receiver<SecretOp>,
    src_prefix: &str,
    dst_prefix: &str,
    src_client: Arc<Mutex<VaultClient>>,
    dst_client: Arc<Mutex<VaultClient>>,
    dry_run: bool,
    run_once: bool,
) {
    let src_prefix = normalize_prefix(src_prefix);
    let dst_prefix = normalize_prefix(dst_prefix);
    info!("Sync worker started");
    let mut stats = SyncStats::new();
    loop {
        let op = rx.recv();
        if let Ok(op) = op {
            match op {
                SecretOp::Update(src_path) | SecretOp::Create(src_path) => {
                    let dst_path = secret_src_to_dst_path(&src_prefix, &dst_prefix, &src_path);
                    let src_secret: Result<Value, _> = {
                        let client = src_client.lock().unwrap();
                        client.get_custom_secret(&src_path)
                    };
                    let dst_secret: Result<Value, _> = {
                        let client = dst_client.lock().unwrap();
                        client.get_custom_secret(&dst_path)
                    };
                    if let Err(error) = src_secret {
                        warn!("Failed to get secret {}: {}", &src_path, error);
                        continue;
                    }
                    let src_secret = src_secret.unwrap();
                    if let Ok(dst_secret) = dst_secret {
                        if dst_secret == src_secret {
                            continue;
                        }
                    }
                    info!("Creating/updating secret {}", &dst_path);
                    if !dry_run {
                        let result = {
                            let client = dst_client.lock().unwrap();
                            client.set_custom_secret(&dst_path, &src_secret)
                        };
                        if let Err(error) = result {
                            warn!("Failed to set secret {}: {}", &dst_path, error);
                        } else {
                            stats.updated += 1;
                        }
                    }
                },
                SecretOp::Delete(secret) => {
                    let secret = secret_src_to_dst_path(&src_prefix, &dst_prefix, &secret);
                    info!("Deleting secret {}", &secret);
                    if !dry_run {
                        let client = dst_client.lock().unwrap();
                        let _ = client.delete_secret(&secret);
                    } else {
                        stats.deleted += 1;
                    }
                },
                SecretOp::FullSyncFinished => {
                    info!("Secrets created/updated: {}, deleted: {}", &stats.updated, &stats.deleted);
                    stats.reset();
                    if run_once {
                        break;
                    }
                },
            }
        }
    }
}


// Convert AuditLog to SecretOp
fn audit_log_op(mount: &str, prefix: &str, version: &EngineVersion, log: &audit::AuditLog) -> Option<SecretOp> {
    if log.log_type != "response" {
        return None;
    }
    if log.request.mount_type.is_none() {
        return None;
    }
    if log.request.mount_type != Some("kv".to_string()) {
        return None;
    }

    let operation = log.request.operation.clone();
    if operation != "create" && operation != "update" && operation != "delete" {
        return None;
    }

    let path = match version {
        EngineVersion::V1 => secret_path_v1(&log.request.path),
        EngineVersion::V2 => secret_path_v2(&log.request.path),
    };
    if let Some(path) = path {
        if path.0 != mount {
            return None;
        }
        if !path.1.starts_with(prefix) {
            return None;
        }
        if operation == "create" {
            return Some(SecretOp::Create(path.1));
        } else if operation == "update" {
            return Some(SecretOp::Update(path.1));
        } else if operation == "delete" {
            return Some(SecretOp::Delete(path.1));
        }
    }
    None
}

// Convert Vault path to a secret path for KV v1
// Example: "secret/path/to/secret" -> "secret", "path/to/secret"
fn secret_path_v1(path: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = path.split("/").collect();
    if parts.len() < 2 {
        return None
    }
    Some((parts[0].to_string(), parts[1..].join("/")))
}

// Convert Vault path to a secret path for KV v2
// Example: "secret/data/path/to/secret" -> "secret", "path/to/secret"
fn secret_path_v2(path: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = path.split("/").collect();
    if parts.len() < 3 {
        return None
    }
    // `vault kv metadata delete secret/path` has `metadata` instead of `data`,
    // we do not support this yet
    if parts[1] == "data" {
        Some((parts[0].to_string(), parts[2..].join("/")))
    } else {
        None
    }
}

fn normalize_prefix(prefix: &str) -> String {
    if prefix.len() == 0 {
        return "".to_string();
    }
    if prefix.ends_with("/") {
        prefix.to_string()
    } else {
        format!("{}/", prefix)
    }
}

// Convert source secret path to destination secret path. Prefixes must be normalized!
// Example: "src/secret1" -> "dst/secret2"
fn secret_src_to_dst_path(src_prefix: &str, dst_prefix: &str, path: &str) -> String {
    let mut path = path.to_string();
    if src_prefix.len() > 0 {
        path = path.trim_start_matches(src_prefix).to_string();
    }
    format!("{}{}", dst_prefix, &path)
}

#[cfg(test)]
mod tests {
    use crate::sync::{normalize_prefix, secret_path_v1, secret_path_v2, secret_src_to_dst_path};

    #[test]
    fn test_secret_path_v1_matches() {
        let path = "secret/path/to/secret";
        let path = secret_path_v1(&path).unwrap();
        assert_eq!(path.0, "secret");
        assert_eq!(path.1, "path/to/secret");
    }

    #[test]
    fn test_custom_secret_path_v1_matches() {
        let path = "custom/path/to/secret";
        let path = secret_path_v1(&path).unwrap();
        assert_eq!(path.0, "custom");
        assert_eq!(path.1, "path/to/secret");
    }

    #[test]
    fn test_secret_path_v1_not_matches() {
        let path = "secret";
        let path = secret_path_v1(&path);
        assert_eq!(path.is_none(), true);
    }

    #[test]
    fn test_secret_path_v2_matches() {
        let path = "secret/data/path/to/secret";
        let path = secret_path_v2(&path).unwrap();
        assert_eq!(path.0, "secret");
        assert_eq!(path.1, "path/to/secret");
    }

    #[test]
    fn test_custom_secret_path_v2_matches() {
        let path = "custom/data/path/to/secret";
        let path = secret_path_v2(&path).unwrap();
        assert_eq!(path.0, "custom");
        assert_eq!(path.1, "path/to/secret");
    }

    #[test]
    fn test_secret_path_v2_not_matches() {
        let path = "secret/metadata/path/to/secret";
        let path = secret_path_v2(&path);
        assert_eq!(path.is_none(), true);
    }

    #[test]
    fn test_normalize_prefix() {
        assert_eq!(normalize_prefix(""), "");
        assert_eq!(normalize_prefix("src"), "src/");
        assert_eq!(normalize_prefix("src/"), "src/");
    }

    #[test]
    fn test_secret_src_to_dst_path() {
        assert_eq!(secret_src_to_dst_path("src/", "dst/", "src/secret"), "dst/secret");
        assert_eq!(secret_src_to_dst_path("", "dst/", "src/secret"), "dst/src/secret");
        assert_eq!(secret_src_to_dst_path("", "", "src/secret"), "src/secret");
    }

}