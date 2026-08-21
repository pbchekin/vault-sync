use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::time;

use hashicorp_vault::client::error::Error as VaultError;
use log::{info, warn};
use serde_json::Value;

use crate::config::{get_backends, VaultSyncConfig};
use crate::sync::{full_sync, normalize_prefix, SecretOp};
use crate::vault::VaultClient;

// Secrets of a single backend, keyed by the secret path relative to the prefix.
type Backend = BTreeMap<String, Value>;

// Content of an export file: secrets of every backend, keyed by the backend name.
// Ordered maps keep the file stable between exports, so it can be diffed.
pub type Secrets = BTreeMap<String, Backend>;

// Exports the secrets from the source Vault to a file.
// The secret paths are stored relative to `src.prefix`.
pub fn export(
    config: &VaultSyncConfig,
    client: Arc<Mutex<VaultClient>>,
    file_name: &str,
) -> Result<(), Box<dyn Error>> {
    let prefix = normalize_prefix(&config.src.prefix);
    let backends = get_backends(&config.src.backend);
    let now = time::Instant::now();

    // full_sync() walks the source Vault and reports every secret it finds. It is a blocking call
    // and the channel is unbounded, so all the secrets are collected before the loop below starts.
    let (tx, rx): (mpsc::Sender<SecretOp>, mpsc::Receiver<SecretOp>) = mpsc::channel();
    full_sync(&config.src.prefix, &backends, client.clone(), tx.clone());
    drop(tx);

    let mut secrets: Secrets = Secrets::new();
    let mut failed = 0;
    for op in rx {
        let path = match op {
            SecretOp::Create(path) | SecretOp::Update(path) => path,
            _ => continue,
        };
        let secret: Result<Value, _> = {
            let mut client = client.lock().unwrap();
            client.secret_backend(&path.mount);
            client.get_custom_secret(&path.path)
        };
        match secret {
            Ok(secret) => {
                let name = path.path.strip_prefix(&prefix).unwrap_or(&path.path);
                secrets.entry(path.mount).or_insert_with(Backend::new).insert(name.to_string(), secret);
            },
            Err(error) => {
                // A secret can be listed, but not readable, for example when all the versions of
                // a KV v2 secret are deleted. There is nothing to export in this case.
                if is_not_found(&error) {
                    info!("Skipping deleted secret {}", &path.path);
                } else {
                    warn!("Failed to get secret {}: {}", &path.path, error);
                    failed += 1;
                }
            }
        }
    }

    let total: usize = secrets.values().map(|backend| backend.len()).sum();
    write_file(file_name, &secrets)?;
    info!("Exported {} secrets to {} in {}ms", total, file_name, now.elapsed().as_millis());

    if failed > 0 {
        return Err(format!("Failed to export {} secrets, {} is incomplete", failed, file_name).into());
    }
    Ok(())
}

// Imports the secrets from a file to the destination Vault.
// The secret paths from the file are relative, so `dst.prefix` is prepended to them.
pub fn import(
    config: &VaultSyncConfig,
    client: Arc<Mutex<VaultClient>>,
    file_name: &str,
    dry_run: bool,
) -> Result<(), Box<dyn Error>> {
    let prefix = normalize_prefix(&config.dst.prefix);
    let src_mounts = get_backends(&config.src.backend);
    let dst_mounts = get_backends(&config.dst.backend);
    let mount_map: HashMap<&str, &str> = src_mounts.iter().map(|s| s.as_str())
        .zip(dst_mounts.iter().map(|s| s.as_str()))
        .collect();
    let now = time::Instant::now();

    let secrets = read_file(file_name)?;
    let mut updated = 0;
    let mut failed = 0;
    for (mount, backend) in &secrets {
        // The file stores the source backend names, map them to the destination ones.
        let dst_mount = match mount_map.get(mount.as_str()) {
            Some(dst_mount) => *dst_mount,
            None => {
                warn!("Backend {} of {} is not a source backend, skipping", mount, file_name);
                failed += backend.len();
                continue;
            }
        };
        for (name, secret) in backend {
            let path = format!("{}{}", &prefix, name);
            // Do not create a new version of a secret that is already up to date.
            let dst_secret: Result<Value, _> = {
                let mut client = client.lock().unwrap();
                client.secret_backend(dst_mount);
                client.get_custom_secret(&path)
            };
            if let Ok(dst_secret) = dst_secret {
                if &dst_secret == secret {
                    continue;
                }
            }
            info!("Creating/updating secret {}", &path);
            if dry_run {
                continue;
            }
            let result = {
                let mut client = client.lock().unwrap();
                client.secret_backend(dst_mount);
                client.set_custom_secret(&path, secret)
            };
            match result {
                Ok(_) => {
                    updated += 1;
                },
                Err(error) => {
                    warn!("Failed to set secret {}: {}", &path, error);
                    failed += 1;
                }
            }
        }
    }

    info!(
        "Imported {} secrets from {} in {}ms, secrets created/updated: {}",
        secrets.values().map(|backend| backend.len()).sum::<usize>(),
        file_name,
        now.elapsed().as_millis(),
        updated,
    );

    if failed > 0 {
        return Err(format!("Failed to import {} secrets from {}", failed, file_name).into());
    }
    Ok(())
}

fn is_not_found(error: &VaultError) -> bool {
    match error {
        VaultError::VaultResponse(_, response) => response.status().as_u16() == 404,
        _ => false,
    }
}

fn read_file(file_name: &str) -> Result<Secrets, Box<dyn Error>> {
    let file = File::open(file_name)?;
    let secrets = serde_json::from_reader(BufReader::new(file))?;
    Ok(secrets)
}

// Writes the secrets to a file readable by the current user only, since the secrets are
// not encrypted.
fn write_file(file_name: &str, secrets: &Secrets) -> Result<(), Box<dyn Error>> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = BufWriter::new(options.open(file_name)?);
    serde_json::to_writer_pretty(&mut file, secrets)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}
