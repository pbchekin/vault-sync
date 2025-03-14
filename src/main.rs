use std::{thread};
use std::error::Error;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::thread::JoinHandle;

use clap::{crate_authors, crate_version, Arg, App};
use log::{error, info};
use simplelog::*;

use config::{VaultHost, VaultSyncConfig};
use vault::VaultClient;
use crate::config::{EngineVersion, get_backends};

mod audit;
mod config;
mod sync;
mod vault;

fn main() -> Result<(), Box<dyn Error>> {
    TermLogger::init(LevelFilter::Info, Config::default(), TerminalMode::Mixed, ColorChoice::Auto)?;

    let matches = App::new("vault-sync")
        .author(crate_authors!())
        .version(crate_version!())
        .arg(Arg::with_name("config")
            .long("config")
            .value_name("FILE")
            .help("Configuration file")
            .default_value("./vault-sync.yaml")
            .takes_value(true))
        .arg(Arg::with_name("dry-run")
            .long("dry-run")
            .help("Do not do any changes with the destination Vault"))
        .arg(Arg::with_name("once")
            .long("once")
            .help("Run the full sync once, then exit"))
        .get_matches();

    let config = load_config(matches.value_of("config").unwrap())?;
    let (tx, rx): (mpsc::Sender<sync::SecretOp>, mpsc::Receiver<sync::SecretOp>) = mpsc::channel();

    let log_sync = match &config.bind {
        Some(_) => Some(log_sync_worker(&config, tx.clone())?),
        None => None,
    };

    info!("Connecting to {}", &config.src.host.url);
    let src_client = vault_client(&config.src.host, &config.src.version)?;
    let shared_src_client = Arc::new(Mutex::new(src_client));
    let src_token = token_worker(&config.src.host, &config.src.version, shared_src_client.clone());

    info!("Connecting to {}", &config.dst.host.url);
    let dst_client = vault_client(&config.dst.host, &config.dst.version)?;
    let shared_dst_client = Arc::new(Mutex::new(dst_client));
    let dst_token = token_worker(&config.dst.host, &config.dst.version,shared_dst_client.clone());

    info!(
        "Audit device {} exists: {}",
        &config.id,
        sync::audit_device_exists(&config.id, shared_src_client.clone()),
    );

    let sync = sync_worker(
        rx,
        &config,
        shared_src_client.clone(),
        shared_dst_client.clone(),
        matches.is_present("dry-run"),
        matches.is_present("once"),
    );

    let mut join_handlers = vec![sync];

    if !matches.is_present("once") {
        let full_sync = full_sync_worker(&config, shared_src_client.clone(), tx.clone());
        join_handlers.push(full_sync);
        join_handlers.push(src_token);
        join_handlers.push(dst_token);
        if log_sync.is_some() {
            join_handlers.push(log_sync.unwrap());
        }
    } else {
        let backends = get_backends(&config.src.backend);
        sync::full_sync(&config.src.prefix, &backends, shared_src_client.clone(), tx.clone());
    };

    // Join all threads
    for handler in join_handlers {
        let _ = handler.join();
    }

    Ok(())
}

fn load_config(file_name: &str) -> Result<VaultSyncConfig, Box<dyn Error>> {
    match VaultSyncConfig::from_file(file_name) {
        Ok(config) => {
            info!("Configuration from {}:\n{}", file_name, serde_json::to_string_pretty(&config).unwrap());
            Ok(config)
        },
        Err(error) => {
            error!("Failed to load configuration file {}: {}", file_name, error);
            Err(error)
        }
    }
}

fn vault_client(host: &VaultHost, version: &EngineVersion) -> Result<VaultClient, Box<dyn Error>> {
    match vault::vault_client(host, version) {
        Ok(client) => {
            Ok(client)
        },
        Err(error) => {
            error!("Failed to connect to {}: {}", &host.url, error);
            Err(error.into())
        }
    }
}

fn token_worker(host: &VaultHost, version: &EngineVersion, client: Arc<Mutex<VaultClient>>) -> JoinHandle<()> {
    let host = host.clone();
    let version = version.clone();
    thread::spawn(move || {
        vault::token_worker(&host, &version, client);
    })
}

fn sync_worker(
    rx: mpsc::Receiver<sync::SecretOp>,
    config: &VaultSyncConfig,
    src_client: Arc<Mutex<VaultClient>>,
    dst_client: Arc<Mutex<VaultClient>>,
    dry_run: bool,
    run_once: bool,
) -> thread::JoinHandle<()> {
    info!("Dry run: {}", dry_run);
    let config = config.clone();
    thread::spawn(move || {
        sync::sync_worker(rx, &config, src_client, dst_client, dry_run, run_once);
    })
}

fn log_sync_worker(config: &VaultSyncConfig, tx: mpsc::Sender<sync::SecretOp>) -> Result<JoinHandle<()>, std::io::Error> {
    let addr = &config.bind.clone().unwrap();
    let config = config.clone();
    info!("Listening on {}", addr);
    let listener = TcpListener::bind(addr)?;
    let handle = thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let tx = tx.clone();
                let config = config.clone();
                thread::spawn(move || {
                    sync::log_sync(&config, stream, tx);
                });
            }
        }
    });
    Ok(handle)
}

fn full_sync_worker(
    config: &VaultSyncConfig,
    client: Arc<Mutex<VaultClient>>,
    tx: mpsc::Sender<sync::SecretOp>
) -> thread::JoinHandle<()>{
    let config = config.clone();
    thread::spawn(move || {
        sync::full_sync_worker(&config, client, tx);
    })
}
