use std::{thread, time};
use std::error::Error;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;

use clap::{crate_authors, crate_version, Arg, App};
use log::{error, info};
use simplelog::*;

use config::{VaultHost, VaultSyncConfig};
use vault::VaultClient;

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

    let log_sync = if let Some(bind) = &config.bind {
        Some(log_sync_worker(bind, &config.src.prefix, tx.clone())?)
    } else {
        None
    };

    info!("Connecting to {}", &config.src.host.url);
    let mut src_client = vault_client(&config.src.host)?;
    src_client.secret_backend(&config.src.backend);
    info!("Audit device vault-sync exists: {}", sync::audit_device_exists(&config.id, &src_client));
    let shared_src_client = Arc::new(Mutex::new(src_client));
    let src_token = token_worker(&config.src.host, shared_src_client.clone());

    info!("Connecting to {}", &config.dst.host.url);
    let mut dst_client = vault_client(&config.dst.host)?;
    dst_client.secret_backend(&config.dst.backend);
    let shared_dst_client = Arc::new(Mutex::new(dst_client));
    let dst_token = token_worker(&config.dst.host, shared_dst_client.clone());

    let sync = sync_worker(
        rx,
        &config.src.prefix,
        &config.dst.prefix,
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
        sync::full_sync(&config.src.prefix, shared_src_client.clone(), tx.clone());
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

fn vault_client(host: &VaultHost) -> Result<VaultClient, Box<dyn Error>> {
    match vault::vault_client(host) {
        Ok(client) => {
            Ok(client)
        },
        Err(error) => {
            error!("Failed to connect to {}: {}", &host.url, error);
            Err(error.into())
        }
    }
}

fn token_worker(host: &VaultHost, client: Arc<Mutex<VaultClient>>) -> thread::JoinHandle<()> {
    let host = host.clone();
    thread::spawn(move || {
        vault::token_worker(&host, client);
    })
}

fn sync_worker(
    rx: mpsc::Receiver<sync::SecretOp>,
    src_prefix: &str,
    dst_prefix: &str,
    src_client: Arc<Mutex<VaultClient>>,
    dst_client: Arc<Mutex<VaultClient>>,
    dry_run: bool,
    run_once: bool,
) -> thread::JoinHandle<()> {
    info!("Dry run: {}", dry_run);
    let src_prefix = src_prefix.to_string();
    let dst_prefix = dst_prefix.to_string();
    thread::spawn(move || {
        sync::sync_worker(rx, &src_prefix, &dst_prefix, src_client, dst_client, dry_run, run_once);
    })
}

fn log_sync_worker(addr: &str, prefix: &str, tx: mpsc::Sender<sync::SecretOp>) -> Result<thread::JoinHandle<()>, std::io::Error> {
    let prefix = prefix.to_string();
    info!("Listening on {}", addr);
    let listener = TcpListener::bind(addr)?;
    let handle = thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let tx = tx.clone();
                let prefix = prefix.clone();
                thread::spawn(move || {
                    sync::log_sync(&prefix, stream, tx);
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
    let interval = time::Duration::from_secs(config.full_sync_interval);
    let prefix = config.src.prefix.clone();
    thread::spawn(move || {
        sync::full_sync_worker(&prefix, interval, client, tx);
    })
}
