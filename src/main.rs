mod client;
mod db;
mod tui;

use client::handlers::handle_client;
use db::users::create_db_pool;
use log::{error, info, Level, Log, Metadata, Record};
use serde::Deserialize;
use std::thread;
use std::{process::exit, sync::mpsc};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tui::{run_app, LogEntry};

#[derive(Deserialize, Debug)]
struct Config {
    address: String,
    port: String,
}

struct CustomLogger {
    tx: mpsc::Sender<LogEntry>,
}

impl Log for CustomLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let now = chrono::Local::now();
            let log_entry = LogEntry {
                timestamp: now.format("%H:%M:%S").to_string(),
                level: record.level().to_string(),
                message: record.args().to_string(),
            };

            let _ = self.tx.send(log_entry);
        }
    }

    fn flush(&self) {}
}

#[tokio::main]
async fn main() {
    create_db_pool().await.unwrap();

    // Create a channel for logging
    let (tx, rx) = mpsc::channel();

    // Create and set the custom logger
    let logger = Box::new(CustomLogger { tx });
    log::set_boxed_logger(logger).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    // Start the TUI in a separate thread
    let _tui_handle = thread::spawn(move || {
        if let Err(e) = run_app(rx) {
            eprintln!("Error running TUI: {:?}", e);
        }

        // Exit the process when the TUI closes
        exit(0);
    });

    // Load the configuration from config file
    let config = match std::fs::read_to_string("config.toml") {
        Ok(config) => match toml::from_str::<Config>(&config) {
            Ok(config) => config,
            Err(e) => {
                error!("Failed to parse config file: {:?}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            error!("Failed to read config file: {:?}", e);
            std::process::exit(1);
        }
    };

    info!("Configuration loaded: {:?}", config);

    // Bind a TCP listener to accept incoming connections
    let listener = TcpListener::bind(config.address + ":" + config.port.as_str())
        .await
        .unwrap();
    info!("Server running on port {}", config.port);

    // Create a broadcast channel for sharing messages
    let (tx, _) = broadcast::channel(100);
    loop {
        // Accept a new client
        let (socket, addr) = listener.accept().await.unwrap();
        info!("Client connected: {}", addr);

        let tx = tx.clone();
        let rx = tx.subscribe();

        // Handle the client in a new task
        tokio::spawn(async move {
            if let Err(e) = handle_client(socket, tx, rx).await {
                error!("Error handling client: {}", e);
            }
        });
    }
}
