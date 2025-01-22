mod client;
use client::handlers::handle_client;

use colog;
use log::{error, info};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

#[derive(Deserialize, Debug)]
struct Config {
    address: String,
    port: String,
}

#[tokio::main]
async fn main() {
    // Initialize the logger
    colog::init();

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
    info!("Server running on port 8080");

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
