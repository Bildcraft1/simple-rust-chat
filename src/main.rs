use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use colog;
use log::{debug, error, info, warn};
use serde::Deserialize;
use std::fs;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use x25519_dalek::{EphemeralSecret, PublicKey};

#[derive(Deserialize)]
struct Config {
    ip: String,
    port: Option<u16>,
}

#[tokio::main]
async fn main() {
    colog::init();

    let contents =
        fs::read_to_string("config.toml").expect("Should have been able to read the file");
    let config: Config =
        toml::from_str(&contents).expect("Should have been able to parse the file");

    info!("Enter your username (or press Enter to use a random one): ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let mut username = input.trim().to_string();

    if !username.is_empty() {
        username = input.trim().to_string();
    } else {
        username = format!("User{}", rand::random::<u32>());
    }

    info!("Username: {}", username);

    let port = config.port.unwrap_or(8080);
    info!("Connecting to server at {}:{}", config.ip, port);

    // Connect to the server
    let stream = TcpStream::connect(format!("{}:{}", config.ip, port))
        .await
        .unwrap();

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    info!("Generating the Keys");

    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_public = PublicKey::from(&client_secret);

    writer.write_all(client_public.as_bytes()).await.unwrap();

    let mut server_public_bytes = [0u8; 32];
    reader.read_exact(&mut server_public_bytes).await.unwrap();

    let server_public = PublicKey::from(server_public_bytes);
    let shared_secret = client_secret.diffie_hellman(&server_public);

    info!("Shared Secret: {:?}", shared_secret.as_bytes());
    info!("Server public key: {:?}", server_public.as_bytes());

    let key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher_reader = Aes256Gcm::new(&key);
    let cipher_writer = Aes256Gcm::new(&key);
    let nonce_reader = Nonce::from_slice(b"unique nonce"); // 96-bits; fixed nonce
    let nonce_writer = nonce_reader.clone();

    warn!("Nonce: {:?}", nonce_reader);

    debug!("Sending Username");

    let encrypted = match cipher_writer.encrypt(&nonce_writer, username.as_bytes()) {
        Ok(encrypted) => encrypted,
        Err(e) => {
            error!("Encryption error: {}", e);
            return;
        }
    };

    let encoded = BASE64.encode(&encrypted);

    if let Err(e) = writer.write_all((encoded + "\n").as_bytes()).await {
        error!("Failed to send username: {}", e);
        return;
    }

    info!("Starting the chat");

    // Task for sending user input to the server
    let send_task = tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut stdin_reader = BufReader::new(stdin);
        let mut input = String::new();

        loop {
            input.clear();
            tokio::io::stdout().flush().await.unwrap();

            stdin_reader.read_line(&mut input).await.unwrap();

            if input.trim().is_empty() {
                continue;
            }

            if input.trim() == "/quit" {
                info!("Disconnecting from server");
                break;
            }

            // Encrypt the input
            let encrypted = match cipher_writer.encrypt(&nonce_writer, input.trim().as_bytes()) {
                Ok(encrypted) => encrypted,
                Err(e) => {
                    error!("Encryption error: {}", e);
                    continue;
                }
            };

            let encoded = BASE64.encode(&encrypted);

            if let Err(e) = writer.write_all((encoded + "\n").as_bytes()).await {
                error!("Failed to send message: {}", e);
                break;
            }
        }
    });

    // Task for receiving messages from the server
    let receive_task = tokio::spawn(async move {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // Server closed connection
                    info!("\nServer disconnected");
                    break;
                }
                Ok(_) => {
                    let decoded = match BASE64.decode(line.trim()) {
                        Ok(decoded) => decoded,
                        Err(e) => {
                            error!("Base64 decode error: {}", e);
                            continue;
                        }
                    };

                    let decrypted = match cipher_reader.decrypt(&nonce_reader, &*decoded) {
                        Ok(decrypted) => decrypted,
                        Err(e) => {
                            error!("Decryption error: {}", e);
                            continue;
                        }
                    };

                    let message = match String::from_utf8(decrypted) {
                        Ok(msg) => msg,
                        Err(e) => {
                            error!("UTF-8 conversion error: {}", e);
                            continue;
                        }
                    };

                    info!("Received: {}", message.trim());
                    info!("Enter message: ");
                    tokio::io::stdout().flush().await.unwrap();
                }
                Err(e) => {
                    error!("Error reading from server: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for tasks to complete
    tokio::select! {
        _ = send_task => (),
        _ = receive_task => (),
    }

    info!("Client exiting");
}
