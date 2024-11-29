use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use colog;
use log::{error, info};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use x25519_dalek::{EphemeralSecret, PublicKey};

#[tokio::main]
async fn main() {
    // Initialize the logger
    colog::init();

    // Bind a TCP listener to accept incoming connections
    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
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

async fn handle_client(
    socket: TcpStream,
    tx: broadcast::Sender<String>,
    mut rx: broadcast::Receiver<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_public = PublicKey::from(&server_secret);

    // Send the server's public key to the client
    writer.write_all(server_public.as_bytes()).await?;

    // Receive the client's public key
    let mut client_public_bytes = [0u8; 32];
    reader.read_exact(&mut client_public_bytes).await?;
    let client_public = PublicKey::from(client_public_bytes);

    // Compute the shared secret
    let shared_secret = server_secret.diffie_hellman(&client_public);

    let key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());

    let cipher_reader = Aes256Gcm::new(&key);
    let cipher_writer = Aes256Gcm::new(&key);
    let nonce_reader = Nonce::from_slice(b"unique nonce"); // 96-bits; fixed nonce
    let nonce_writer = nonce_reader.clone();

    // Read task for receiving messages from the client
    let read_task = tokio::spawn(async move {
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        info!("Client disconnected");
                        break;
                    }

                    let decoded = match BASE64.decode(line.trim().as_bytes()) {
                        Ok(decoded) => decoded,
                        Err(e) => {
                            error!("Base64 decode error: {:?}", e);
                            continue;
                        }
                    };

                    let decrypted = match cipher_reader.decrypt(&nonce_reader, decoded.as_ref()) {
                        Ok(decrypted) => decrypted,
                        Err(e) => {
                            error!("Decryption error: {:?}", e);
                            continue;
                        }
                    };

                    let message = match String::from_utf8(decrypted) {
                        Ok(msg) => msg,
                        Err(e) => {
                            error!("UTF-8 conversion error: {:?}", e);
                            continue;
                        }
                    };

                    info!("Received message: {}", message.trim());

                    if message.trim() == "/quit" {
                        info!("Client requested to quit");
                        break;
                    }

                    // Broadcast the message to all clients
                    match tx.send(message) {
                        Ok(_) => info!("Message broadcast successfully"),
                        Err(e) => {
                            error!("Failed to broadcast message: {:?}", e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading from client: {:?}", e);
                    break;
                }
            }
        }
    });

    // Write task for sending messages to the client
    let write_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if !msg.is_empty() {
                // Encrypt the message
                let encrypted = match cipher_writer.encrypt(&nonce_writer, msg.as_bytes()) {
                    Ok(encrypted) => encrypted,
                    Err(e) => {
                        error!("Encryption error: {:?}", e);
                        continue;
                    }
                };

                // Base64 encode the encrypted message
                let encoded = BASE64.encode(&encrypted);

                if let Err(e) = writer.write_all((encoded + "\n").as_bytes()).await {
                    error!("Failed to send message: {:?}", e);
                    break;
                }
            }
        }
    });

    // Wait for both tasks to complete
    tokio::select! {
        _ = read_task => (),
        _ = write_task => (),
    }

    info!("Client handling completed");
    Ok(())
}