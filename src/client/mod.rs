pub(crate) mod handlers {
    use aes_gcm::{
        aead::{Aead, KeyInit, OsRng},
        Aes256Gcm, Key, Nonce,
    };

    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use log::{debug, error, info};
    use serde::Deserialize;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    use tokio::sync::broadcast;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    use crate::db::users::create_user;
    /*
        Specifications of the packet
        32 bytes - Command name
        512 bytes - Command argument
        if command is empty then it is a message
    */
    #[derive(Deserialize, Debug)]
    struct Message {
        command: Vec<String>,
        argument: Vec<String>, // Changed from Vec<str> to Vec<String>
    }

    fn parse_message(message: &str) -> Message {
        let mut iter = message.split_whitespace();

        let command: Vec<String> = if let Some(cmd) = iter.next() {
            if cmd.starts_with("/") {
                vec![cmd.to_string()]
            } else {
                Vec::new() // Empty command means it's a regular message
            }
        } else {
            Vec::new()
        };

        let argument: Vec<String> = iter.map(String::from).collect();

        Message { command, argument }
    }

    pub async fn handle_client(
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

        debug!("Reciving Username");

        // Read the username from the client
        line.clear();
        reader.read_line(&mut line).await?;
        let decoded = BASE64.decode(line.trim().as_bytes())?;
        let decrypted = cipher_reader
            .decrypt(&nonce_reader, decoded.as_ref())
            .unwrap();
        let username = Arc::new(String::from_utf8(decrypted)?);
        let username_read = Arc::clone(&username); // Clone the Arc for read task
        let username_write = Arc::clone(&username); // Clone the Arc for write task

        create_user(&username, "1234").await?;

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

                        let decrypted = match cipher_reader.decrypt(&nonce_reader, decoded.as_ref())
                        {
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

                        info!("Parsing message");

                        let parsed_message = parse_message(message.as_str());
                        // Handle commands
                        if !parsed_message.command.is_empty() {
                            match parsed_message.command[0].as_str() {
                                "/msg" => {
                                    if parsed_message.argument.len() < 2 {
                                        match tx.send("Error! Invalid /msg format".to_string()) {
                                            Ok(_) => info!(
                                                "Error message sent to client {}",
                                                username_write
                                            ),
                                            Err(e) => {
                                                error!("Failed to send error message: {:?}", e);
                                                break;
                                            }
                                        }
                                        continue;
                                    }
                                    let target_user = &parsed_message.argument[0];
                                    let msg_content = parsed_message.argument[1..].join(" ");
                                    info!("Private message to {}: {}", target_user, msg_content);
                                }

                                "/quit" => {
                                    info!("Client requested to quit");
                                    break;
                                }

                                "/nickname" => {
                                    if parsed_message.argument.is_empty() {
                                        error!(
                                            "Invalid /nickname format. Usage: /nickname new_name"
                                        );
                                        continue;
                                    }
                                    let new_nickname = &parsed_message.argument[0];
                                    info!("Changing nickname to: {}", new_nickname);
                                    // Here implement your nickname change logic
                                }

                                _ => {
                                    error!("Unknown command: {}", parsed_message.command[0]);
                                    match tx.send("Error! Unknown command".to_string()) {
                                        Ok(_) => {
                                            info!("Error message sent to client {}", username_write)
                                        }
                                        Err(e) => {
                                            error!("Failed to send error message: {:?}", e);
                                            break;
                                        }
                                    }
                                }
                            }
                        } else {
                            // Regular message handling
                            info!(
                                "Received message from {}: {}",
                                username_read,
                                parsed_message.argument.join(" ")
                            );

                            let formatted_message =
                                format!("{}: {}", username_read, message.trim());

                            // Broadcast the message to all clients
                            match tx.send(formatted_message) {
                                Ok(_) => info!("Message broadcast successfully"),
                                Err(e) => {
                                    error!("Failed to broadcast message: {:?}", e);
                                    break;
                                }
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
                    // Encrypt the message with error handling
                    let encrypted = match cipher_writer.encrypt(&nonce_writer, msg.as_bytes()) {
                        Ok(encrypted) => encrypted,
                        Err(e) => {
                            error!("Encryption error: {:?}", e);
                            continue;
                        }
                    };

                    // Base64 encode and format with newline
                    let message = format!("{}\n", BASE64.encode(&encrypted));

                    // Write with proper error handling
                    if let Err(e) = writer.write_all(message.as_bytes()).await {
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
}
