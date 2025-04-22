pub(crate) mod handlers {
    use aes_gcm::{
        aead::{Aead, KeyInit, OsRng},
        Aes256Gcm, Key, Nonce,
    };

    use crate::db::users::{
        add_kick, add_new_file, add_verified_flag_to_file, ban_user, change_password, check_ban,
        check_file_verified, check_for_account, check_kick, create_user, get_ban_reason,
        hash_password, remove_kick, request_file, unban_user, verify_admin, verify_password,
    };
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use log::{debug, error, info};
    use serde::Deserialize;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    use tokio::sync::broadcast;
    use x25519_dalek::{EphemeralSecret, PublicKey};

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
        info!("Username received: {}", username);

        // Check if the user already exists in the database
        if check_for_account(&username).await? {
            // Check if the user is banned
            if check_ban(&username).await? == true {
                let ban_reason_result = get_ban_reason(&username).await;

                let message: String = match ban_reason_result {
                    Ok(Some(reason)) => {
                        info!("User {} is banned, Reason: {}", username, reason);
                        format!("User {} is banned, Reason: {}", username, reason).to_string()
                    }
                    Ok(None) => {
                        info!("User {} is banned, but no reason provided", username);
                        format!("User {} is banned, but no reason provided", username).to_string()
                    }
                    Err(e) => {
                        error!("Error fetching ban reason: {}", e);
                        format!("You are banned").to_string();
                        return Ok(());
                    }
                };

                let encrypted = match cipher_writer.encrypt(&nonce_writer, message.as_bytes()) {
                    Ok(encrypted) => encrypted,
                    Err(e) => {
                        error!("Encryption error: {}", e);
                        return Ok(());
                    }
                };
                let message = format!("{}\n", BASE64.encode(&encrypted));
                writer.write_all(message.as_bytes()).await?;
                return Ok(());
            }

            info!("User {} already exists", username);
            // Send a message to the client
            let message = format!("User {} is registered, input your password", username);
            let encrypted = match cipher_writer.encrypt(&nonce_writer, message.as_bytes()) {
                Ok(encrypted) => encrypted,
                Err(e) => {
                    error!("Encryption error: {}", e);
                    return Ok(());
                }
            };
            let message = format!("{}\n", BASE64.encode(&encrypted));
            writer.write_all(message.as_bytes()).await?;

            // Read the password from the client
            line.clear();
            reader.read_line(&mut line).await?;
            let decoded = BASE64.decode(line.trim().as_bytes())?;
            let decrypted = cipher_reader
                .decrypt(&nonce_reader, decoded.as_ref())
                .unwrap();
            // verifiy password
            let password = String::from_utf8(decrypted)?;
            if verify_password(&username, &password).await? == true {
                info!("Password verified successfully");
            } else {
                info!("Password verification failed");
                // Send an error message to the client
                let message = format!("Invalid password for user {}", username);
                let encrypted = match cipher_writer.encrypt(&nonce_writer, message.as_bytes()) {
                    Ok(encrypted) => encrypted,
                    Err(e) => {
                        error!("Encryption error: {}", e);
                        return Ok(());
                    }
                };
                let message = format!("{}\n", BASE64.encode(&encrypted));
                writer.write_all(message.as_bytes()).await?;
                return Ok(());
            }
        } else {
            // User does not exist, create a new account
            // Send a message to the client
            let message = format!("User {} is not registered, input your password", username);
            let encrypted = match cipher_writer.encrypt(&nonce_writer, message.as_bytes()) {
                Ok(encrypted) => encrypted,
                Err(e) => {
                    error!("Encryption error: {}", e);
                    return Ok(());
                }
            };
            let message = format!("{}\n", BASE64.encode(&encrypted));
            writer.write_all(message.as_bytes()).await?;
            // Read the password from the client
            line.clear();
            reader.read_line(&mut line).await?;
            let decoded = BASE64.decode(line.trim().as_bytes())?;
            let decrypted = cipher_reader
                .decrypt(&nonce_reader, decoded.as_ref())
                .unwrap();
            let password = String::from_utf8(decrypted)?;
            info!("Password received");
            // Hash the password
            let password_hash = hash_password(&password).await;
            let password_hash = password_hash.as_str();
            info!("Password hashed successfully");
            debug!("Hash: {}", password_hash);
            // Create the user in the database
            create_user(&username, password_hash).await?;
        }
        // Send a success message to the client
        let message = format!("Welcome, {}!", username);
        let encrypted = match cipher_writer.encrypt(&nonce_writer, message.as_bytes()) {
            Ok(encrypted) => encrypted,
            Err(e) => {
                error!("Encryption error: {}", e);
                return Ok(());
            }
        };
        let message = format!("{}\n", BASE64.encode(&encrypted));
        writer.write_all(message.as_bytes()).await?;

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

                        if check_kick(&username).await.unwrap() == true {
                            info!("User {} is kicked", username);
                            let message = format!("User {} is kicked", username);
                            let _ = tx.send(message);
                            remove_kick(&username).await.unwrap();
                            break;
                        }

                        if check_ban(&username).await.unwrap() == true {
                            info!("User {} is banned", username);
                            let message = format!("User {} is banned", username);
                            let _ = tx.send(message);
                            break;
                        }

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
                                    // dm format sender|target_user message
                                    let formatted_message = format!(
                                        "{}|{} {}",
                                        username_read, target_user, msg_content
                                    );
                                    match tx.send(formatted_message) {
                                        Ok(_) => info!("Private message sent successfully"),
                                        Err(e) => {
                                            error!("Failed to send private message: {:?}", e);
                                            break;
                                        }
                                    }
                                }

                                "/quit" => {
                                    info!("Client requested to quit");
                                    break;
                                }

                                "/kick" => {
                                    if parsed_message.argument.is_empty() {
                                        error!("Invalid /kick format. Usage: /kick username");
                                        match tx.send(
                                            format!("Error! Invalid /kick format").to_string(),
                                        ) {
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

                                    match verify_admin(&username_read).await {
                                        Ok(true) => {
                                            info!("User {} is admin", username);
                                            let target_user = &parsed_message.argument[0];
                                            info!("Kicking user: {}", target_user);
                                            add_kick(&target_user).await.unwrap();
                                            match tx.send(format!(
                                                "User {} has been kicked",
                                                target_user
                                            )) {
                                                Ok(_) => info!(
                                                    "Error message sent to client {}",
                                                    username_write
                                                ),
                                                Err(e) => {
                                                    error!("Failed to send error message: {:?}", e);
                                                    break;
                                                }
                                            }
                                        }
                                        Ok(false) => {
                                            error!("User {} is not admin", username);
                                            continue;
                                        }
                                        Err(e) => {
                                            error!("Error verifying admin: {:?}", e);
                                            continue;
                                        }
                                    }
                                }

                                "/addfile" => {
                                    if parsed_message.argument.is_empty() {
                                        error!("Invalid /addfile format. Usage: /addfile filename link");
                                        match tx.send(
                                            format!("Invalid /addfile format. Usage: /addfile filename link").to_string(),
                                        ) {
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

                                    let file_name = &parsed_message.argument[0];
                                    let file_link = &parsed_message.argument[1];
                                    info!("Adding file: {}", file_name);
                                    info!("File link: {}", file_link);

                                    add_new_file(&file_name, &file_link).await.unwrap();

                                    match tx.send(format!("File {} has been added", file_name)) {
                                        Ok(_) => {
                                            info!("Error message sent to client {}", username_write)
                                        }
                                        Err(e) => {
                                            error!("Failed to send error message: {:?}", e);
                                            break;
                                        }
                                    }
                                }

                                "/verifylink" => {
                                    if parsed_message.argument.is_empty() {
                                        error!("Invalid /verifylink format. Usage: /verifylink filename");
                                        match tx.send(
                                            format!("Invalid /verifylink format. Usage: /verifylink filename").to_string(),
                                        ) {
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

                                    let file_name = &parsed_message.argument[0];
                                    info!("Verifying link for file: {}", file_name);

                                    match verify_admin(&username).await {
                                        Ok(true) => {
                                            info!("User {} is admin", username);
                                            add_verified_flag_to_file(file_name).await.unwrap();
                                            match tx.send(format!(
                                                "File {} has been verified",
                                                file_name
                                            )) {
                                                Ok(_) => info!(
                                                    "Error message sent to client {}",
                                                    username_write
                                                ),
                                                Err(e) => {
                                                    error!("Failed to send error message: {:?}", e);
                                                    break;
                                                }
                                            }
                                        }
                                        Ok(false) => {
                                            error!("User {} is not admin", username);
                                            continue;
                                        }
                                        Err(e) => {
                                            error!("Error verifying admin: {:?}", e);
                                            continue;
                                        }
                                    }
                                }

                                "/requestfile" => {
                                    if parsed_message.argument.is_empty() {
                                        error!("Invalid /requestfile format. Usage: /requestfile filename");
                                        match tx.send(
                                            format!("Invalid /requestfile format. Usage: /requestfile filename").to_string(),
                                        ) {
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

                                    let file_name = &parsed_message.argument[0];
                                    info!("Requesting file: {}", file_name);

                                    let file_link = request_file(file_name).await.unwrap();

                                    match tx.send(format!("Link for {}: {}", file_name, file_link))
                                    {
                                        Ok(_) => {
                                            info!("message sent to client {}", username_write)
                                        }
                                        Err(e) => {
                                            error!("Failed to send error message: {:?}", e);
                                            break;
                                        }
                                    }

                                    if check_file_verified(file_name).await.unwrap() == true {
                                        match tx.send(format!("dl! {}", file_link)) {
                                            Ok(_) => info!(
                                                "Error message sent to client {}",
                                                username_write
                                            ),
                                            Err(e) => {
                                                error!("Failed to send error message: {:?}", e);
                                                break;
                                            }
                                        }
                                    }
                                }

                                "/ban" => {
                                    if parsed_message.argument.is_empty() {
                                        error!("Invalid /ban format. Usage: /ban username");
                                        match tx
                                            .send(format!("Error! Invalid /ban format").to_string())
                                        {
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

                                    match verify_admin(&username_read).await {
                                        Ok(true) => {
                                            info!("User {} is admin", username);
                                            let target_user = &parsed_message.argument[0];
                                            info!("Banning user: {}", target_user);
                                            match check_ban(target_user).await {
                                                Ok(true) => {
                                                    info!("User {} is already banned", target_user);
                                                    match tx.send(format!(
                                                        "User {} is already banned",
                                                        target_user
                                                    )) {
                                                        Ok(_) => info!(
                                                            "Error message sent to client {}",
                                                            username_write
                                                        ),
                                                        Err(e) => {
                                                            error!("Failed to send error message: {:?}", e);
                                                            break;
                                                        }
                                                    }
                                                }
                                                Ok(false) => {
                                                    ban_user(
                                                        target_user,
                                                        "You're banned from this server.",
                                                    )
                                                    .await
                                                    .unwrap();
                                                    info!("User {} has been banned", target_user);
                                                    match tx.send(
                                                        format!(
                                                            "User {} has been banned",
                                                            target_user,
                                                        )
                                                        .to_string(),
                                                    ) {
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
                                                Err(e) => {
                                                    error!("Error checking ban status: {:?}", e);
                                                }
                                            }
                                        }
                                        Ok(false) => {
                                            error!("User {} is not admin", username);
                                            continue;
                                        }
                                        Err(e) => {
                                            error!("Error verifying admin: {:?}", e);
                                            continue;
                                        }
                                    }
                                }

                                "/unban" => {
                                    if parsed_message.argument.is_empty() {
                                        error!("Invalid /unban format. Usage: /unban username");
                                    }

                                    match verify_admin(&username_read).await {
                                        Ok(true) => {
                                            info!("User {} is admin", username);
                                            let target_user = &parsed_message.argument[0];
                                            info!("Unbanning user: {}", target_user);
                                            match check_ban(target_user).await {
                                                Ok(true) => {
                                                    info!("User {} is banned", target_user);
                                                    unban_user(target_user).await.unwrap();
                                                    info!("User {} has been unbanned", target_user);
                                                    match tx.send(
                                                        format!(
                                                            "User {} has been unbanned",
                                                            target_user,
                                                        )
                                                        .to_string(),
                                                    ) {
                                                        Ok(_) => info!(
                                                            "Error message sent to client {}",
                                                            username_write
                                                        ),
                                                        Err(e) => {
                                                            error!("Failed to send error message: {:?}", e);
                                                            break;
                                                        }
                                                    }
                                                }
                                                Ok(false) => {
                                                    info!("User {} is not banned", target_user);
                                                    match tx.send(format!(
                                                        "User {} is not banned",
                                                        target_user
                                                    )) {
                                                        Ok(_) => info!(
                                                            "Error message sent to client {}",
                                                            username_write
                                                        ),
                                                        Err(e) => {
                                                            error!("Failed to send error message: {:?}", e);
                                                            break;
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("Error checking ban status: {:?}", e);
                                                }
                                            }
                                        }
                                        Ok(false) => {
                                            error!("User {} is not admin", username);
                                            continue;
                                        }
                                        Err(e) => {
                                            error!("Error verifying admin: {:?}", e);
                                            continue;
                                        }
                                    }
                                }

                                "/changepassword" => {
                                    if parsed_message.argument.len() < 2 {
                                        error!("Invalid /changepassword format. Usage: /changepassword old_password new_password");
                                        match tx
                                            .send(format!("Invalid /changepassword format. Usage: /changepassword old_password new_password"))
                                        {
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

                                    let old_password = &parsed_message.argument[0];
                                    let new_password = &parsed_message.argument[1];

                                    info!("Changing password for user {}", username);
                                    info!("new password: {}", new_password);
                                    info!("old password: {}", old_password);

                                    if verify_password(old_password, &username).await.is_ok() {
                                        match change_password(&username, new_password).await {
                                            Ok(_) => {
                                                info!("Password changed successfully");
                                                let _ = tx.send(
                                                    "Password changed successfully".to_string(),
                                                );
                                            }
                                            Err(e) => {
                                                error!("Error changing password: {:?}", e);
                                                match tx.send(format!(
                                                    "Error changing password: {:?}",
                                                    e
                                                )) {
                                                    Ok(_) => info!(
                                                        "Error message sent to client {}",
                                                        username_write
                                                    ),
                                                    Err(e) => {
                                                        error!(
                                                            "Failed to send error message: {:?}",
                                                            e
                                                        );
                                                        break;
                                                    }
                                                }
                                                continue;
                                            }
                                        }
                                    } else {
                                        info!("Old password verification failed");
                                        match tx.send(format!(
                                            "Invalid old password for user {}",
                                            username
                                        )) {
                                            Ok(_) => info!(
                                                "Error message sent to client {}",
                                                username_write
                                            ),
                                            Err(e) => {
                                                error!("Failed to send error message: {:?}", e);
                                                break;
                                            }
                                        }
                                    }
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
