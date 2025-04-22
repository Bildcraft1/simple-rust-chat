use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use colog;
use log::{debug, error, info, warn};
use notify_rust::Notification;
use serde::Deserialize;
use std::{
    fs,
    fs::File,
    io,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::mpsc,
    time::{sleep, Duration},
};
use x25519_dalek::{EphemeralSecret, PublicKey};
// Ratatui imports
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Position},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};

#[derive(Deserialize)]
struct Config {
    ip: String,
    port: Option<u16>,
}

// UI structs and enums
enum InputMode {
    Normal,
    Editing,
}

struct ChatState {
    input: String,
    messages: Vec<(String, String)>, // (username, message)
    input_mode: InputMode,
    username: String,
    should_quit: bool,
}

impl ChatState {
    fn new(username: String) -> Self {
        ChatState {
            input: String::new(),
            messages: Vec::new(),
            input_mode: InputMode::Editing,
            username,
            should_quit: false,
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // Restore terminal
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture);

        // Call the original hook
        original_hook(panic_info);
    }));

    colog::init();

    let contents =
        fs::read_to_string("config.toml").expect("Should have been able to read the file");
    let config: Config =
        toml::from_str(&contents).expect("Should have been able to parse the file");

    info!("Enter your username (or press Enter to use a random one): ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let username = if input.trim().is_empty() {
        format!("User{}", rand::random::<u32>())
    } else {
        input.trim().to_string()
    };

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
            return Ok(());
        }
    };

    let encoded = BASE64.encode(&encrypted);

    if let Err(e) = writer.write_all((encoded + "\n").as_bytes()).await {
        error!("Failed to send username: {}", e);
        return Ok(());
    }

    info!("Starting the chat");

    // Setup UI
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Setup channels for communication
    let (tx_ui, mut rx_ui) = mpsc::channel::<(String, String)>(100);
    let (tx_net, mut rx_net) = mpsc::channel::<String>(100);

    // Create shared state
    let chat_state = Arc::new(Mutex::new(ChatState::new(username.clone())));
    let chat_state_ui = Arc::clone(&chat_state);

    // Task for UI handling
    let ui_task = tokio::spawn(async move {
        let mut chat_state = chat_state_ui;

        loop {
            let should_quit = {
                let state = chat_state.lock().unwrap();
                state.should_quit
            };

            if should_quit {
                break;
            }

            // Check for new messages from network
            if let Ok(msg) = rx_ui.try_recv() {
                let mut state = chat_state.lock().unwrap();
                state.messages.push(msg);
            }

            // Handle input events
            if let Ok(should_break) = ui_loop(&mut terminal, &mut chat_state, &tx_net) {
                if should_break {
                    break;
                }
            }

            sleep(Duration::from_millis(16)).await; // ~60 fps refresh rate
        }
        if let Err(e) = disable_raw_mode() {
            error!("Failed to disable raw mode: {}", e);
        }

        if let Err(e) = execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        ) {
            error!("Failed to leave alternate screen: {}", e);
        }

        if let Err(e) = terminal.show_cursor() {
            error!("Failed to show cursor: {}", e);
        }
    });

    // Task for sending messages to the server
    let send_task = tokio::spawn(async move {
        while let Some(input) = rx_net.recv().await {
            // Encrypt the input
            let encrypted = match cipher_writer.encrypt(&nonce_writer, input.as_bytes()) {
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
                    tx_ui
                        .send(("System".to_string(), "Server disconnected".to_string()))
                        .await
                        .ok();
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

                    if message.contains('|') {
                        // Handle DM format
                        let parts: Vec<&str> = message.splitn(2, '|').collect();
                        if parts.len() == 2 {
                            let sender = parts[0].trim();
                            // The second part contains both receiver and message
                            let receiver_and_message = parts[1].trim();
                            // Split at the first space to separate receiver from message
                            if let Some(space_pos) = receiver_and_message.find(' ') {
                                let (receiver, content) = receiver_and_message.split_at(space_pos);
                                if receiver != username {
                                    // If the receiver is the same as the client, ignore
                                    continue;
                                }

                                let content = content.trim_start();

                                // Style as DM
                                let dm_label = if sender == &username {
                                    format!("DM to {}: ", receiver)
                                } else {
                                    format!("DM from {}: ", sender)
                                };

                                tx_ui
                                    .send(("DM".to_string(), format!("{}{}", dm_label, content)))
                                    .await
                                    .ok();
                            }
                        }
                    } else if message.contains("dl!") {
                        // Handle file download request
                        let parts: Vec<&str> = message.splitn(2, ' ').collect();
                        if parts.len() == 2 {
                            let filename = parts[1].trim();
                            tx_ui
                                .send((
                                    "System".to_string(),
                                    format!("Download request for file: {}", filename),
                                ))
                                .await
                                .ok();
                            let resp = reqwest::get(filename).await.expect("request failed");
                            let body = resp.bytes().await.expect("body invalid");
                            // get the file name from the end of the link
                            let filename = filename.split('/').last().unwrap_or("file");
                            // Create the file
                            let mut out = File::create(filename).expect("failed to create file");
                            let body_bytes = body.to_vec();
                            io::copy(&mut &body_bytes[..], &mut out)
                                .expect("failed to copy content");
                            tx_ui
                                .send((
                                    "System".to_string(),
                                    format!("Download completed, {}", filename),
                                ))
                                .await
                                .ok();
                        }
                    } else if let Some(pos) = message.find(':') {
                        let (sender, content) = message.split_at(pos);
                        if sender == username {
                            // If the sender is the same as the client, ignore
                            continue;
                        }

                        // if the message contains a @username, highlight it
                        if content.contains(&username) {
                            // send the message in chat

                            Notification::new()
                                .summary("You got tagged in a message")
                                .body(&format!("{}{}", sender, content))
                                .show()
                                .unwrap();
                        }

                        // Skip the colon and any space
                        let content = content.trim_start_matches(|c| c == ':' || c == ' ');
                        tx_ui
                            .send((sender.to_string(), content.to_string()))
                            .await
                            .ok();
                    } else {
                        // If message format is different, treat as system message
                        tx_ui.send(("System".to_string(), message)).await.ok();
                    }
                }
                Err(e) => {
                    error!("Error reading from server: {}", e);
                    tx_ui
                        .send(("System".to_string(), format!("Error: {}", e)))
                        .await
                        .ok();
                    break;
                }
            }
        }
    });

    // Wait for tasks to complete
    tokio::select! {
        _ = ui_task => (),
        _ = send_task => (),
        _ = receive_task => (),
    }

    info!("Client exiting");
    Ok(())
}

// UI rendering function
fn ui_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    chat_state: &mut Arc<Mutex<ChatState>>,
    tx_net: &mpsc::Sender<String>,
) -> io::Result<bool> {
    terminal.draw(|f| {
        let size = f.area();

        // Create layout with chat messages on top and input at bottom
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([Constraint::Min(3), Constraint::Length(3)])
            .split(size);

        let state = chat_state.lock().unwrap();

        // Create messages list
        let messages: Vec<ListItem> = state
            .messages
            .iter()
            .map(|(username, message)| {
                let username_style = if username == &state.username {
                    Style::default().fg(Color::Green)
                } else if username == "System" {
                    Style::default().fg(Color::Yellow)
                } else if username == "DM" {
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Blue)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{}: ", username), username_style),
                    Span::raw(message),
                ]))
            })
            .collect();

        let messages =
            List::new(messages).block(Block::default().borders(Borders::ALL).title("Messages"));

        // Input box
        let input = Paragraph::new(state.input.as_str())
            .style(match state.input_mode {
                InputMode::Normal => Style::default(),
                InputMode::Editing => Style::default().fg(Color::Yellow),
            })
            .block(Block::default().borders(Borders::ALL).title("Input"));

        f.render_widget(messages, chunks[0]);
        f.render_widget(input, chunks[1]);

        // Set cursor position
        match state.input_mode {
            InputMode::Normal => {}
            InputMode::Editing => {
                f.set_cursor_position(Position::new(
                    chunks[1].x + 1 + state.input.len() as u16,
                    chunks[1].y + 1,
                ));
            }
        }
    })?;

    // Handle events
    if event::poll(Duration::from_millis(10))? {
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                let mut state = chat_state.lock().unwrap();

                match state.input_mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('e') => {
                            state.input_mode = InputMode::Editing;
                        }
                        KeyCode::Char('q') => {
                            state.should_quit = true;
                            tx_net.try_send("/quit".to_string()).ok();
                            return Ok(true);
                        }
                        _ => {}
                    },
                    InputMode::Editing => match key.code {
                        KeyCode::Enter => {
                            let message = state.input.drain(..).collect::<String>();
                            if !message.is_empty() {
                                drop(state); // Release mutex before async operation

                                // Add message to UI
                                let username_clone = {
                                    let state = chat_state.lock().unwrap();
                                    state.username.clone()
                                };
                                let mut state = chat_state.lock().unwrap();
                                state
                                    .messages
                                    .push((username_clone.clone(), message.clone()));

                                // Send to network
                                tx_net.try_send(message).ok();
                            }
                        }
                        KeyCode::Char(c) => {
                            state.input.push(c);
                        }
                        KeyCode::Backspace => {
                            state.input.pop();
                        }
                        KeyCode::Esc => {
                            state.input_mode = InputMode::Normal;
                        }
                        _ => {}
                    },
                }
            }
        }
    }

    Ok(false)
}
