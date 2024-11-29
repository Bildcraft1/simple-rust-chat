// main.rs
use colog;
use log::info;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

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
            handle_client(socket, tx, rx).await;
        });
    }
}

async fn handle_client(
    socket: TcpStream,
    tx: broadcast::Sender<String>,
    mut rx: broadcast::Receiver<String>,
) {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Task for reading messages from the client
    let mut read_task = tokio::spawn(async move {
        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await.unwrap();
            if bytes_read == 0 {
                break;
            }
            tx.send(line.clone()).unwrap();
        }
    });

    // Task for sending messages to the client
    let mut write_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            writer.write_all(msg.as_bytes()).await.unwrap();
        }
    });

    // Wait for both tasks to complete
    tokio::select! {
        _ = &mut read_task => (),
        _ = &mut write_task => (),
    }

    info!("Client disconnected");
}
