use futures::{SinkExt, StreamExt};
use log::info;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LinesCodec};

#[tokio::main]
async fn main() {
    colog::init();

    info!("Client");
    info!("Enter Server Address");
    let addr: String = read_string();
    info!("Server address: {}", &addr);

    let stream = TcpStream::connect(addr)
        .await
        .expect("Could not connect to server");

    info!("Connected to server");

    let (tx, mut rx) = mpsc::channel::<String>(32);
    let mut frame = Framed::new(stream, LinesCodec::new());

    // Spawn a single task to handle both sending and receiving
    let network_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(Ok(line)) = frame.next() => {
                    info!("Received: {}", line);
                }
                Some(message) = rx.recv() => {
                    if let Err(e) = frame.send(message).await {
                        info!("Failed to send message: {}", e);
                        break;
                    }
                }
                else => break,
            }
        }
    });

    // Main loop for reading user input
    loop {
        info!("Enter message to send:");
        let message = read_string();
        if let Err(e) = tx.send(message).await {
            info!("Failed to send to channel: {}", e);
            break;
        }
    }

    // Wait for the network and heartbeat tasks to complete
    if let Err(e) = network_task.await {
        info!("Network task failed: {}", e);
    }
}

fn read_string() -> String {
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("can not read user input");
    input.trim().to_string()
}
