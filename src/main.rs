use log::{debug, error, info, trace, warn};
use std::env::args;
use std::net::{TcpListener, TcpStream};

#[derive(Debug)]
struct Settings {
    host: String,
    port: String,
}

impl Settings {
    fn new(args: &[String]) -> Result<Settings, &'static str> {
        if args.len() < 4 {
            return Err("not enough arguments");
        }

        let port = args[2].clone();
        let host = args[4].clone();

        Ok(Settings { host, port })
    }

    fn get_full_host(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

async fn handle_client(mut stream: TcpStream) {
    info!("Connected to {}", stream.peer_addr().unwrap());
    stream.set_nodelay(true).unwrap();

    loop {
        
    }
}

#[tokio::main]
async fn main() {
    colog::init();
    info!("Starting...");
    let args: Vec<String> = args().collect();
    let settings = Settings::new(&args).unwrap();
    info!("Server Address: {}:{}", settings.host, settings.port);
    info!("Starting to listen to connections...");
    let listener = TcpListener::bind(Settings::get_full_host(&settings)).unwrap();
    match listener.accept() {
        Ok((socket, _)) => {
            tokio::spawn(async move {
                handle_client(socket).await;
            });
        }
        Err(e) => {
            error!("Something went wrong {}", e);
        }
    }
}
