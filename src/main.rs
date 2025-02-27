use tokio::{
    net::TcpListener,
    io::AsyncReadExt,
    sync::Mutex,
};
use std::{
    collections::{HashMap, HashSet}, 
    sync::Arc,
};
use tokio::sync::RwLock;
mod modules;
use bytes::BytesMut;

lazy_static::lazy_static! {
    pub static ref REQUEST_HASHES: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
}
lazy_static::lazy_static! {
    pub static ref CONNECTIONS: Arc<RwLock<HashMap<String, Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>>>> = 
        Arc::new(RwLock::new(HashMap::new()));
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:8081").await?;
    let nodes_conns: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (socket, _addr) = listener.accept().await?;
        let nodes_conns_clone = Arc::clone(&nodes_conns);

        tokio::spawn(handle_client(socket, nodes_conns_clone));
    }
}

async fn handle_client(socket: tokio::net::TcpStream, nodes_conns: Arc<Mutex<HashMap<String, String>>>) {
    let mut buffer = BytesMut::with_capacity(1024);
    let (mut read_half, write_half) = socket.into_split();
    let writer = Arc::new(Mutex::new(write_half));
    loop {
        match read_half.read_buf(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => {
                if n < 5 {
                    println!("[ERROR] Invalid packet: too short");
                    continue;
                }
                let prefix = &buffer[0..3];
                if prefix[0] > 5 {
                    buffer.clear();
                    continue;
                }
                let payload_size_bytes = &buffer[1..3];
                let payload_size = u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;
                if buffer.len() < payload_size as usize {
                    println!("[INFO] Waiting for more data...");
                    continue;
                }
                if prefix[0] == 0 {
                    println!("Ping Test !");
                }
                else if prefix[0] == 1 {
                    modules::handle::handle_connect(&buffer, writer.clone()).await;
                }
                else if prefix[0] < 5 {
                    modules::handle::forward(&buffer).await;
                }
                else {
                    println!("Data not recognized");
                }
                buffer.clear();
            }
            Err(e) => {
                println!("[ERROR] Failed to read from socket: {}", e);
                break;
            }
        }
    }
}

