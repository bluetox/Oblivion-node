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
    let nodes_conns = Arc::new(Mutex::new(HashMap::new()));
    loop {
        let (socket, _addr) = listener.accept().await?;
        let request_hashes = REQUEST_HASHES.clone();
        let nodes_conns_clone = Arc::clone(&nodes_conns);
        let (mut read_half, write_half) = socket.into_split();
        let writer = Arc::new(Mutex::new(write_half));
        println!("New connection established");

        tokio::spawn(async move {
            let mut buffer = Vec::new();
            let mut chunk = vec![0; 1024];
            loop {
                match read_half.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buffer.extend_from_slice(&chunk[..n]);
                        if let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                            let received = String::from_utf8_lossy(&buffer[..pos]).trim().to_string();
                            buffer.drain(..=pos);

                            if let Ok(input) = serde_json::from_str::<modules::json_structs::Input>(&received) {
                                if input.data.ip == "192.168.1.51:8081" {
                                    println!("Received connect");
                                    modules::handle::handle_connect(received, Arc::clone(&writer), request_hashes.clone()).await;

                                } else {
                                    println!("Received Broadcast");
                                    modules::handle::handle_broadcast(received, Arc::clone(&nodes_conns_clone)).await;
                                }
                            }
                            else if let Ok(_input) = serde_json::from_str::<modules::json_structs::AppendKyberKey>(&received) {
                                println!("Forwarding KyberKey");
                                modules::handle::forward(received, Arc::clone(&nodes_conns_clone)).await;
                            }
                            else if let Ok(_input) = serde_json::from_str::<modules::json_structs::AppendCypherText>(&received) {
                                println!("Forwarding CypherText");
                                modules::handle::forward(received, Arc::clone(&nodes_conns_clone)).await;
                            }
                            else if let Ok(_input) = serde_json::from_str::<modules::json_structs::ForwardMessage>(&received) {
                                println!("Forwarding Message");
                                modules::handle::forward(received, Arc::clone(&nodes_conns_clone)).await;
                            }
                        }
                    }
                    Err(e) => {
                        println!("[ERROR] Failed to read from socket: {}", e);
                        break;
                    }
                }
            }
        });
    }
}