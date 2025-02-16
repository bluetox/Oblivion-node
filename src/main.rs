use pqc_dilithium::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    net::{TcpListener, TcpStream},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use std::{
    collections::{HashMap, HashSet}, 
    sync::Arc,
    fs,
    error::Error,
};
use chrono::Utc;
use serde_json::Value;
use hex;

#[derive(Serialize, Deserialize)]
struct InputData {
    r#type: String, 
    publicKey: String,
    ts: String,
    ip: String,
}

#[derive(Serialize, Deserialize)]
struct Input {
    signature: String,
    data: InputData,
}

#[derive(Serialize, Deserialize)]
struct Output {
    valid: bool,
    hashedPublicKey: String,
}
fn check_ts_validity(ts: &str) -> bool {
    let ts = ts.parse::<u64>().unwrap_or(0) / 1000;
    let now = Utc::now().timestamp() as u64;
    let diff = now.saturating_sub(ts);
    println!("Parsed TS: {}, Now: {}", ts, now);
    diff <= 10 || (ts > now && (ts - now) <= 2)
}

fn verify_signature(input: &Input) -> bool {
    let pub_key = hex::decode(&input.data.publicKey).ok();
    let sig = hex::decode(&input.signature).ok();
    
    pub_key.zip(sig).map_or(false, |(pk, s)| {
        let message = serde_json::to_string(&input.data).unwrap(); 
        verify(&s, message.as_bytes(), &pk).is_ok()
    })
}


async fn broadcast_conn(data: &InputData) {
    // Read nodes from JSON file
    let nodes = match read_nodes_from_json("nodes.json") {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Failed to read nodes.json: {}", e);
            return;
        }
    };

    // Prepare the message
    let message = serde_json::to_string(&data).unwrap();
    let message_with_newline = format!("{}\n", message); // Ensure it ends with a newline

    let mut tasks = Vec::new();

    // Send data to each node concurrently
    for node_ip in nodes {
        let msg = message_with_newline.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = send_tcp_message(&node_ip, &msg).await {
                eprintln!("Failed to send to {}: {}", node_ip, e);
            }
        }));
    }

    for task in tasks {
        let _ = task.await;
    }
}

// Reads the list of nodes from a JSON file
fn read_nodes_from_json(file_path: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let content = fs::read_to_string(file_path)?;
    let json: Value = serde_json::from_str(&content)?;
    
    let nodes = json.as_array()
        .ok_or("Expected JSON array")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    Ok(nodes)
}

// Sends a message over TCP
async fn send_tcp_message(ip: &str, message: &str) -> Result<(), Box<dyn Error>> {
    if let Ok(mut stream) = TcpStream::connect(ip).await {
        stream.write_all(message.as_bytes()).await?;
        stream.flush().await?;
        println!("Broadcasted message to {}", ip);
    } else {
        println!("Failed to connect to {}", ip);
    }
    Ok(())
}

lazy_static::lazy_static! {
    static ref REQUEST_HASHES: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
}

fn sha256_hash(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    hex::encode(result)
}

async fn handle_connect(
    received: String,
    socket: &mut tokio::net::TcpStream,
    request_hashes: Arc<Mutex<HashSet<String>>>,
    connections: Arc<Mutex<HashMap<String, String>>>,
    addr: std::net::SocketAddr,
) {
    if let Ok(input) = serde_json::from_str::<Input>(&received) {
        if !check_ts_validity(&input.data.ts) {
            println!("Timestamp is not valid!");
            let response = Output { 
                valid: false,
                hashedPublicKey: "".to_string(),
            };
            let response_json = format!("{}\n", serde_json::to_string(&response).unwrap());
            let _ = socket.write_all(response_json.as_bytes()).await;
            return;
        }

        let mut combined_bytes = input.data.publicKey.as_bytes().to_vec();
        combined_bytes.extend(input.data.ts.as_bytes());
        let public_id = sha256_hash(input.data.publicKey.as_bytes());
        let unique_request_hash = sha256_hash(&combined_bytes);

        let mut hashes = request_hashes.lock().await;
        if hashes.contains(&unique_request_hash) {
            println!("Duplicate request detected!");
            let response = Output { 
                valid: false,
                hashedPublicKey: public_id.clone(),
            };
            let response_json = format!("{}\n", serde_json::to_string(&response).unwrap());
            let _ = socket.write_all(response_json.as_bytes()).await;
        } else {
            let is_valid = verify_signature(&input);
            hashes.insert(unique_request_hash.clone());

            let mut conn_map = connections.lock().await;
            conn_map.insert(public_id.clone(), addr.to_string());

            let response = Output {
                valid: is_valid,
                hashedPublicKey: public_id.clone(),
            };
            let response_json = format!("{}\n", serde_json::to_string(&response).unwrap());
            let _ = socket.write_all(response_json.as_bytes()).await;
            if is_valid {
                println!("Connection verified. Broadcasting...");
                broadcast_conn(&input.data).await;
            }
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let connections: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new())); 
    let listener = TcpListener::bind("0.0.0.0:8081").await?;
    println!("Listening on port 8081...");

    loop {
        let (mut socket, addr) = listener.accept().await?;
        println!("Connection from: {}", addr);
        let request_hashes = REQUEST_HASHES.clone();
        let connections = connections.clone();

        tokio::spawn(async move {
            let mut buffer = Vec::new();

            loop {
                let mut chunk = vec![0; 1024];
                match socket.read(&mut chunk).await {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        buffer.extend_from_slice(&chunk[..n]);

                        if let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                            let received = String::from_utf8_lossy(&buffer[..pos]).trim().to_string();
                            buffer.drain(..=pos);
                            
                            // Try to deserialize the message
                            match serde_json::from_str::< Input>(&received) {
                                Ok(input) => {
                                    match input.data.ip.as_str() {
                                        "192.168.1.70" => {
                                            handle_connect(received, &mut socket, request_hashes.clone(), connections.clone(), addr).await;
                                        }
                                        _ => {
                                            println!("Received request from an unrecognized IP: {}", input.data.ip);
                                            // Optionally, send an error response to the client
                                        }
                                    }
                                }
                                Err(e) => {
                                    println!("Failed to parse JSON: {:?}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        println!("Error reading from client: {:?}", e);
                        break;
                    }
                }
            }
        });
    }
}
