use pqc_dilithium::verify;
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
use std::time::Duration;
use tokio::sync::RwLock;
use hex;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppendCypherText {
    data: CypherData,
    signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CypherData {
    r#type: String,
    dst: String,
    ct: String,
    kpk: String,
    publicKey: String,
    ts: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppendKyberKey {
    data: KyberData,
    signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KyberData {
    r#type: String,
    dst: String,
    kpk: String,
    publicKey: String,
    ts: String,
}

#[derive(Serialize, Deserialize)]
struct ForwardMessage {
    data: MessageData,
    signature: String,
}
#[derive(Serialize, Deserialize)]
struct MessageData {
    r#type: String,
    dst: String,
    msg: String,
    publicKey: String,
    ts: String,
}

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
    diff <= 10 || (ts > now && (ts - now) <= 2)
}

fn verify_signature(signature: &str, public_key: &str, data: &str) -> bool {
    let pub_key = hex::decode(public_key).ok();
    let sig = hex::decode(signature).ok();
    
    pub_key.zip(sig).map_or(false, |(pk, s)| {
        verify(&s, data.as_bytes(), &pk).is_ok()
    })
}

async fn broadcast_conn(input: &Input) {
    let nodes = match read_nodes_from_json("nodes.json") {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Failed to read nodes.json: {}", e);
            return;
        }
    };
    println!("Broadcasting to nodes: {:?}", nodes);
    let message = serde_json::to_string(&input).unwrap();
    let message_with_newline = format!("{}\n", message);
    let input_ip = input.data.ip.clone();

    let mut tasks = Vec::new();

    for node_ip in nodes {
        if node_ip == input_ip {
            continue; // Skip self
        }

        let msg = message_with_newline.clone();
        tasks.push(tokio::spawn(async move {
            match send_tcp_message(&node_ip, &msg).await {
                Ok(_) => println!("Successfully broadcasted to {}", node_ip),
                Err(e) => eprintln!("Failed to send to {}: {}", node_ip, e),
            }
        }));
    }

    for task in tasks {
        let _ = task.await;
    }
}


fn read_nodes_from_json(file_path: &str) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let content = fs::read_to_string(file_path)?;
    let json: Value = serde_json::from_str(&content)?;
    
    let nodes = json.as_array()
        .ok_or_else(|| "Expected JSON array".to_string())? 
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    Ok(nodes)
}

async fn send_tcp_message(ip: &str, message: &str) -> Result<(), Box<dyn Error>> {
    for attempt in 1..=3 {
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(ip)).await {
            Ok(Ok(mut stream)) => {
                stream.write_all(format!("{}\n", message).as_bytes()).await?;
                stream.flush().await?;
                return Ok(());
            }
            Ok(Err(e)) => eprintln!("[Attempt {}] Failed to connect to {}: {}", attempt, ip, e),
            Err(_) => eprintln!("[Attempt {}] Connection to {} timed out", attempt, ip),
        }
        tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
    }
    Err(format!("Failed to send message to {} after 3 attempts", ip).into())
}


lazy_static::lazy_static! {
    static ref REQUEST_HASHES: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
}
lazy_static::lazy_static! {
    static ref CONNECTIONS: Arc<RwLock<HashMap<String, Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>>>> = 
        Arc::new(RwLock::new(HashMap::new()));
}

fn sha256_hash(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

async fn handle_connect(
    received: String,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    request_hashes: Arc<Mutex<HashSet<String>>>,
) {
    if let Ok(input) = serde_json::from_str::<Input>(&received) {
        if !check_ts_validity(&input.data.ts) {
            let response = Output { valid: false, hashedPublicKey: String::new() };
            let mut stream = writer.lock().await;
            let _ = stream.write_all(format!("{}\n", serde_json::to_string(&response).unwrap()).as_bytes()).await;
            return;
        }
        println!("In connect");
        let decoded_public_key = match hex::decode(&input.data.publicKey) {
            Ok(pk) => pk,
            Err(_) => {
                eprintln!("Invalid hex string for public key");
                return;
            }
        };
        let public_id = sha256_hash(&decoded_public_key);
        
        let unique_request_hash = sha256_hash(
            &[input.data.publicKey.as_bytes(), input.data.ts.as_bytes()].concat()
        );

        {
            let mut hashes = request_hashes.lock().await;
            if hashes.contains(&unique_request_hash) {
                drop(hashes);
                println!("Duplicate request detected");
                let response = Output { valid: false, hashedPublicKey: public_id.clone() };
                let mut stream = writer.lock().await;
                let _ = stream.write_all(format!("{}\n", serde_json::to_string(&response).unwrap()).as_bytes()).await;
                return;
            }
            hashes.insert(unique_request_hash);
        }

        let input_data_str = serde_json::to_string(&input.data).unwrap();
        let is_valid = verify_signature(&input.signature, &input.data.publicKey, &input_data_str);
        {
            let mut conn_map = CONNECTIONS.write().await;
            conn_map.insert(public_id.clone(), Arc::clone(&writer));
        }

        {
            let response = Output { valid: is_valid, hashedPublicKey: public_id.clone() };
            let mut stream = writer.lock().await;
            let _ = stream.write_all(format!("{}\n", serde_json::to_string(&response).unwrap()).as_bytes()).await;
        }
        if is_valid {
            broadcast_conn(&input).await;

        } else {
            println!("Destination not found in active connections, broadcasting...");
                
        }
    }
}


async fn forward(
    received: String,
    nodes_conns: Arc<Mutex<HashMap<String, String>>>,
) {
    if let Ok(input) = serde_json::from_str::<AppendKyberKey>(&received) {
        let input_data_str = serde_json::to_string(&input.data).unwrap();
        
        if !verify_signature(&input.signature, &input.data.publicKey, &input_data_str) {
            println!("[ERROR] Invalid signature, dropping message.");
            return;
        }

        println!("Signature verified, proceeding with forwarding.");
        
        let connection = {
            let connections = CONNECTIONS.read().await;
            println!("{:?}", connections);
            connections.get(&input.data.dst).cloned()
        };

        if let Some(stream) = connection {
            let mut locked_writer = stream.lock().await;
            if let Err(e) = locked_writer.write_all(format!("{}\n", received).as_bytes()).await {
                println!("[ERROR] Failed to write to socket: {}", e);
            } else {
                println!("Message successfully sent to {}", input.data.dst);
            }
        } else {
            let nodes_map = nodes_conns.lock().await;
            println!("Current nodes_conns: {:?}", *nodes_map);

            if let Some(node_ip) = nodes_map.get(&input.data.dst) {
                println!("Forwarding to node IP: {}", node_ip);
                
                if let Err(e) = send_tcp_message(node_ip, &received).await {
                    eprintln!("Failed to send to {}: {}", node_ip, e);
                } else {
                    println!("Successfully forwarded to {}", node_ip);
                }
            } else {
                println!("Destination {} not found in connections or known nodes.", input.data.dst);
            }
        }
    }
    else if let Ok(input) = serde_json::from_str::<AppendCypherText>(&received) {
        let input_data_str = serde_json::to_string(&input.data).unwrap();
        
        if !verify_signature(&input.signature, &input.data.publicKey, &input_data_str) {
            println!("[ERROR] Invalid signature, dropping message.");
            return;
        }

        println!("Signature verified, proceeding with forwarding.");
        
        let connection = {
            let connections = CONNECTIONS.read().await;
            println!("{:?}", connections);
            connections.get(&input.data.dst).cloned()
        };

        if let Some(stream) = connection {
            let mut locked_writer = stream.lock().await;
            if let Err(e) = locked_writer.write_all(format!("{}\n", received).as_bytes()).await {
                println!("[ERROR] Failed to write to socket: {}", e);
            } else {
                println!("Message successfully sent to {}", input.data.dst);
            }
        } else {
            let nodes_map = nodes_conns.lock().await;
            println!("Current nodes_conns: {:?}", *nodes_map);

            if let Some(node_ip) = nodes_map.get(&input.data.dst) {
                println!("Forwarding to node IP: {}", node_ip);
                
                if let Err(e) = send_tcp_message(node_ip, &received).await {
                    eprintln!("Failed to send to {}: {}", node_ip, e);
                } else {
                    println!("Successfully forwarded to {}", node_ip);
                }
            } else {
                println!("Destination {} not found in connections or known nodes.", input.data.dst);
            }
        }
    }
    else if let Ok(input) = serde_json::from_str::<ForwardMessage>(&received) {
        let input_data_str = serde_json::to_string(&input.data).unwrap();
        
        if !verify_signature(&input.signature, &input.data.publicKey, &input_data_str) {
            println!("[ERROR] Invalid signature, dropping message.");
            return;
        }

        println!("Signature verified, proceeding with forwarding.");
        
        let connection = {
            let connections = CONNECTIONS.read().await;
            println!("{:?}", connections);
            connections.get(&input.data.dst).cloned()
        };

        if let Some(stream) = connection {
            let mut locked_writer = stream.lock().await;
            if let Err(e) = locked_writer.write_all(format!("{}\n", received).as_bytes()).await {
                println!("[ERROR] Failed to write to socket: {}", e);
            } else {
                println!("Message successfully sent to {}", input.data.dst);
            }
        } else {
            let nodes_map = nodes_conns.lock().await;
            println!("Current nodes_conns: {:?}", *nodes_map);

            if let Some(node_ip) = nodes_map.get(&input.data.dst) {
                println!("Forwarding to node IP: {}", node_ip);
                
                if let Err(e) = send_tcp_message( node_ip, &received).await {
                    eprintln!("Failed to send to {}: {}", node_ip, e);
                } else {
                    println!("Successfully forwarded to {}", node_ip);
                }
            } else {
                println!("Destination {} not found in connections or known nodes.", input.data.dst);
            }
        }
    }
}


async fn handle_broadcast(received: String, nodes_conns: Arc<Mutex<HashMap<String, String>>>) {
    if let Ok(input) = serde_json::from_str::<Input>(&received) {
        let decoded_public_key = match hex::decode(&input.data.publicKey) {
            Ok(pk) => pk,
            Err(_) => {
                eprintln!("Invalid public key format");
                return;
            }
        };
        let public_id = sha256_hash(&decoded_public_key);
        let input_data_str = serde_json::to_string(&input.data).unwrap();
        let is_valid = verify_signature(&input.signature, &input.data.publicKey, &input_data_str);

        if is_valid {
            let mut nodes_map = nodes_conns.lock().await;
            nodes_map.insert(public_id.clone(), input.data.ip.clone());
            println!("Updated nodes_conns: {:?}", *nodes_map);
        } else {
            eprintln!("Invalid signature for public ID: {}", public_id);
        }
    } else {
        eprintln!("Failed to parse received data as Input. ");
    }
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
                    Ok(0) => break,  // No data, break the loop
                    Ok(n) => {
                        buffer.extend_from_slice(&chunk[..n]);
                        if let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                            let received = String::from_utf8_lossy(&buffer[..pos]).trim().to_string();
                            buffer.drain(..=pos);

                            if let Ok(input) = serde_json::from_str::<Input>(&received) {
                                if input.data.ip == "192.168.1.51:8081" {
                                    println!("Received connect");
                                    handle_connect(received, Arc::clone(&writer), request_hashes.clone()).await;

                                } else {
                                    println!("Received Broadcast");
                                    handle_broadcast(received, Arc::clone(&nodes_conns_clone)).await;
                                }
                            }
                            else if let Ok(_input) = serde_json::from_str::<AppendKyberKey>(&received) {
                                println!("Forwarding KyberKey");
                                forward(received, Arc::clone(&nodes_conns_clone)).await;
                            }
                            else if let Ok(_input) = serde_json::from_str::<AppendCypherText>(&received) {
                                println!("Forwarding CypherText");
                                forward(received, Arc::clone(&nodes_conns_clone)).await;
                            }
                            else if let Ok(_input) = serde_json::from_str::<ForwardMessage>(&received) {
                                println!("Forwarding Message");
                                forward(received, Arc::clone(&nodes_conns_clone)).await;
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
