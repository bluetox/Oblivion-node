use modules::handle;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener, sync::Mutex
};
use std::io::{Write, Read};
use std::net::TcpStream;
use std::{
    collections::{HashMap, HashSet}, 
    sync::Arc,
};
use tokio::sync::RwLock;
use bytes::{buf, Buf, BytesMut};
use std::fs::OpenOptions;

mod modules;

lazy_static::lazy_static! {
    pub static ref DELAYED_DELIVERY: Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>> = Arc::new(Mutex::new(HashMap::new()));
}

lazy_static::lazy_static! {
    pub static ref REQUEST_HASHES: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
}

lazy_static::lazy_static! {
    pub static ref CONNECTIONS: Arc<RwLock<HashMap<String, Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>>>> = Arc::new(RwLock::new(HashMap::new()));
}

lazy_static::lazy_static! {
    pub static ref NODES_HASHMAP: Arc<Mutex<Vec<modules::node_assign::IpHash>>> = Arc::new(Mutex::new(Vec::new()));
}

lazy_static::lazy_static! {
    pub static ref PUBLIC_IP: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
}

async fn get_pub_ip() -> String {
    const SERVER_ADDR: &str = "ipv4.icanhazip.com:80";
    let mut stream = TcpStream::connect(SERVER_ADDR).unwrap();

    let request = b"GET / HTTP/1.1\r\nHost: ipv4.icanhazip.com\r\nConnection: close\r\n\r\n";
    stream.write_all(request).unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();

    if let Ok(response_str) = String::from_utf8(response) {

        if let Some(ip) = response_str.split("\r\n\r\n").nth(1) {
            let ip = ip.trim();
            println!("Your public IP address is: {}", ip);
            *PUBLIC_IP.lock().unwrap() = ip.to_string();
            return ip.to_string();
        } else {
            eprintln!("Failed to extract IP address from response.");
        }
    }

    String::new()
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let _ = get_pub_ip().await;

    let file = OpenOptions::new()
    .read(true)
    .write(true)
    .create(true)
    .open("sorted_hashes.txt")?;

    let conn = rusqlite::Connection::open("node.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS secrets (
            ip TEXT NOT NULL,
            shared_secret BLOB NOT NULL
        )",
        [],
    ).unwrap();
    modules::node_assign::read_and_sort_hashes_from_file(&file).await.unwrap();
    let listener = match TcpListener::bind("0.0.0.0:32775").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to port: {}", e);
            return Err(e);
        }
    };
    loop {
        let (socket, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
                continue;
            }
        };

        tokio::spawn(handle_client(socket));
    }
}
/*
async fn handle_client(
    socket: tokio::net::TcpStream, 
) {
    let mut buffer = BytesMut::with_capacity(1024);
    let (mut read_half, write_half) = socket.into_split();
    let writer = Arc::new(Mutex::new(write_half));
    let mut user_id = String::new();
    let mut shared_secret: [u8; 32] = [0; 32];
    
    loop {
        match read_half.read_buf(&mut buffer).await {
            Ok(0) => {
                if user_id.len() > 0 {
                    let mut connections = CONNECTIONS.write().await;
                    if let Some(existing_arc) = connections.get(&user_id) {
                        if Arc::ptr_eq(existing_arc, &writer) {
                            println!("Connection closed by client: {}", user_id);
                            connections.remove(&user_id);
                            println!("{:?}", connections);
                        }
                    }
                break;
                }

                println!("a connection was cleanely aborted");
                break
            },

            Ok(n) => {
                if n < 3 {
                    println!("[ERROR] Invalid packet: too short");
                    buffer.clear();
                    continue;
                }

                let prefix = &buffer[0..3];
                let payload_size = if prefix[0] == 0xF0 {
                    let payload_size_bytes = &buffer[1..5];
                    u32::from_le_bytes([
                        payload_size_bytes[0],
                        payload_size_bytes[1],
                        payload_size_bytes[2],
                        payload_size_bytes[3],
                    ]) as usize
                } else {
                    let payload_size_bytes = &buffer[1..3];
                    u16::from_le_bytes([
                        payload_size_bytes[0],
                        payload_size_bytes[1],
                    ]) as usize
                };

                if buffer.len() < payload_size{
                    println!("payload size expected: {}", payload_size);
                    continue;
                }

                let unique_request_hash = modules::crypto::sha256_hash(&buffer);
                {
                    let mut hashes = REQUEST_HASHES.lock().await;
                    if hashes.contains(&unique_request_hash) {
                        buffer.advance(payload_size);
                        continue;
                    }
                    hashes.insert(unique_request_hash);
                }
                match prefix[0] {
                    0 => {
                        let public_kk = &buffer[5 .. 5 + 1568];
                        let mut enc_rng =   rand::rngs::OsRng;
                        let (ct,ss) = safe_pqc_kyber::encapsulate(public_kk, &mut enc_rng, None).unwrap();
                        {
                            shared_secret = ss;
                            println!("shared secret: {:?}", shared_secret);
                            let mut message = BytesMut::with_capacity(1573);
                            message.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
                            message.extend_from_slice(&ct);
                            let mut locked_writer = writer.lock().await;
                            locked_writer.write_all(&message).await.unwrap();
                        }
                    },
                    1 => modules::handle::handle_connect(&buffer[..payload_size], writer.clone(), &mut user_id, &shared_secret.to_vec()).await,
                    2..=4 => modules::handle::forward(&buffer[..payload_size], &shared_secret.to_vec()).await,
                    10 => {
                        modules::handle::handle_node_assignement(&buffer[..payload_size], writer.clone()).await},
                    0xF0 => {            
                        let dst_user_id_bytes = &buffer[5 .. 5 + 32];
                        let user_id = hex::encode(dst_user_id_bytes);
                        println!("received call frame: {}", user_id);           

                        let connection = {
                            let connections = CONNECTIONS.read().await;
                            println!("{:?}", &connections);
                            connections.get(&user_id).cloned()
                        };
                        let failed = if let Some(stream) = connection {
                            let mut locked_writer = stream.lock().await;
                            if let Err(e) = locked_writer.write_all(&buffer[..payload_size]).await {
                                println!("[ERROR] Failed to write to socket: {}", e);
                                true
                            } else {
                                println!("Message successfully sent to {}", user_id);
                                false
                            }
                        } else {
                            println!("No connection for {}", user_id);
                            true
                        };
                        if failed {
                            for raw_ip in modules::node_assign::find_closest_hashes(&hex::decode(&user_id).unwrap(), 4).await {
                                let ip: std::net::IpAddr = raw_ip.parse().expect("Invalid IP address");
                                if raw_ip != PUBLIC_IP.lock().unwrap().to_string() && raw_ip != "127.0.0.1" {
                                match modules::utils::send_tcp_message(&ip, &buffer[..payload_size]).await {
                                    Ok(()) => {
                                        println!("node is online");
                                        break;
                                    }
                                    Err(_) => {
                                        println!("node is offline")
                                    },
                                }
                            }
                            break;
                            }
                        }
                    },
                    0xC0..=0xCF => modules::handle::forward(&buffer[..payload_size], &shared_secret.to_vec()).await,
                    _ => {}
                }
                buffer.advance(payload_size);
                println!("Advanced buffer length: {}", buffer.len());
            }
            Err(e) => {
                println!("[ERROR] Failed to read from socket: {}", e);
                if user_id.len() > 0 {
                    let mut connections = CONNECTIONS.write().await;
                    connections.remove(&user_id);
                    println!("{:?}", connections)
                }
                break;
            }
        }
    }
}
*/
async fn handle_client(socket: tokio::net::TcpStream) {
    let mut buffer = BytesMut::with_capacity(1024);
    let (mut read_half, write_half) = socket.into_split();
    let writer = Arc::new(Mutex::new(write_half));
    let mut user_id = String::new();
    let mut shared_secret: [u8; 32] = [0; 32];
    let mut video_call_socket: Option<TcpStream> = None;

    loop {
        match read_half.read_buf(&mut buffer).await {
            Ok(0) => {
                if user_id.len() > 0 {
                    let mut connections = CONNECTIONS.write().await;
                    if let Some(existing_arc) = connections.get(&user_id) {
                        if Arc::ptr_eq(existing_arc, &writer) {
                            println!("Connection closed by client: {}", user_id);
                            connections.remove(&user_id);
                            println!("{:?}", connections);
                        }
                    }
                break;
                }

                println!("a connection was cleanely aborted");
                break
            },
            Ok(_n) => {
                loop {
                    if buffer.len() < 3 {
                        break;
                    }

                    let prefix = &buffer[0..3];
                    let payload_size = if prefix[0] == 0xF0 {
                        let sz = u32::from_le_bytes(buffer[1..5].try_into().unwrap()) as usize;
                        sz
                    } else {
                        let sz = u16::from_le_bytes(buffer[1..3].try_into().unwrap()) as usize;
                        sz
                    };

                    if buffer.len() < payload_size {
                        break;
                    }

                    let packet = buffer.split_to(payload_size);

                    /*
                    let unique_request_hash = modules::crypto::sha256_hash(&packet);
                    {
                        let mut hashes = REQUEST_HASHES.lock().await;
                        if hashes.contains(&unique_request_hash) {
                            // déjà vu → on ignore
                            continue;
                        }
                        hashes.insert(unique_request_hash);
                    }
                    */
                    // switch sur packet[0]
                    match packet[0] {
                        0 => {
                            let public_kk = &packet[5 .. 5 + 1568];
                            let mut enc_rng =   rand::rngs::OsRng;
                            let (ct,ss) = safe_pqc_kyber::encapsulate(public_kk, &mut enc_rng, None).unwrap();
                            {
                                shared_secret = ss;
                                println!("shared secret: {:?}", shared_secret);
                                let mut message = BytesMut::with_capacity(1573);
                                message.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
                                message.extend_from_slice(&ct);
                                let mut locked_writer = writer.lock().await;
                                locked_writer.write_all(&message).await.unwrap();
                            }
                        },
                        1 => {
                            modules::handle::handle_connect(
                                &packet[..], writer.clone(), &mut user_id, &shared_secret.to_vec()
                            ).await
                        }
                        2..=4 | 0xC0..=0xCF => {
                            modules::handle::forward(&packet[..], &shared_secret.to_vec()).await
                        }
                        10 => {
                            modules::handle::handle_node_assignement(&packet[..], writer.clone()).await
                        }
                        
                        0xF0 => {
                            let dst_user_id_bytes = &packet[5..5+32];
                            let call_user = hex::encode(dst_user_id_bytes);

                            let failed = if let Some(stream) = {
                                let conns = CONNECTIONS.read().await;
                                conns.get(&call_user).cloned()
                            } {
                                let mut w = stream.lock().await;
                                w.write_all(&packet[..]).await.is_err()
                            } else {
                                true
                            };

                            if failed {
                                for raw_ip in modules::node_assign::find_closest_hashes(
                                        &hex::decode(&call_user).unwrap(), 4
                                    ).await
                                {
                                    if raw_ip != PUBLIC_IP.lock().unwrap().to_string()
                                        && raw_ip != "127.0.0.1"
                                    {

                                        let ip: std::net::IpAddr = raw_ip.parse().unwrap();
                                        match &mut video_call_socket {
                                            Some(socket) => {
                                                if socket.write_all(&packet).is_ok() {
                                                    println!("Sent packet to existing video call socket: {}", ip);
                                                    break;
                                                } else {
                                                    println!("Failed writing to existing socket. Dropping it.");
                                                }
                                            }
                                            None => {
                                                match TcpStream::connect((ip, 32775)) {
                                                    Ok(mut stream) => {
                                                        println!("Connection established with node: {}", ip);
                                                        if stream.write_all(&packet).is_ok() {
                                                            video_call_socket = Some(stream);
                                                            break;
                                                        } else {
                                                            println!("Failed to write after connecting to {}", ip);
                                                        }
                                                    }
                                                    Err(err) => {
                                                        println!("Failed to connect to {}: {}", ip, err);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to read from socket: {}", e);
                break;
            }
        }
    }
}