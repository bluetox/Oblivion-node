use super::json_structs;
use super::crypto;
use super::utils;
use super::super::CONNECTIONS;
use tokio::{
    io::AsyncWriteExt,
    sync::Mutex,
};
use std::{
    collections::{HashMap, HashSet}, 
    sync::Arc,
};
use hex;

pub async fn handle_broadcast(received: String, nodes_conns: Arc<Mutex<HashMap<String, String>>>) {
    if let Ok(input) = serde_json::from_str::<json_structs::Input>(&received) {
        let decoded_public_key = match hex::decode(&input.data.publicKey) {
            Ok(pk) => pk,
            Err(_) => {
                eprintln!("Invalid public key format");
                return;
            }
        };
        let public_id = crypto::sha256_hash(&decoded_public_key);
        let input_data_str = serde_json::to_string(&input.data).unwrap();
        let is_valid = crypto::verify_signature(&input.signature, &input.data.publicKey, &input_data_str);

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

pub async fn forward(
    received: String,
    nodes_conns: Arc<Mutex<HashMap<String, String>>>,
) {
    if let Ok(input) = serde_json::from_str::<json_structs::AppendKyberKey>(&received) {
        let input_data_str = serde_json::to_string(&input.data).unwrap();
        
        if !crypto::verify_signature(&input.signature, &input.data.publicKey, &input_data_str) {
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
                
                if let Err(e) = utils::send_tcp_message(node_ip, &received).await {
                    eprintln!("Failed to send to {}: {}", node_ip, e);
                } else {
                    println!("Successfully forwarded to {}", node_ip);
                }
            } else {
                println!("Destination {} not found in connections or known nodes.", input.data.dst);
            }
        }
    }
    else if let Ok(input) = serde_json::from_str::<json_structs::AppendCypherText>(&received) {
        let input_data_str = serde_json::to_string(&input.data).unwrap();
        
        if !crypto::verify_signature(&input.signature, &input.data.publicKey, &input_data_str) {
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
                
                if let Err(e) = utils::send_tcp_message(node_ip, &received).await {
                    eprintln!("Failed to send to {}: {}", node_ip, e);
                } else {
                    println!("Successfully forwarded to {}", node_ip);
                }
            } else {
                println!("Destination {} not found in connections or known nodes.", input.data.dst);
            }
        }
    }
    else if let Ok(input) = serde_json::from_str::<json_structs::ForwardMessage>(&received) {
        let input_data_str = serde_json::to_string(&input.data).unwrap();
        
        if !crypto::verify_signature(&input.signature, &input.data.publicKey, &input_data_str) {
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
                
                if let Err(e) = utils::send_tcp_message( node_ip, &received).await {
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

pub async fn handle_connect(
    received: String,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    request_hashes: Arc<Mutex<HashSet<String>>>,
) {
    if let Ok(input) = serde_json::from_str::<json_structs::Input>(&received) {
        if !utils::check_ts_validity(&input.data.ts) {
            let response = json_structs::Output { valid: false, hashedPublicKey: String::new() };
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
        let public_id = crypto::sha256_hash(&decoded_public_key);
        
        let unique_request_hash = crypto::sha256_hash(
            &[input.data.publicKey.as_bytes(), input.data.ts.as_bytes()].concat()
        );

        {
            let mut hashes = request_hashes.lock().await;
            if hashes.contains(&unique_request_hash) {
                drop(hashes);
                println!("Duplicate request detected");
                let response = json_structs::Output { valid: false, hashedPublicKey: public_id.clone() };
                let mut stream = writer.lock().await;
                let _ = stream.write_all(format!("{}\n", serde_json::to_string(&response).unwrap()).as_bytes()).await;
                return;
            }
            hashes.insert(unique_request_hash);
        }

        let input_data_str = serde_json::to_string(&input.data).unwrap();
        let is_valid = crypto::verify_signature(&input.signature, &input.data.publicKey, &input_data_str);
        {
            let mut conn_map = CONNECTIONS.write().await;
            conn_map.insert(public_id.clone(), Arc::clone(&writer));
        }

        {
            let response = json_structs::Output { valid: is_valid, hashedPublicKey: public_id.clone() };
            let mut stream = writer.lock().await;
            let _ = stream.write_all(format!("{}\n", serde_json::to_string(&response).unwrap()).as_bytes()).await;
        }
        if is_valid {
            utils::broadcast_conn(&input).await;

        } else {
            println!("Destination not found in active connections, broadcasting...");
                
        }
    }
}