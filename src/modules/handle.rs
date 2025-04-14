use crate::modules::utils::save_packet;

use super::crypto;
use super::utils;
use super::super::CONNECTIONS;
use super::utils::check_ts_validity;
use tokio::{
    io::AsyncWriteExt,
    sync::Mutex,
};

use std::sync::Arc;
use bytes::BytesMut;
use hex;
use pqc_dilithium::verify;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

pub async fn forward(
    encrypted_packet: &BytesMut,
    shared_secret: &[u8]
) {
    println!("received forward");
    let mut decypted_packet : Vec<u8>;
    if (encrypted_packet[3] & (1 << 7)) != 0 {
        decypted_packet = encrypted_packet.to_vec();
    }
    else {
        decypted_packet = super::utils::decrypt_packet(encrypted_packet, shared_secret).await.unwrap().to_vec();
    }
    
    let payload_size_bytes = &decypted_packet[1..3];
    let payload_size = u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;

    let dilithium_signature = &decypted_packet[5 .. 5 + 3293];
    let ed25519_signature = &decypted_packet[5 + 3293 .. 5 + 3293 + 64];

    let dilithium_public_key_bytes = &decypted_packet[5 + 3293 + 64 .. 5 + 3293 + 64 + 1952];
    let ed25519_public_key = &decypted_packet[5 + 3293 + 64 + 1952 .. 5 + 3293 + 64 + 1952 + 32];

    let user_id_bytes = &decypted_packet[5 + 3293 + 64 + 1952 + 32 .. 5 + 3293 + 64 + 1952 + 32 + 32];
    let user_id_hex = hex::encode(user_id_bytes);

    let timestamp_bytes = &decypted_packet[5 + 3293 + 64 + 1952 + 32 + 32 + 16 .. 5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8];
    let timestamp = utils::uint8_array_to_ts(&timestamp_bytes);

    let data_to_sign_bytes = &decypted_packet[5 + 3293 + 64 ..payload_size];

    if !check_ts_validity(timestamp) {
        println!("[ERROR] Timestamp invalid, dropping message");
    }

    if !verify(&dilithium_signature, &data_to_sign_bytes, &dilithium_public_key_bytes).is_ok() {
        println!("[ERROR] Invalid signature, dropping message.");
        return;
    }
    
    let ed_public_key_array: &[u8; 32] = ed25519_public_key
        .try_into()
        .expect("Public key must be exactly 32 bytes");

    let ed_signature_array: &[u8; 64] = ed25519_signature
        .try_into()
        .expect("Signature must be exactly 64 bytes");

    match VerifyingKey::from_bytes(ed_public_key_array) {
        Ok(public_key) => {
            let signature = Signature::from_bytes(ed_signature_array);
            match public_key.verify(data_to_sign_bytes, &signature) {
                Ok(_) => println!("✅ Ed25519 Signature is valid!"),
                Err(_) => return,
            }
        },
        Err(_) => return,
    }
    let connection = {
        let connections = CONNECTIONS.read().await;
        println!("{:?}", &connections);
        connections.get(&user_id_hex).cloned()
    };
    if let Some(stream) = connection {
        let mut locked_writer = stream.lock().await;
        if let Err(e) = locked_writer.write_all(&decypted_packet).await {
            println!("[ERROR] Failed to write to socket: {}", e);
        } else {
            println!("Message successfully sent to {}", user_id_hex);
        }
    }
    else {
        println!("No connection for {}", user_id_hex);
        for raw_ip in super::node_assign::find_closest_hashes(&hex::decode(&user_id_hex).unwrap(), 4).await {
            let ip: std::net::IpAddr = raw_ip.parse().expect("Invalid IP address");
            if raw_ip == super::super::PUBLIC_IP.lock().unwrap().to_string() {
                save_packet(user_id_hex.clone(), decypted_packet.to_vec()).await;
            }
            decypted_packet[3] |= 1 << 7;
            match utils::send_tcp_message(&ip, &decypted_packet).await {
                Ok(()) => {
                    println!("node is online");
                    break;
                }
                Err(_) => {
                    println!("node is offline")
                },
            }
        }
    }
}

pub async fn handle_connect(
    encrypted_packet: &BytesMut,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    user_id:  &mut String,
    shared_secret: &[u8]
) {
    let decypted_packet=  super::utils::decrypt_packet(encrypted_packet, shared_secret).await.unwrap();
    let dilithium_signature = &decypted_packet[5 .. 5 + 3293];
    let ed25519_signature = &decypted_packet[5 + 3293 .. 5 + 3293 + 64];

    let dilithium_public_key_bytes = &decypted_packet[5 + 3293 + 64 .. 5 + 3293 + 64 + 1952];
    let ed25519_public_key = &decypted_packet[5 + 3293 + 64 + 1952 .. 5 + 3293 + 64 + 1952 + 32];
    let nonce = &decypted_packet[5 + 3293 + 64 + 1952 + 32 .. 5 + 3293 + 64 + 1952 + 32 + 16];

    let data_to_sign_bytes = &decypted_packet[5 + 3293 + 64 ..];
    
    let timestamp_bytes = &decypted_packet[5 + 3293 + 64 + 1952 + 32 + 16 .. 5 + 3293 + 64 + 1952 + 32 + 16 + 8];
    let timestamp = utils::uint8_array_to_ts(&timestamp_bytes);

    let ed_public_key_array: &[u8; 32] = ed25519_public_key
        .try_into()
        .expect("Public key must be exactly 32 bytes");

    let ed_signature_array: &[u8; 64] = ed25519_signature
        .try_into()
        .expect("Signature must be exactly 64 bytes");

    match VerifyingKey::from_bytes(ed_public_key_array) {
        Ok(public_key) => {
            let signature = Signature::from_bytes(ed_signature_array);
            match public_key.verify(data_to_sign_bytes, &signature) {
                Ok(_) => println!("✅ Ed25519 Signature is valid!"),
                Err(_) => return,
            }
        },
        Err(_) => return,
    }
    let result = verify(dilithium_signature, data_to_sign_bytes, dilithium_public_key_bytes).is_ok();
    if !result {
        return;
    }
    if !utils::check_ts_validity(timestamp) {
        return;
    }
    let full_hash_input = [
        &dilithium_public_key_bytes[..],
        &ed25519_public_key[..],         
        &nonce[..],                      
    ].concat();

    let public_id = crypto::sha256_hash(&full_hash_input);

    user_id.push_str(&public_id);
    {
        let mut conn_map = CONNECTIONS.write().await;
        conn_map.insert(public_id.clone(), Arc::clone(&writer));
    }
    {
        let user_packets = utils::get_packets_for_user(&public_id).await;
        match user_packets {
            Some(packets) => {
                let mut locked_writer = writer.lock().await;

                for packet in packets {
                    let _ = locked_writer.write_all(&packet).await;
                }
    
                println!("All packets for user {} have been processed.", public_id);
                utils::delete_packets_for_user(&public_id).await;
            }
            None => {
                println!("No packets found for user {}", public_id);
            }
        }
    }
    println!("Connexion request properly formated");
}

pub async fn handle_node_assignement(
    buffer: &BytesMut,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>
) {
    let payload_size_bytes = &buffer[1..3];
    let payload_size = u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;
    let dilithium_signature = &buffer[5 .. 5 + 3293];
    let ed25519_signature = &buffer[5 + 3293 .. 5 + 3293 + 64];

    let dilithium_public_key_bytes = &buffer[5 + 3293 + 64 .. 5 + 3293 + 64 + 1952];
    let ed25519_public_key = &buffer[5 + 3293 + 64 + 1952 .. 5 + 3293 + 64 + 1952 + 32];
    let nonce = &buffer[5 + 3293 + 64 + 1952 + 32 .. 5 + 3293 + 64 + 1952 + 32 + 16];

    let data_to_sign_bytes = &buffer[5 + 3293 + 64 .. payload_size];
    
    let timestamp_bytes = &buffer[5 + 3293 + 64 + 1952 + 32 + 16 .. 5 + 3293 + 64 + 1952 + 32 + 16 + 8];
    let timestamp = utils::uint8_array_to_ts(&timestamp_bytes);

    let ed_public_key_array: &[u8; 32] = ed25519_public_key
        .try_into()
        .expect("Public key must be exactly 32 bytes");

    let ed_signature_array: &[u8; 64] = ed25519_signature
        .try_into()
        .expect("Signature must be exactly 64 bytes");

    match VerifyingKey::from_bytes(ed_public_key_array) {
        Ok(public_key) => {
            let signature = Signature::from_bytes(ed_signature_array);
            match public_key.verify(data_to_sign_bytes, &signature) {
                Ok(_) => println!("✅ Ed25519 Signature is valid!"),
                Err(_) => return,
            }
        },
        Err(_) => return,
    }
    let result = verify(dilithium_signature, data_to_sign_bytes, dilithium_public_key_bytes).is_ok();
    if !result {
        return;
    }
    if !utils::check_ts_validity(timestamp) {
        return;
    }
    let full_hash_input = [
        &dilithium_public_key_bytes[..],
        &ed25519_public_key[..],         
        &nonce[..],                      
    ].concat();

    let public_id = crypto::sha256_hash(&full_hash_input);
    let start_time = std::time::Instant::now();
    let closest_nodes = super::node_assign::find_closest_hashes(&hex::decode(public_id).unwrap(), 4).await;
    let duration = start_time.elapsed();
    println!("Time taken to find closest hashes: {} seconds and {} nanoseconds", 
             duration.as_secs(), duration.subsec_nanos());

    let mut buffer = BytesMut::with_capacity(1024);
    for ip in closest_nodes {
        buffer.extend_from_slice(ip.as_bytes());
        println!("ip: {}", ip);
        buffer.extend_from_slice(" ".as_bytes());
    }
    let mut locked_writer = writer.lock().await;
    locked_writer.write_all(&buffer).await.expect("Write failed");
    
    
}