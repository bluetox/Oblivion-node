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
    packet: &[u8],
) -> Result<(), String>{
    let dilithium_signature = &packet[5 .. 5 + 3293];
    let ed25519_signature = &packet[5 + 3293 .. 5 + 3293 + 64];

    let dilithium_public_key_bytes = &packet[5 + 3293 + 64 .. 5 + 3293 + 64 + 1952];
    let ed25519_public_key = &packet[5 + 3293 + 64 + 1952 .. 5 + 3293 + 64 + 1952 + 32];

    let user_id_bytes = &packet[5 + 3293 + 64 + 1952 + 32 .. 5 + 3293 + 64 + 1952 + 32 + 32];
    let user_id_hex = hex::encode(user_id_bytes);

    let timestamp_bytes = &packet[5 + 3293 + 64 + 1952 + 32 + 32 + 16 .. 5 + 3293 + 64 + 1952 + 32 + 32 + 16 + 8];
    let timestamp = utils::uint8_array_to_ts(&timestamp_bytes);

    let data_to_sign_bytes = &packet[5 + 3293 + 64 ..];

    if !check_ts_validity(timestamp) {
        // TODO handle invalid timestamp
    }

    verify(dilithium_signature, data_to_sign_bytes, dilithium_public_key_bytes).map_err(|_| "Dilithium signature invalid".to_string())?;
    
    let ed_public_key_array: &[u8; 32] = ed25519_public_key
        .try_into()
        .expect("Public key must be exactly 32 bytes");

    let ed_signature_array: &[u8; 64] = ed25519_signature
        .try_into()
        .expect("Signature must be exactly 64 bytes");

    let public_key = VerifyingKey::from_bytes(ed_public_key_array).map_err(|e| e.to_string())?;
    let signature = Signature::from_bytes(ed_signature_array);
    public_key.verify(data_to_sign_bytes, &signature).map_err(|e| e.to_string())?;

    let connection = {
        let connections = CONNECTIONS.read().await;
        connections.get(&user_id_hex).cloned()
    };
    let failed = if let Some(stream) = connection {
        let mut locked_writer = stream.lock().await;
        if let Err(e) = locked_writer.write(packet).await {
            println!("[ERROR] Failed to write to socket: {}", e);
            true
        } else {
            println!("Message successfully sent to {}", user_id_hex);
            false
        }
    } else {
        println!("No connection for {}", user_id_hex);
        true
    };

    if failed {
        println!("No connection for {}", user_id_hex);
        for raw_ip in super::node_assign::find_closest_hashes(&hex::decode(&user_id_hex).unwrap(), 4).await {
            let ip: std::net::IpAddr = raw_ip.parse().expect("Invalid IP address");
            if raw_ip == super::super::PUBLIC_IP.lock().unwrap().to_string() || raw_ip == "127.0.0.1"{
                save_packet(user_id_hex.clone(), packet.to_vec()).await;
                return Ok(());
            }

            match utils::send_tcp_message(&ip, &packet).await {
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
    Ok(())
}

pub async fn handle_connect(
    packet: &[u8]
) -> Result<String, String> {
    let dilithium_signature = &packet[5 .. 5 + 3293];
    let ed25519_signature = &packet[5 + 3293 .. 5 + 3293 + 64];

    let dilithium_public_key_bytes = &packet[5 + 3293 + 64 .. 5 + 3293 + 64 + 1952];
    let ed25519_public_key = &packet[5 + 3293 + 64 + 1952 .. 5 + 3293 + 64 + 1952 + 32];
    let nonce = &packet[5 + 3293 + 64 + 1952 + 32 .. 5 + 3293 + 64 + 1952 + 32 + 16];

    let data_to_sign_bytes = &packet[5 + 3293 + 64 ..];
    
    let timestamp_bytes = &packet[5 + 3293 + 64 + 1952 + 32 + 16 .. 5 + 3293 + 64 + 1952 + 32 + 16 + 8];
    let timestamp = utils::uint8_array_to_ts(&timestamp_bytes);

    let ed_public_key_array: &[u8; 32] = ed25519_public_key
        .try_into()
        .expect("Public key must be exactly 32 bytes");

    let ed_signature_array: &[u8; 64] = ed25519_signature
        .try_into()
        .expect("Signature must be exactly 64 bytes");

    let public_key = VerifyingKey::from_bytes(ed_public_key_array).map_err(|e| e.to_string())?;
    let signature = Signature::from_bytes(ed_signature_array);
    public_key.verify(data_to_sign_bytes, &signature).map_err(|e| e.to_string())?;

    
    verify(dilithium_signature, data_to_sign_bytes, dilithium_public_key_bytes).map_err(|_| "Dilithium signature invalid".to_string())?;

    if !utils::check_ts_validity(timestamp) {
        // TODO handle invalid timestamp
    }
    let full_hash_input = [
        &dilithium_public_key_bytes[..],
        &ed25519_public_key[..],         
        &nonce[..],                      
    ].concat();

    let public_id = crypto::sha256_hash(&full_hash_input);

    Ok(public_id)
}

pub async fn handle_node_assignement(
    buffer: &[u8]
) -> Result<Vec<u8>, String> {
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

    let public_key = VerifyingKey::from_bytes(ed_public_key_array).map_err(|e| e.to_string())?;
    let signature = Signature::from_bytes(ed_signature_array);
    public_key.verify(data_to_sign_bytes, &signature).map_err(|e| e.to_string())?;

    verify(dilithium_signature, data_to_sign_bytes, dilithium_public_key_bytes).map_err(|_| "Dilithium signature invalid".to_string())?;

    if !utils::check_ts_validity(timestamp) {
        // TODO handle invalid timestamp
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

    let mut buffer = Vec::new();
    for ip in closest_nodes {
        buffer.extend_from_slice(ip.as_bytes());
        println!("ip: {}", ip);
        buffer.extend_from_slice(" ".as_bytes());
    }

    Ok(buffer)
}