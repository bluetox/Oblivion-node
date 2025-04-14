use chrono::Utc;
use tokio::{
    net::TcpStream,
    io::AsyncWriteExt,
};
use bytes::BytesMut;
use std::error::Error;
use std::net::SocketAddr;
use std::time::Duration;
use std::net::IpAddr;

pub fn check_ts_validity(ts: u64) -> bool {
    let ts = ts / 1000;
    let now = Utc::now().timestamp() as u64;
    let diff = now.saturating_sub(ts);
    diff <= 10 || (ts > now && (ts - now) <= 2)
}

pub async fn send_tcp_message(ip: &IpAddr, buffer: &[u8]) -> Result<(), Box<dyn Error>> {
    let addr: SocketAddr = SocketAddr::new(*ip, 20168);

    match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            stream.write_all(buffer).await?;
            println!("data_sent");
            stream.flush().await?;
            println!("Message sent to {}", ip);
            Ok(())
        },
        Ok(Err(e)) => {
            eprintln!("Failed to connect to {}: {}", ip, e);
            Err(Box::new(e))
        },
        Err(_) => {
            eprintln!("Connection to {} timed out", ip);
            Err("Connection timed out".into())
        }
    }
}

pub fn uint8_array_to_ts(arr: &[u8]) -> u64 {
    if arr.len() != 8 {
        panic!("Input array must be exactly 8 bytes long");
    }

    let high = u32::from(arr[0]) << 24
        | u32::from(arr[1]) << 16
        | u32::from(arr[2]) << 8
        | u32::from(arr[3]);

    let low = u32::from(arr[4]) << 24
        | u32::from(arr[5]) << 16
        | u32::from(arr[6]) << 8
        | u32::from(arr[7]);

    ((high as u64) << 32) | low as u64
}

pub fn _ip_to_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

pub async fn save_packet(hash: String, packet: Vec<u8>) {
    println!("Saved packet");
    let mut store = super::super::DELAYED_DELIVERY.lock().await;

    store
        .entry(hash)
        .and_modify(|packets| packets.push(packet.clone()))
        .or_insert_with(|| vec![packet]);
}

pub async fn get_packets_for_user(hash: &str) -> Option<Vec<Vec<u8>>> {
    let store = super::super::DELAYED_DELIVERY.lock().await;
    store.get(hash).cloned()
}

pub async fn delete_packets_for_user(hash: &str) -> bool {
    let mut store = super::super::DELAYED_DELIVERY.lock().await;
    store.remove(hash).is_some()
}

pub async fn decrypt_packet(encrypted_packet: &BytesMut, shared_secret: &[u8]) -> Option<BytesMut> {
    let payload_size_bytes = &encrypted_packet[1..3];
    let payload_size = u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;

    if encrypted_packet.len() < payload_size {
        println!("[ERROR] Buffer is too short for declared payload size.");
        return None;
    }

    let encrypted_data = &encrypted_packet[5.. payload_size];

    let decrypted_data = match super::encryption::decrypt_message(encrypted_data, shared_secret).await {
        Ok(data) => data,
        Err(e) => {
            println!("[ERROR] Decryption failed: {}", e);
            return None;
        }
    };

    let mut decrypted_packet = BytesMut::with_capacity(5 + decrypted_data.len());
    decrypted_packet.extend_from_slice(&encrypted_packet[..5]);
    decrypted_packet.extend_from_slice(&decrypted_data);

    let total_size = decrypted_packet.len() as u16;
    decrypted_packet[1..3].copy_from_slice(&total_size.to_le_bytes());

    Some(decrypted_packet)
}
