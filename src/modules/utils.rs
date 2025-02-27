use chrono::Utc;
use tokio::{
    net::TcpStream,
    io::AsyncWriteExt,
};
use std::{
    fs,
    error::Error,
};
use serde_json::Value;
use std::time::Duration;

pub fn check_ts_validity(ts: u64) -> bool {
    let ts = ts / 1000;
    let now = Utc::now().timestamp() as u64;
    let diff = now.saturating_sub(ts);
    diff <= 10 || (ts > now && (ts - now) <= 2)
}


pub fn read_nodes_from_json(file_path: &str) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let content = fs::read_to_string(file_path)?;
    let json: Value = serde_json::from_str(&content)?;
    
    let nodes = json.as_array()
        .ok_or_else(|| "Expected JSON array".to_string())? 
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    Ok(nodes)
}

pub async fn send_tcp_message(ip: &str, message: &str) -> Result<(), Box<dyn Error>> {
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