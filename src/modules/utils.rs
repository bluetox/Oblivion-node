use chrono::Utc;
use super::json_structs;
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

pub fn check_ts_validity(ts: &str) -> bool {
    let ts = ts.parse::<u64>().unwrap_or(0) / 1000;
    let now = Utc::now().timestamp() as u64;
    let diff = now.saturating_sub(ts);
    diff <= 10 || (ts > now && (ts - now) <= 2)
}

pub async fn broadcast_conn(input: &json_structs::Input) {
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
