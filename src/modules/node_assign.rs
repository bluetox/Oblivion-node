use hex;
use num_bigint::BigUint;
use std::{
    fs::File,
    io::{self, BufReader, BufRead, Write},
};
use std::io::Seek;

#[derive(Clone, Debug)]
pub struct IpHash {
    ip: String,
    hash: Vec<u8>,
}


pub async fn read_and_sort_hashes_from_file(file: &File) -> io::Result<Vec<IpHash>> {
    let reader = BufReader::new(file);
    let mut hashes = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if let Some((ip, hash_str)) = line.split_once(':') {
            if let Ok(decoded_hash) = hex::decode(hash_str) {
                hashes.push(IpHash { ip: ip.to_string(), hash: decoded_hash });
            }
        }
    }
    hashes.sort_by(|a, b| {
        BigUint::from_bytes_be(&a.hash).cmp(&BigUint::from_bytes_be(&b.hash))
    });
    let mut nodes_hashmap = super::super::NODES_HASHMAP.lock().await;
    *nodes_hashmap = hashes.clone(); // 
    println!("finished loading!");
    Ok(hashes)
}

fn _insert_hash_into_sorted_list(hashes: &mut Vec<IpHash>, new_ip_hash: IpHash) {
    let new_num = BigUint::from_bytes_be(&new_ip_hash.hash);

    let mut left = 0;
    let mut right = hashes.len();

    while left < right {
        let mid = (left + right) / 2;
        let mid_num = BigUint::from_bytes_be(&hashes[mid].hash);

        if mid_num < new_num {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    hashes.insert(left, new_ip_hash);
}

fn _write_sorted_hashes_to_file(file: &mut File, hashes: &[IpHash]) -> io::Result<()> {
    file.set_len(0)?;
    file.seek(io::SeekFrom::Start(0))?;

    for entry in hashes {
        writeln!(file, "{}:{}", entry.ip, hex::encode(&entry.hash))?;
    }
    Ok(())
}

pub async fn find_closest_hashes(target_hash: &Vec<u8>, n: usize) -> Vec<String> {
    println!("the user_id is: {}", hex::encode(&target_hash));
    let hashes = super::super::NODES_HASHMAP.lock().await;
    let target_num = BigUint::from_bytes_be(target_hash);
    let mut left = 0;
    let mut right = hashes.len();

    while left < right {
        let mid = (left + right) / 2;
        let mid_num = BigUint::from_bytes_be(&hashes[mid].hash);

        if mid_num < target_num {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    let mut lower = if right == 0 { 0 } else { right - 1 };
    let mut upper = right;

    let mut closest = Vec::new();

    while closest.len() < n && (lower > 0 || upper < hashes.len()) {
        if upper >= hashes.len() || (lower > 0 && {
            let lower_num = BigUint::from_bytes_be(&hashes[lower].hash);
            let upper_num = BigUint::from_bytes_be(&hashes.get(upper).map(|h| &h.hash).unwrap_or(&hashes[0].hash));
            
            let lower_diff = if target_num > lower_num {
                &target_num - &lower_num
            } else {
                &lower_num - &target_num
            };
        
            let upper_diff = if upper_num > target_num {
                &upper_num - &target_num
            } else {
                &target_num - &upper_num
            };
        
            lower_diff <= upper_diff
        }) {
            closest.push(hashes[lower].ip.clone());
            println!("hash of ip: {}, ip associated: {}",hex::encode(&hashes[lower].hash), &hashes[lower].ip);
            if lower > 0 { lower -= 1; }
        } else {
            closest.push(hashes[upper].ip.clone());
            println!("hash of ip: {}, ip associated: {}",hex::encode(&hashes[upper].hash), &hashes[upper].ip);
            upper += 1;
        }
    }

    closest
}
