// #![allow(dead_code)]

use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf, AsyncReadExt};
use std::error::Error;
use std::path::PathBuf;

use crate::constants::*;
use crate::objects::*;
use crate::{utils, settings, crypto};

pub struct PqTlsClient {
    pub reader: ReadHalf<TcpStream>,
    pub writer: WriteHalf<TcpStream>,
    pub client_random: [u8; 32],
    pub ss: [u8; 32],
    pub buffer: Vec<u8>
}

impl PqTlsClient {
    pub async fn connect(ip: &str, port: u16, settings: &mut PqTlsSettings) -> Result<Self, Box<dyn Error>> {
        let addr = format!("{}:{}", ip, port);

        let db_path = PathBuf::from("known_hosts/db.sqlite");
        let db = crate::database::setup_db(&db_path).await;

        let stream = TcpStream::connect(addr).await?;

        let (mut reader, mut writer) = tokio::io::split(stream);

        let client_random = utils::generate_client_random();

        let mut client_hello = Vec::with_capacity(CLIENT_HELLO_PACKET_SIZE);

        let settings_bytes = settings::settings_to_bytes(&settings);

        client_hello.push(CLIENT_HELLO_CODE);
        client_hello.extend_from_slice(&settings_bytes);
        client_hello.extend_from_slice(&client_random);

        writer.write(&client_hello).await?;

        let server_hello = Self::get_server_hello(&mut reader, &settings).await?;
        
        let server_random = &server_hello[1 .. 1 + 32];

        let pq_sign_pk_size = settings.pq_signing_keys.pk_size();
        let pq_sign_size = settings.pq_signing_keys.sign_size();
        let c_sign_pk_size = settings.c_signing_keys.pk_size();
        let c_sign_size = settings.c_signing_keys.sign_size();
        let pq_aka_pk_size = settings.pq_aka_keys.pk_size();
        let c_aka_pk_size = settings.c_aka_keys.pk_size();

        let pq_sign = &server_hello[1 + 32 .. 1 + 32 + pq_sign_size];
        let c_sign = &server_hello[1 + 32 + pq_sign_size .. 1 + 32 + pq_sign_size + c_sign_size];
        let pq_sign_pk = &server_hello[1 + 32 + pq_sign_size + c_sign_size .. 1 + 32 + pq_sign_size + c_sign_size + pq_sign_pk_size];
        let c_sign_pk = &server_hello[1 + 32 + pq_sign_size + c_sign_size + pq_sign_pk_size .. 1 + 32 + pq_sign_size + c_sign_size + pq_sign_pk_size + c_sign_pk_size];
        let pq_kem_pk = &server_hello[1 + 32 + pq_sign_size + c_sign_size + pq_sign_pk_size + c_sign_pk_size .. 1 + 32 + pq_sign_size + c_sign_size + pq_sign_pk_size + c_sign_pk_size + pq_aka_pk_size];
        let c_aka_pk = &server_hello[1 + 32 + pq_sign_size + c_sign_size + pq_sign_pk_size + c_sign_pk_size + pq_aka_pk_size .. 1 + 32 + pq_sign_size + c_sign_size + pq_sign_pk_size + c_sign_pk_size + pq_aka_pk_size + c_aka_pk_size];

        let signed_part = &server_hello[1 + 32 + pq_sign_size + c_sign_size .. ];

        settings.pq_signing_keys.verify(signed_part, pq_sign_pk, pq_sign)?;
        settings.c_signing_keys.verify(signed_part, c_sign_pk, c_sign)?;

        let fingerprint = utils::hash_combined(pq_sign_pk, c_sign_pk);
        println!("fingerprint: {:?}", fingerprint);
        let known = crate::database::fingerprint_exists(&db, &fingerprint).await?;

        if !known {
            
            match crate::database::insert_new_peer(&db, pq_sign_pk, &settings.pq_signing_keys.key_type(), c_sign_pk, &settings.c_signing_keys.key_type() , &fingerprint, ip, port).await {
                Ok(()) => {},
                Err(e) => return Err(format!("Invalid fingerprint for host: {} {}", ip, e).into())
            }
        }

        let (pq_ct, pq_ss) = settings.pq_aka_keys.encapsulate(pq_kem_pk);
        let (c_aka_p_pk, c_ss) = crypto::decapsulate_x25519(c_aka_pk);
        let ss = crypto::derive_hybrid_key(&client_random, &server_random, &pq_ss, &c_ss);

        let mut signed_part: Vec<u8> = Vec::new();
        signed_part.extend_from_slice(&settings.pq_signing_keys.public());
        signed_part.extend_from_slice(&settings.c_signing_keys.public());
        signed_part.extend_from_slice(&pq_ct);
        signed_part.extend_from_slice(&c_aka_p_pk);

        let pq_sign = settings.pq_signing_keys.sign(&signed_part);
        let c_sign = settings.c_signing_keys.sign(&signed_part).to_vec();

        let mut client_ct: Vec<u8> = Vec::new();
        client_ct.push(2);
        client_ct.extend_from_slice(&pq_sign);
        client_ct.extend_from_slice(&c_sign);
        client_ct.extend_from_slice(&signed_part);
        
        writer.write(&client_ct).await?;

        println!("Shared secret estalished: {:?}", ss);
        let ss_slice =  ss.try_into().expect("Shared Secret is not the write size"); 
        Ok(Self { reader, writer , client_random, ss: ss_slice, buffer: Vec::new()})
    }

    async fn get_server_hello(reader: &mut ReadHalf<TcpStream>, settings: &PqTlsSettings) -> Result<Vec<u8>, Box<dyn Error>> {
        let pq_sign_pk_size = settings.pq_signing_keys.pk_size();
        let pq_sign_size = settings.pq_signing_keys.sign_size();
        let c_sign_pk_size = settings.c_signing_keys.pk_size();
        let c_sign_size = settings.c_signing_keys.sign_size();
        let pq_aka_pk_size = settings.pq_aka_keys.pk_size();
        let c_aka_pk_size = settings.c_aka_keys.pk_size();

        let mut server_hello = Vec::new();
        while server_hello.len() < 1 + 32 + pq_sign_size + c_sign_size + pq_sign_pk_size + c_sign_pk_size + pq_aka_pk_size + c_aka_pk_size{
            let mut chunk = [0u8; 1024];
            match reader.read(&mut chunk).await {
                Ok(n) if n == 0 => {
                    return Err("Connection terminated".into());
                }
                Ok(n) => {
                    server_hello.extend_from_slice(&chunk[..n]);

                }
                Err(e) => {
                    return Err(e.into());
                }
            };
        }
        Ok(server_hello)
    }

    pub async fn send_dummy_packet(&mut self) -> Result<(), std::io::Error> {
        let payload = b"Hello from dummy packet!";

        let state: u8 = 2;

        let size = 1 + 3 + payload.len();

        let mut header = [0u8; 3];
        header[0] = (size & 0xFF) as u8;
        header[1] = ((size >> 8) & 0xFF) as u8;
        header[2] = ((size >> 16) & 0xFF) as u8;

        let mut packet = Vec::with_capacity(size);
        packet.push(state);
        packet.extend_from_slice(&header);
        packet.extend_from_slice(payload);


        let enc_packet = crypto::encrypt_packet(&packet, &self.ss);
        self.writer.write_all(&enc_packet).await?;
        Ok(())
    }

    pub async fn wait_for_packet(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        loop {
            let mut chunk = [0u8; 1024];
            let n = match self.reader.read(&mut chunk).await {
                Ok(0) => return Err("Connection terminated".into()),
                Ok(n) => n,
                Err(e) => return Err(format!("Error reading from stream: {}", e).into()),
            };

            self.buffer.extend_from_slice(&chunk[..n]);

            if self.buffer.len() < 4 {
                continue;
            }

            let size = (self.buffer[1] as usize)
                | ((self.buffer[2] as usize) << 8)
                | ((self.buffer[3] as usize) << 16);

            let packet = &self.buffer[..size].to_vec();
            if self.buffer.len() >= size {
                let dec_packet = crypto::decrypt_packet(packet, &self.ss);

                self.buffer.drain(0..size);
                return Ok(dec_packet);
            }
        }
    }
}