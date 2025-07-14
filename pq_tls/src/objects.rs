use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey, Signature as Ed25519Signature, Signer};
use rand::rngs::OsRng;
use rand::RngCore;
use std::error::Error;
use frodo_kem::Algorithm;
use frodo_kem::{EncryptionKey as FrodoKemPub, DecryptionKey as FrodoKemPrivate};
use std::fs::File;
use std::fs::create_dir_all;
use std::io::Write;
use std::io::Read;
use crate::constants::*;

pub struct Dilithium2Keypair(pqc_dilithium2::Keypair);
pub struct Dilithium3Keypair(pqc_dilithium3::Keypair);
pub struct Dilithium5Keypair(pqc_dilithium5::Keypair);

pub struct FrodoKem1344Keypair {
    pub secret: FrodoKemPrivate,
    pub public: FrodoKemPub
}

pub struct FrodoKem976Keypair {
    pub secret: FrodoKemPrivate,
    pub public: FrodoKemPub
}

pub struct FrodoKem640Keypair {
    pub secret: FrodoKemPrivate,
    pub public: FrodoKemPub
}



pub struct Ed25519Keypair(Ed25519SigningKey);
pub struct Kyber1024Keypair(kyber1024::Keypair);
pub struct Kyber768Keypair(kyber768::Keypair);
pub struct Kyber512Keypair(kyber512::Keypair);

pub struct X25519Keypair{
    pub secret: EphemeralSecret,
    pub public: X25519PublicKey
}

impl X25519Keypair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        X25519Keypair { secret, public}
    }
}

impl Dilithium2Keypair {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let keypair = pqc_dilithium2::Keypair::generate(&seed);

        Dilithium2Keypair(keypair)
    }

    pub fn load_or_generate() -> Self {
        if let Ok(mut file) = File::open("serv_data/keys/Dilithium2") {
            let mut pk = [0u8; DILITHIUM2_PUBLIC_KEY_SIZE];
            let mut sk = [0u8; DILITHIUM2_SECRET_KEY_SIZE];

            if file.read_exact(&mut pk).is_ok() && file.read_exact(&mut sk).is_ok() {
                let keypair = pqc_dilithium2::Keypair::load(pk, sk);
                return Dilithium2Keypair(keypair);
            }
        }

        println!("Warning: Generating new Dilithium2 keypair (existing key missing or invalid)");

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let keypair = pqc_dilithium2::Keypair::generate(&seed);
        let sk = keypair.expose_secret();
        let pk = &keypair.public;

        if let Some(parent) = std::path::Path::new("serv_data/keys/Dilithium2").parent() {
            create_dir_all(parent).expect("Failed to create key directory");
        }

        let mut file = File::create("serv_data/keys/Dilithium2").expect("Failed to create key file");
        file.write_all(pk).expect("Failed to write public key");
        file.write_all(sk).expect("Failed to write secret key");

        Dilithium2Keypair(keypair)
    }
}

impl Dilithium3Keypair {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let keypair = pqc_dilithium3::Keypair::generate(&seed);

        Dilithium3Keypair(keypair)
    }

    pub fn load_or_generate() -> Self {
        if let Ok(mut file) = File::open("serv_data/keys/Dilithium3") {
            let mut pk = [0u8; DILITHIUM3_PUBLIC_KEY_SIZE];
            let mut sk = [0u8; DILITHIUM3_SECRET_KEY_SIZE];

            if file.read_exact(&mut pk).is_ok() && file.read_exact(&mut sk).is_ok() {
                let keypair = pqc_dilithium3::Keypair::load(pk, sk);
                return Dilithium3Keypair(keypair);
            }
        }

        println!("Warning: Generating new Dilithium3 keypair (existing key missing or invalid)");
        
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let keypair = pqc_dilithium3::Keypair::generate(&seed);
        let sk = keypair.expose_secret();
        let pk = &keypair.public;

        if let Some(parent) = std::path::Path::new("serv_data/keys/Dilithium3").parent() {
            create_dir_all(parent).expect("Failed to create key directory");
        }

        let mut file = File::create("serv_data/keys/Dilithium3").expect("Failed to create key file");
        file.write_all(pk).expect("Failed to write public key");
        file.write_all(sk).expect("Failed to write secret key");

        Dilithium3Keypair(keypair)
    }
}


impl Dilithium5Keypair {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let keypair = pqc_dilithium5::Keypair::generate(&seed);

        Dilithium5Keypair(keypair)
    }

    pub fn load_or_generate() -> Self {
        if let Ok(mut file) = File::open("serv_data/keys/Dilithium5") {
            let mut pk = [0u8; DILITHIUM5_PUBLIC_KEY_SIZE];
            let mut sk = [0u8; DILITHIUM5_SECRET_KEY_SIZE];

            if file.read_exact(&mut pk).is_ok() && file.read_exact(&mut sk).is_ok() {
                let keypair = pqc_dilithium5::Keypair::load(pk, sk);
                return Dilithium5Keypair(keypair);
            }
        }

        println!("Warning: Generating new Dilithium5 keypair (existing key missing or invalid)");
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let keypair = pqc_dilithium5::Keypair::generate(&seed);
        let sk = keypair.expose_secret();
        let pk = &keypair.public;

        if let Some(parent) = std::path::Path::new("serv_data/keys/Dilithium5").parent() {
            create_dir_all(parent).expect("Failed to create key directory");
        }

        let mut file = File::create("serv_data/keys/Dilithium5").expect("Failed to create key file");
        file.write_all(pk).expect("Failed to write public key");
        file.write_all(sk).expect("Failed to write secret key");
        Dilithium5Keypair(keypair)
    }
}

impl Kyber1024Keypair {
    pub fn generate() -> Self {
        let keypair = kyber1024::keypair(&mut OsRng, None);
        Kyber1024Keypair(keypair)
    }
}

impl Kyber768Keypair {
    pub fn generate() -> Self {
        let keypair = kyber768::keypair(&mut OsRng, None);
        Kyber768Keypair(keypair)
    }
}
impl Kyber512Keypair {
    pub fn generate() -> Self {
        let keypair = kyber512::keypair(&mut OsRng, None);
        Kyber512Keypair(keypair)
    }
}

impl FrodoKem1344Keypair {
    pub fn generate() -> Self {
        let alg = Algorithm::FrodoKem1344Shake;
        let (ek, dk) = alg.generate_keypair(OsRng);
        FrodoKem1344Keypair { secret: dk, public: ek }
    }
}

impl FrodoKem976Keypair {
    pub fn generate() -> Self {
        let alg = Algorithm::FrodoKem976Shake;
        let (ek, dk) = alg.generate_keypair(OsRng);
        FrodoKem976Keypair { secret: dk, public: ek }
    }
}

impl FrodoKem640Keypair {
    pub fn generate() -> Self {
        let alg = Algorithm::FrodoKem640Shake;
        let (ek, dk) = alg.generate_keypair(OsRng);
        FrodoKem640Keypair { secret: dk, public: ek }
    }
}

impl Ed25519Keypair {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let keypair = Ed25519SigningKey::from_bytes(&seed);

        Ed25519Keypair(keypair)
    }

    pub fn load_or_generate() -> Self {
        if let Ok(mut file) = File::open("serv_data/keys/Ed25519") {
            let mut seed = [0u8; 32];

            if file.read_exact(&mut seed).is_ok() {
                let keypair = Ed25519SigningKey::from_bytes(&seed);
                return Ed25519Keypair(keypair);
            }
        }

        println!("Warning: Generating new Ed25519 keypair (existing seed missing or invalid)");
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let keypair = Ed25519SigningKey::from_bytes(&seed);

        if let Some(parent) = std::path::Path::new("serv_data/keys/Ed25519").parent() {
            create_dir_all(parent).expect("Failed to create key directory");
        }

        let mut file = File::create("serv_data/keys/Ed25519").expect("Failed to create key file");
        file.write_all(&seed).expect("Failed to write private seed");
        Ed25519Keypair(keypair)
    }
}


pub enum PqSigningKeys {
    Dilithium2(Dilithium2Keypair),
    Dilithium3(Dilithium3Keypair),
    Dilithium5(Dilithium5Keypair)
}

pub enum CSigningKeys {
    Ed25519(Ed25519Keypair)
}

impl CSigningKeys {
    pub fn public(&self) -> Vec<u8> {
        match self {
            CSigningKeys::Ed25519(ed25519) => ed25519.0.verifying_key().as_bytes().to_vec(),
        }
    }

    pub fn sign(&mut self, data: &Vec<u8>) -> Vec<u8> {
        match self {
            CSigningKeys::Ed25519(ed25519) => ed25519.0.sign(&data).to_vec()
        }
    }

    pub fn verify(&mut self, data: &[u8], pk: &[u8], signature: &[u8]) -> Result<(), Box<dyn Error>>  {
        match self {
            CSigningKeys::Ed25519(_) => {
                let pubkey_array: &[u8; 32] = pk.try_into().expect("slice with incorrect length");
                let verifying_key: VerifyingKey = VerifyingKey::from_bytes(pubkey_array)?;
                let signature: Ed25519Signature = Ed25519Signature::try_from(&signature[..])?;
                verifying_key.verify_strict(data, &signature)?;  
                
            }
        }
        Ok(())
    }

    pub fn pk_size(&self) -> usize {
        match self {
            CSigningKeys::Ed25519(_) => ED25519_PUBLIC_KEY_SIZE
        }
    } 

    pub fn sign_size(&self) -> usize {
        match self {
            CSigningKeys::Ed25519(_) => ED25519_SIGNATURE_SIZE
        }
    } 

    pub fn default() -> Self {
        let key = Ed25519Keypair::generate();
        CSigningKeys::Ed25519(key)
    }

    pub fn key_type(&self) -> String {
        match self {
            CSigningKeys::Ed25519(_) => "Ed25519".to_string()
        }

    }
}

impl PqSigningKeys {
    pub fn public(&self) -> Vec<u8> {
        match self {
            PqSigningKeys::Dilithium2(dilithium) => dilithium.0.public.to_vec(),
            PqSigningKeys::Dilithium3(dilithium) => dilithium.0.public.to_vec(), // a
            PqSigningKeys::Dilithium5(dilithium) => dilithium.0.public.to_vec(), // a
        }
    }

    pub fn sign(&mut self, data: &Vec<u8>) -> Vec<u8> {
        match self {
            PqSigningKeys::Dilithium2(dilithium) => dilithium.0.sign(&data).to_vec(),
            PqSigningKeys::Dilithium3(dilithium) => dilithium.0.sign(&data).to_vec(),
            PqSigningKeys::Dilithium5(dilithium) => dilithium.0.sign(&data).to_vec(),
        }
    }

    pub fn verify(&self, message: &[u8], public_key: &[u8], signature: &[u8]) -> Result<(), Box<dyn Error>> {
        match self {
            PqSigningKeys::Dilithium2(_) => pqc_dilithium2::verify(signature, message, public_key)
                .map_err(|_| Box::<dyn Error>::from(String::from("Invalid PQ Signature")))?,
            PqSigningKeys::Dilithium3(_) => pqc_dilithium3::verify(signature, message, public_key)
                .map_err(|_| Box::<dyn Error>::from(String::from("Invalid PQ Signature")))?,
            PqSigningKeys::Dilithium5(_) => pqc_dilithium5::verify(signature, message, public_key)
                .map_err(|_| Box::<dyn Error>::from(String::from("Invalid PQ Signature")))?,
        }
        Ok(())
    }

    pub fn default() -> Self {
        let key = Dilithium3Keypair::generate();
        PqSigningKeys::Dilithium3(key)
    }
    pub fn pk_size(&self) -> usize {
        match self {
            PqSigningKeys::Dilithium2(_) => DILITHIUM2_PUBLIC_KEY_SIZE,
            PqSigningKeys::Dilithium3(_) => DILITHIUM3_PUBLIC_KEY_SIZE,
            PqSigningKeys::Dilithium5(_) => DILITHIUM5_PUBLIC_KEY_SIZE
        }
    }
    pub fn sign_size(&self) -> usize {
        match self {
            PqSigningKeys::Dilithium2(_) => DILITHIUM2_SIGNATURE_SIZE,
            PqSigningKeys::Dilithium3(_) => DILITHIUM3_SIGNATURE_SIZE,
            PqSigningKeys::Dilithium5(_) => DILITHIUM5_SIGNATURE_SIZE
        }
    }
    pub fn key_type(&self) -> String {
        match self {
            &PqSigningKeys::Dilithium2(_) => "Dilithium2".to_string(),
            &PqSigningKeys::Dilithium3(_) => "Dilithium3".to_string(),
            &PqSigningKeys::Dilithium5(_) => "Dilithium5".to_string()
        }

    }
}

pub enum PqAKAKeys {
    Kyber1024(Kyber1024Keypair),
    Kyber768(Kyber768Keypair),
    Kyber512(Kyber512Keypair),
    FrodoKem1344(FrodoKem1344Keypair),
    FrodoKem976(FrodoKem976Keypair),
    FrodoKem640(FrodoKem640Keypair)
}


pub enum CAKAKeys {
    X25519(X25519Keypair),
}

impl CAKAKeys {
    pub fn public(&self) -> Vec<u8> {
        match self {
            CAKAKeys::X25519(x25519) => x25519.public.as_bytes().to_vec(),
        }
    }

    pub fn decapsulate(&mut self, pk: &[u8]) -> Vec<u8> {
        match self {
            CAKAKeys::X25519(x25519) => {
                let arr: [u8; 32] = pk.try_into().expect("Failed to convert slice to array");
                let public_key = X25519PublicKey::from(arr);

                // Move secret out of x25519 to use diffie_hellman
                let secret = std::mem::replace(&mut x25519.secret, EphemeralSecret::random_from_rng(rand::rngs::OsRng));

                secret.diffie_hellman(&public_key).as_ref().to_vec()
            }
        }
    }

    pub fn pk_size(&self) -> usize {
        match self {
            CAKAKeys::X25519(_) => X25519_PUBLIC_KEY_SIZE
        }
    } 

    pub fn default() -> Self {
        let key = X25519Keypair::generate();
        CAKAKeys::X25519(key)
    }
}

impl PqAKAKeys {
    pub fn public(&self) -> Vec<u8> {
        match self {
            PqAKAKeys::Kyber1024(kyber) => kyber.0.public.to_vec(),
            PqAKAKeys::Kyber768(kyber) => kyber.0.public.to_vec(),
            PqAKAKeys::Kyber512(kyber) => kyber.0.public.to_vec(),
            PqAKAKeys::FrodoKem1344(frodo_kem) => frodo_kem.public.value().to_vec(),
            PqAKAKeys::FrodoKem976(frodo_kem) => frodo_kem.public.value().to_vec(),
            PqAKAKeys::FrodoKem640(frodo_kem) => frodo_kem.public.value().to_vec(),
        }
    }

    pub fn decapsulate(&self, ct: &[u8]) -> Vec<u8> {
        match self {
            PqAKAKeys::Kyber1024(kyber) => kyber1024::decapsulate(ct, &kyber.0.secret).unwrap().to_vec(),
            PqAKAKeys::Kyber768(kyber) => kyber768::decapsulate(ct, &kyber.0.secret).unwrap().to_vec(),
            PqAKAKeys::Kyber512(kyber) => kyber512::decapsulate(ct, &kyber.0.secret).unwrap().to_vec(),
            PqAKAKeys::FrodoKem1344(frodo_kem) => {
                let alg = Algorithm::FrodoKem1344Shake;
                let decap = alg
                    .decapsulate(&frodo_kem.secret, &alg.ciphertext_from_bytes(ct).unwrap())
                    .unwrap();

                let ss_slice = decap.0.value();

                let ss_array: [u8; 32] = ss_slice
                    .try_into()
                    .expect("Shared secret must be 32 bytes long");
                ss_array.to_vec()
            },
            PqAKAKeys::FrodoKem976(frodo_kem) => {
                let alg = Algorithm::FrodoKem976Shake;
                let decap = alg
                    .decapsulate(&frodo_kem.secret, &alg.ciphertext_from_bytes(ct).unwrap())
                    .unwrap();

                let ss_slice = decap.0.value();

                let ss_array: [u8; 24] = ss_slice
                    .try_into()
                    .expect("Shared secret must be 32 bytes long");
                ss_array.to_vec()
            },
            PqAKAKeys::FrodoKem640(frodo_kem) => {
                let alg = Algorithm::FrodoKem640Shake;
                let decap = alg
                    .decapsulate(&frodo_kem.secret, &alg.ciphertext_from_bytes(ct).unwrap())
                    .unwrap();

                let ss_slice = decap.0.value();

                let ss_array: [u8; 16] = ss_slice
                    .try_into()
                    .expect("Shared secret must be 32 bytes long");
                ss_array.to_vec()
            }
        }
    }

    pub fn encapsulate(&self, pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
        match self {
            PqAKAKeys::Kyber512(_) => {
                let (ct, ss ) = kyber512::encapsulate(pk, &mut OsRng, None).unwrap();
                (ct.to_vec(), ss.to_vec())
            }

            PqAKAKeys::Kyber768(_) => {
                let (ct, ss ) = kyber768::encapsulate(pk, &mut OsRng, None).unwrap();
                (ct.to_vec(), ss.to_vec())
            }
            PqAKAKeys::Kyber1024(_) => {
                let (ct, ss ) = kyber1024::encapsulate(pk, &mut OsRng, None).unwrap();
                (ct.to_vec(), ss.to_vec())
            }
            PqAKAKeys::FrodoKem1344(_)  => {
                let ek = Algorithm::FrodoKem1344Shake.encryption_key_from_bytes(pk).unwrap();
                let (ct, ss_slice) = Algorithm::FrodoKem1344Shake.encapsulate_with_rng(&ek, &mut OsRng).unwrap();
                
                let ss: [u8; 32] = ss_slice.value()
                    .try_into()
                    .expect("Shared secret must be 32 bytes long");

                (ct.value().to_vec(), ss.to_vec())
            }
            PqAKAKeys::FrodoKem976(_)  => {
                let ek = Algorithm::FrodoKem976Shake.encryption_key_from_bytes(pk).unwrap();
                let (ct, ss_slice) = Algorithm::FrodoKem976Shake.encapsulate_with_rng(&ek, &mut OsRng).unwrap();
                
                let ss: [u8; 24] = ss_slice.value()
                    .try_into()
                    .expect("Shared secret must be 24 bytes long");

                (ct.value().to_vec(), ss.to_vec())
            }
            PqAKAKeys::FrodoKem640(_)  => {
                let ek = Algorithm::FrodoKem640Shake.encryption_key_from_bytes(pk).unwrap();
                let (ct, ss_slice) = Algorithm::FrodoKem640Shake.encapsulate_with_rng(&ek, &mut OsRng).unwrap();
                
                let ss: [u8; 16] = ss_slice.value()
                    .try_into()
                    .expect("Shared secret must be 16 bytes long");

                (ct.value().to_vec(), ss.to_vec())
            }
        }
    }
    pub fn default() -> Self {
        let key = Kyber1024Keypair::generate();
        PqAKAKeys::Kyber1024(key)
    }

    pub fn pk_size(&self) -> usize {
        match self {
            PqAKAKeys::Kyber1024(_) => KYBER_1024_PUBLIC_KEY_SIZE,
            PqAKAKeys::Kyber768(_) => KYBER_768_PUBLIC_KEY_SIZE,
            PqAKAKeys::Kyber512(_) => KYBER_512_PUBLIC_KEY_SIZE,
            PqAKAKeys::FrodoKem1344(_) => Algorithm::FrodoKem1344Shake.params().encryption_key_length,
            PqAKAKeys::FrodoKem976(_) => Algorithm::FrodoKem976Shake.params().encryption_key_length,
            PqAKAKeys::FrodoKem640(_) => Algorithm::FrodoKem640Shake.params().encryption_key_length
        }
    } 
    pub fn ct_size(&self) -> usize {
        match self {
            PqAKAKeys::Kyber1024(_) => KYBER_1024_CIPHERTEXT_SIZE,
            PqAKAKeys::Kyber768(_) => KYBER_768_CIPHERTEXT_SIZE,
            PqAKAKeys::Kyber512(_) => KYBER_512_CIPHERTEXT_SIZE,
            PqAKAKeys::FrodoKem1344(_) => Algorithm::FrodoKem1344Shake.params().ciphertext_length,
            PqAKAKeys::FrodoKem976(_) => Algorithm::FrodoKem976Shake.params().ciphertext_length,
            PqAKAKeys::FrodoKem640(_) => Algorithm::FrodoKem640Shake.params().ciphertext_length
        }
    } 
}

pub struct PqTlsSettings {
    pub pq_signing_keys: PqSigningKeys,
    pub c_signing_keys: CSigningKeys,
    pub 
    pq_aka_keys: PqAKAKeys,
    pub c_aka_keys: CAKAKeys
}


impl Default for PqTlsSettings {
    fn default() -> Self {
        Self {
            pq_signing_keys: PqSigningKeys::Dilithium2(Dilithium2Keypair::generate()),
            c_signing_keys: CSigningKeys::default(),
            pq_aka_keys: PqAKAKeys::Kyber512(Kyber512Keypair::generate()),
            c_aka_keys: CAKAKeys::default()
        }
    }
}