use crate::objects::*;


pub fn bytes_to_settings(settings_bytes: &[u8]) -> PqTlsSettings {
    let pq_signing_keys = match settings_bytes.get(0) {
        Some(0) => PqSigningKeys::Dilithium2(Dilithium2Keypair::load_or_generate()),
        Some(1) => PqSigningKeys::Dilithium3(Dilithium3Keypair::load_or_generate()),
        Some(2) => PqSigningKeys::Dilithium5(Dilithium5Keypair::load_or_generate()),
        _ => PqSigningKeys::Dilithium3(Dilithium3Keypair::load_or_generate()),
    }; 

    let c_signing_keys = match settings_bytes.get(1) {
        Some(0) => CSigningKeys::Ed25519(Ed25519Keypair::load_or_generate()),
        _ => CSigningKeys::Ed25519(Ed25519Keypair::load_or_generate()),
    };

    let pq_aka_keys = match settings_bytes.get(2) {
        Some(0) => PqAKAKeys::Kyber512(Kyber512Keypair::generate()),
        Some(1) => PqAKAKeys::Kyber768(Kyber768Keypair::generate()),
        Some(2) => PqAKAKeys::Kyber1024(Kyber1024Keypair::generate()),
        Some(3) => PqAKAKeys::FrodoKem1344(FrodoKem1344Keypair::generate()),
        Some(4) => PqAKAKeys::FrodoKem976(FrodoKem976Keypair::generate()),
        Some(5) => PqAKAKeys::FrodoKem640(FrodoKem640Keypair::generate()),
        _ => {
            println!("Error: pq_aka setting not handled");
            PqAKAKeys::Kyber512(Kyber512Keypair::generate())
        }
    };

    let c_aka_keys = match settings_bytes.get(3) {
        Some(0) => CAKAKeys::X25519(X25519Keypair::generate()),
        _ => CAKAKeys::X25519(X25519Keypair::generate()),
    };

    PqTlsSettings {
        pq_signing_keys,
        c_signing_keys,
        pq_aka_keys,
        c_aka_keys
    }
}

pub fn settings_to_bytes(settings: &PqTlsSettings) -> [u8; 8] {
    let mut settings_bytes = [0u8; 8];
    settings_bytes[0] = match settings.pq_signing_keys {
        PqSigningKeys::Dilithium2(_) => 0,
        PqSigningKeys::Dilithium3(_) => 1,
        PqSigningKeys::Dilithium5(_) => 2
    };
    settings_bytes[1] = match settings.c_signing_keys {
        CSigningKeys::Ed25519(_) => 0
    };
    settings_bytes[2] = match settings.pq_aka_keys {
        PqAKAKeys::Kyber512(_) => 0,
        PqAKAKeys::Kyber768(_) => 1,
        PqAKAKeys::Kyber1024(_) => 2,
        PqAKAKeys::FrodoKem1344(_) => 3,
        PqAKAKeys::FrodoKem976(_) => 4,
        PqAKAKeys::FrodoKem640(_) => 5,
    };
    settings_bytes[3] = match settings.c_aka_keys {
        CAKAKeys::X25519(_) => 0
    };


    settings_bytes
}