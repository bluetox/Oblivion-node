use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendCypherText {
    pub data: CypherData,
    pub signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CypherData {
    pub r#type: String,
    pub dst: String,
    pub ct: String,
    pub kpk: String,
    pub publicKey: String,
    pub ts: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendKyberKey {
    pub data: KyberData,
    pub signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KyberData {
    pub r#type: String,
    pub dst: String,
    pub kpk: String,
    pub publicKey: String,
    pub ts: String,
}

#[derive(Serialize, Deserialize)]
pub struct ForwardMessage {
    pub data: MessageData,
    pub signature: String,
}
#[derive(Serialize, Deserialize)]
pub struct MessageData {
    pub r#type: String,
    pub dst: String,
    pub msg: String,
    pub publicKey: String,
    pub ts: String,
}

#[derive(Serialize, Deserialize)]
pub struct InputData {
    pub r#type: String, 
    pub publicKey: String,
    pub ts: String,
    pub ip: String,
}

#[derive(Serialize, Deserialize)]
pub struct Input {
    pub signature: String,
    pub data: InputData,
}

#[derive(Serialize, Deserialize)]
pub struct Output {
    pub valid: bool,
    pub hashedPublicKey: String,
}
