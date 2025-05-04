use std::{error::Error as ErrorTrait, fmt::Display, io};

use bincode::config::BigEndian;
use serde::{Deserialize, Serialize};

mod protocol;

pub mod secure_channel;

fn bincode_config() -> bincode::config::Configuration<BigEndian> {
    bincode::config::standard().with_big_endian()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum NetworkMessage {
    KeepAlive,
    KeepAliveResponse,
    ComponentExchange(banana_crypto::x25519::PublicKey),
    Close,

    Message(banana_crypto::chacha20poly1305::Ciphertext),
}

#[derive(Debug)]
pub enum Error {
    Dead,
    ConnectionNotEstablished,
    ConnectionAlreadyEstablished,
    BincodeEncode(bincode::error::EncodeError),
    BincodeDecode(bincode::error::DecodeError),
    Io(std::io::Error),
    Signature(banana_crypto::ed25519::SignatureError),
    Cipher(banana_crypto::chacha20poly1305::Error),
    TaskJoin(tokio::task::JoinError),
    Elapsed(tokio::time::error::Elapsed),
    Protocol(protocol::Error),
    ShutdownSender(tokio::sync::watch::error::SendError<bool>),
    Receiver(tokio::sync::watch::error::RecvError),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dead => write!(f, "Stream is dead"),
            Self::ConnectionNotEstablished => write!(f, "Connection not established"),
            Self::ConnectionAlreadyEstablished => write!(f, "Connection already established"),
            Self::BincodeEncode(e) => write!(f, "Bincode Encode Error: {}", e),
            Self::BincodeDecode(e) => write!(f, "Bincode Decode Error: {}", e),
            Self::Io(e) => write!(f, "IO Error: {}", e),
            Self::Signature(e) => write!(f, "Signature Error: {}", e),
            Self::Cipher(e) => write!(f, "Cipher Error: {}", e),
            Self::TaskJoin(e) => write!(f, "Task Join Error: {}", e),
            Self::Elapsed(e) => write!(f, "Elapsed Error: {}", e),
            Self::Protocol(e) => write!(f, "Protocol Error: {}", e),
            Self::ShutdownSender(e) => write!(f, "Shutdown Sender Error: {}", e),
            Self::Receiver(e) => write!(f, "Reveiver Error: {}", e),
        }
    }
}

impl ErrorTrait for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<protocol::Error> for Error {
    fn from(e: protocol::Error) -> Self {
        Error::Protocol(e)
    }
}
