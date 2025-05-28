use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use serde::{Deserialize, Serialize};

pub mod encrypted_socket;
pub mod listener;
pub mod reliable_stream;
pub mod serialisable_keypair;

const VERSION_MAJOR_MINOR: &str = env!("VERSION_MAJOR_MINOR");

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "M: for<'a> Deserialize<'a>"))]
pub enum NetworkMessage<M>
where
    M: Serialize + for<'a> Deserialize<'a>,
{
    Message(M),

    Version(String),

    /// The [`std::time::Instant`] timestamp when Ping was sent.
    Ping(u128),
    /// The [`std::time::Instant`] timestamp when Ping was sent.
    Pong(u128),

    Disconnect(Reason),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Reason {
    /// Normal disconnect
    Disconnect,
    VersionMismatch,
    /// Timeout. No message received for too long.
    Timeout,
    Dead,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Snow(snow::Error),
    BincodeEncode(bincode::error::EncodeError),
    BincodeDecode(bincode::error::DecodeError),
    TokioJoinError(tokio::task::JoinError),
    EOF,
    Dead,
    AlreadyRunning,
    NotRunning,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnect => write!(f, "Disconnect"),
            Self::VersionMismatch => write!(f, "Version mismatch"),
            Self::Timeout => write!(f, "Timeout"),
            Self::Dead => write!(f, "Dead"),
        }
    }
}

impl std::error::Error for Reason {}

impl From<std::io::Error> for Error {
    fn from(io_error: std::io::Error) -> Self {
        Self::Io(io_error)
    }
}

impl From<snow::Error> for Error {
    fn from(snow_error: snow::Error) -> Self {
        Self::Snow(snow_error)
    }
}

impl From<tokio::task::JoinError> for Error {
    fn from(join_error: tokio::task::JoinError) -> Self {
        Self::TokioJoinError(join_error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Network Error: {{ ")?;
        match self {
            Self::Io(e) => write!(f, "IO Error: {}", e),
            Self::Snow(e) => write!(f, "Snow Error: {}", e),
            Self::BincodeEncode(e) => write!(f, "Bincode Encode Error: {}", e),
            Self::BincodeDecode(e) => write!(f, "Bincode Decode Error: {}", e),
            Self::TokioJoinError(e) => write!(f, "Tokio Join Error: {}", e),
            Self::EOF => write!(f, "EOF"),
            Self::Dead => write!(f, "Dead"),
            Self::AlreadyRunning => write!(f, "Already Running"),
            Self::NotRunning => write!(f, "Not Running"),
        }?;
        write!(f, " }}")
    }
}

impl std::error::Error for Error {}

fn encode<T>(message: T) -> Result<Vec<u8>, Error>
where
    T: Serialize + for<'a> Deserialize<'a>,
{
    bincode::serde::encode_to_vec(message, bincode_config()).map_err(Error::BincodeEncode)
}

fn decode<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: Serialize + for<'a> Deserialize<'a>,
{
    bincode::serde::borrow_decode_from_slice(bytes, bincode_config())
        .map(|(message, _)| message)
        .map_err(Error::BincodeDecode)
}

const fn bincode_config() -> bincode::config::Configuration<bincode::config::BigEndian> {
    bincode::config::standard().with_big_endian()
}

pub fn get_atomic_bool(atomic_bool: &Arc<AtomicBool>) -> bool {
    atomic_bool.load(Ordering::Acquire)
}

fn set_atomic_bool(atomic_bool: &Arc<AtomicBool>, v: bool) {
    atomic_bool.store(v, Ordering::Release);
}

#[cfg(test)]
mod netwrk_test {
    use crate::Error;

    #[test]
    fn test_error() {
        println!(
            "{}",
            Error::Io(std::io::Error::new(std::io::ErrorKind::Other, "Test"))
        );
    }
}
