use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use listener::Listener;
pub use reliable_stream::ReliableStream;

pub mod encrypted_socket;
pub mod listener;
pub mod reliable_stream;

const VERSION_MAJOR_MINOR: &str = env!("VERSION_MAJOR_MINOR");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "M: for<'a> Deserialize<'a>"))]
enum NetworkMessage<M>
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

#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum Reason {
    /// Normal disconnect
    #[error("Disconnect")]
    Disconnect,
    #[error("Version Mismatch")]
    VersionMismatch,
    /// Timeout. No message received for too long.
    #[error("Timout")]
    Timeout,
    #[error("Dead")]
    Dead,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Snow Error: {0}")]
    Snow(#[from] snow::Error),
    #[error("Bincode Encoding Error: {0}")]
    BincodeEncode(#[from] bincode::error::EncodeError),
    #[error("Bincode Decoding Error: {0}")]
    BincodeDecode(#[from] bincode::error::DecodeError),
    #[error("Tokio Join Error: {0}")]
    TokioJoinError(#[from] tokio::task::JoinError),
    #[error("Transport Error: {0}")]
    TransportError(#[from] banana_crypto::transport::Error),
    #[error("Unexpected End Of File")]
    EOF,
    #[error("Dead")]
    Dead,
    #[error("Already Running")]
    AlreadyRunning,
    #[error("Not Running")]
    NotRunning,
}

fn encode<T>(message: T) -> Result<Vec<u8>, Error>
where
    T: Serialize + for<'a> Deserialize<'a>,
{
    Ok(bincode::serde::encode_to_vec(message, bincode_config())?)
}

fn decode<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: Serialize + for<'a> Deserialize<'a>,
{
    Ok(
        bincode::serde::borrow_decode_from_slice(bytes, bincode_config())
            .map(|(message, _)| message)?,
    )
}

const fn bincode_config() -> bincode::config::Configuration<bincode::config::BigEndian> {
    bincode::config::standard().with_big_endian()
}

fn get_atomic_bool(atomic_bool: &Arc<AtomicBool>) -> bool {
    atomic_bool.load(Ordering::Acquire)
}

fn set_atomic_bool(atomic_bool: &Arc<AtomicBool>, v: bool) {
    atomic_bool.store(v, Ordering::Release);
}

#[cfg(test)]
pub mod netwrk_test {
    use std::sync::Once;

    static INIT_LOGGER: Once = Once::new();

    pub fn init_logger() {
        INIT_LOGGER.call_once(|| {
            tracing_subscriber::fmt::init();
        });
    }
}
