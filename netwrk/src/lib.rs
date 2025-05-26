use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub mod inner_stream;
pub mod listener;
pub mod serialisable_keypair;
pub mod stream;

type FramedStream = Framed<TcpStream, LengthDelimitedCodec>;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

const MESSAGE_PROCESSING_INTERVALL: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "M: for<'a> Deserialize<'a>"))]
pub enum NetwrkMessage<M>
where
    M: Serialize + for<'a> Deserialize<'a>,
{
    Disconnect,

    Message(M),
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
    NotAvailable,
}

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
        write!(f, "Netwrk Error: {{ ")?;
        match self {
            Self::Io(e) => write!(f, "IO Error: {}", e),
            Self::Snow(e) => write!(f, "Snow Error: {}", e),
            Self::BincodeEncode(e) => write!(f, "Bincode Encode Error: {}", e),
            Self::BincodeDecode(e) => write!(f, "Bincode Decode Error: {}", e),
            Self::TokioJoinError(e) => write!(f, "Tokio Join Error: {}", e),
            Self::EOF => write!(f, "EOF"),
            Self::Dead => write!(f, "Dead"),
            Self::NotAvailable => write!(f, "Not avialable"),
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

fn bincode_config() -> bincode::config::Configuration<bincode::config::BigEndian> {
    bincode::config::standard().with_big_endian()
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
