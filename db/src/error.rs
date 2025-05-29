use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Sled Error: {0}")]
    Sled(#[from] sled::Error),
    #[error("Bincode Encode Error: {0}")]
    BincodeEncode(#[from] bincode::error::EncodeError),
    #[error("Bincode Decode Error: {0}")]
    BincodeDecode(#[from] bincode::error::DecodeError),
}
