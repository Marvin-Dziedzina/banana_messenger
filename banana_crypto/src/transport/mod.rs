use snow::TransportState;

mod handshake;
mod serialisable_keypair;

pub use handshake::*;
pub use serialisable_keypair::*;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug)]
pub struct Transport {
    transport: TransportState,
}

impl Transport {
    /// Decrypt a message from 'message' into `payload`.
    pub fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, Error> {
        self.transport
            .read_message(message, payload)
            .map_err(Error::Snow)
    }

    /// Encrypt a message from `payload` into `message`.
    pub fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, Error> {
        self.transport
            .write_message(payload, message)
            .map_err(Error::Snow)
    }

    pub fn remote_public_key(&self) -> Public {
        self.transport
            .get_remote_static()
            .expect("A Transport must have a remote public key")
            .into()
    }

    /// Generate a new [`SerializableKeypair`].
    pub fn generate_keypair() -> SerializableKeypair {
        snow::Builder::new(NOISE_PARAMS.parse().unwrap())
            .generate_keypair()
            .expect("Failed to generate new keypair")
            .into()
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Snow(snow::Error),
    HandshakeNotDone,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "Io Error: {}", e),
            Self::Snow(e) => write!(f, "Snow Error: {}", e),
            Self::HandshakeNotDone => write!(f, "Handshake not done"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<snow::Error> for Error {
    fn from(e: snow::Error) -> Self {
        Self::Snow(e)
    }
}

#[cfg(test)]
mod test_transport {
    use crate::transport::Transport;

    #[tokio::test]
    async fn test_generate_keypair() {
        let _ = Transport::generate_keypair();
    }
}
