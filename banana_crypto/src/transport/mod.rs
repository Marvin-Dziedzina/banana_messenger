use snow::TransportState;

mod handshake;
mod serialisable_keypair;

pub use handshake::*;
pub use serialisable_keypair::*;
use thiserror::Error;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug)]
pub struct Transport {
    transport: TransportState,
}

impl Transport {
    /// Decrypt a message from 'payload` into `message` and return the number of decrypted bytes.
    #[inline]
    pub fn read_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, Error> {
        Ok(self.transport.read_message(payload, message)?)
    }

    /// Encrypt a message from `payload` into `message` and return the number of encrypted bytes.
    #[inline]
    pub fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, Error> {
        Ok(self.transport.write_message(payload, message)?)
    }

    /// Get the remote public key.
    #[inline]
    pub fn remote_public_key(&self) -> PublicKey {
        self.transport
            .get_remote_static()
            .expect("A Transport must have a remote public key")
            .into()
    }

    /// Generate a new [`SerializableKeypair`].
    #[inline]
    pub fn generate_keypair() -> Keypair {
        snow::Builder::new(NOISE_PARAMS.parse().unwrap())
            .generate_keypair()
            .expect("Failed to generate new keypair")
            .into()
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Snow Error: {0}")]
    Snow(#[from] snow::Error),
    #[error("Handshake not done")]
    HandshakeNotDone,
}

#[cfg(test)]
mod test_transport {
    use crate::transport::Transport;

    use super::{Handshake, HandshakeRole, Keypair};

    #[test]
    fn test_transport() {
        let ((mut transport, keypair), (mut other_transport, other_keypair)) =
            get_connected_transport();

        assert_eq!(keypair.public_key, other_transport.remote_public_key());
        assert_eq!(other_keypair.public_key, transport.remote_public_key());

        let mut buf = [0u8; u16::MAX as usize];

        let payload = vec![71, 72, 71];
        let len = transport.write_message(&payload, &mut buf).unwrap();
        let len = other_transport
            .read_message(&buf[..len].to_vec(), &mut buf)
            .unwrap();
        assert_eq!(&buf[..len], payload);

        let len = other_transport.write_message(&payload, &mut buf).unwrap();
        let len = transport
            .read_message(&buf[..len].to_vec(), &mut buf)
            .unwrap();

        assert_eq!(&buf[..len], payload);
    }

    #[test]
    fn test_failed_handshake() {}

    #[test]
    fn test_generate_keypair() {
        let _ = Transport::generate_keypair();
    }

    fn get_connected_transport() -> ((Transport, Keypair), (Transport, Keypair)) {
        let (mut handshake_initiator, initiator_keypair) =
            Handshake::new(None, HandshakeRole::Initiator).unwrap();
        let (mut handshake_responder, responder_keypair) =
            Handshake::new(None, HandshakeRole::Responder).unwrap();

        let mut buf = [0u8; u16::MAX as usize];

        let len = handshake_initiator.write_message(&mut buf).unwrap();

        handshake_responder
            .read_message(&buf[..len].to_vec(), &mut buf)
            .unwrap();
        let len = handshake_responder.write_message(&mut buf).unwrap();

        handshake_initiator
            .read_message(&buf[..len].to_vec(), &mut buf)
            .unwrap();
        let len = handshake_initiator.write_message(&mut buf).unwrap();

        handshake_responder
            .read_message(&buf[..len].to_vec(), &mut buf)
            .unwrap();

        (
            (handshake_initiator.try_into().unwrap(), initiator_keypair),
            (handshake_responder.try_into().unwrap(), responder_keypair),
        )
    }
}
