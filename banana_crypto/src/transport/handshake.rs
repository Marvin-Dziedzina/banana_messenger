/// # Initiator
/// let mut buf = [0u8; 65535];
///
/// // Send ephemeral public key
/// let len = self.write_message(&[], &mut buf)?;
/// stream.send(&buf[..len])?;
///
/// // Receive ephemeral and static public keys
/// let len = stream.read(&mut buf)?;
/// self.read_message(&buf[..len].to_vec(), &mut buf)?;
///
/// // Send static public key
/// let len = self.write_message(&[], &mut buf)?;
/// stream.send(&buf[..len])?;
///
/// let transport = Transport::try_from(self);
///
/// info!("Initiator handshake successful");
///
/// transport
///
///
///
/// # Responder
/// let mut buf = [0u8; 65535];
///
/// // Receive ephemeral public key
/// let len = stream.read(&mut buf)?;
/// self.read_message(&buf[..len].to_vec(), &mut buf)?;
///
/// // Send ephemeral and static public keys
/// let len = self.write_message(&[], &mut buf)?;
/// stream.send(&buf[..len])?;
///
/// // Receive static public key
/// let len = stream.read(&mut buf)?;
/// self.read_message(&buf[..len].to_vec(), &mut buf)?;
///
/// let transport = Transport::try_from(self);
///
/// info!("Responder handshake successful");
///
/// transport
use snow::HandshakeState;

use super::{Error, Keypair, NOISE_PARAMS, Transport};

#[derive(Debug)]
pub struct Handshake {
    handshake: HandshakeState,
    handshake_role: HandshakeRole,
}

impl Handshake {
    /// Build a new Handshake.
    pub fn new(
        keypair: Option<Keypair>,
        handshake_role: HandshakeRole,
    ) -> Result<(Self, Keypair), Error> {
        let builder = snow::Builder::new(NOISE_PARAMS.parse().unwrap());
        let keypair = match keypair {
            Some(ser_keypair) => ser_keypair.into(),
            None => builder.generate_keypair()?,
        };
        let builder = builder.local_private_key(&keypair.private);

        let handshake = match handshake_role {
            HandshakeRole::Responder => builder.build_responder(),
            HandshakeRole::Initiator => builder.build_initiator(),
        }?;

        Ok((
            Self {
                handshake,
                handshake_role,
            },
            Keypair::from(keypair),
        ))
    }

    #[inline]
    pub fn get_handshake_role(&self) -> &HandshakeRole {
        &self.handshake_role
    }

    /// Read the handshake.
    #[inline]
    pub fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, Error> {
        Ok(self.handshake.read_message(message, payload)?)
    }

    /// Write the handshake response.
    #[inline]
    pub fn write_message(&mut self, message: &mut [u8]) -> Result<usize, Error> {
        Ok(self.handshake.write_message(&[], message)?)
    }

    /// Generate a new [`SerializableKeypair`].
    #[inline]
    pub fn generate_keypair() -> Keypair {
        Transport::generate_keypair()
    }
}

impl TryFrom<Handshake> for Transport {
    type Error = Error;

    /// Tries to convert a [`Handshake`] to a [`Transport`].
    ///
    /// # Errors
    ///
    /// Will result in a [`Error::HandshakeNotDone`] error if the handshake is not done.
    /// Will result in a [`Error::Snow`] if the conversion did fail.
    fn try_from(handshake: Handshake) -> Result<Self, Self::Error> {
        if !handshake.handshake.is_handshake_finished() {
            return Err(Error::HandshakeNotDone);
        };

        Ok(Self {
            transport: handshake.handshake.into_transport_mode()?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

#[cfg(test)]
mod test_handshake {}
