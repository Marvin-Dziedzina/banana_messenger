use std::fmt::Display;

use serde::{Deserialize, Serialize};

use super::Transport;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keypair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

impl Default for Keypair {
    /// Generate a new [`Keypair`].
    #[inline]
    fn default() -> Self {
        Transport::generate_keypair()
    }
}

impl From<snow::Keypair> for Keypair {
    #[inline]
    fn from(keypair: snow::Keypair) -> Self {
        Self {
            private_key: keypair.private.into(),
            public_key: keypair.public.into(),
        }
    }
}

impl From<Keypair> for snow::Keypair {
    #[inline]
    fn from(ser_keypair: Keypair) -> Self {
        Self {
            private: ser_keypair.private_key.into(),
            public: ser_keypair.public_key.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PrivateKey(Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(Vec<u8>);

impl From<&[u8]> for PrivateKey {
    /// Clones the slice and constructs a [`Private`].
    #[inline]
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
}

impl From<Vec<u8>> for PrivateKey {
    #[inline]
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<PrivateKey> for Vec<u8> {
    #[inline]
    fn from(mut v: PrivateKey) -> Self {
        std::mem::take(&mut v.0)
    }
}

impl From<&[u8]> for PublicKey {
    /// Clones the slice and constructs a [`Public`].
    #[inline]
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
}

impl From<Vec<u8>> for PublicKey {
    #[inline]
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<PublicKey> for Vec<u8> {
    #[inline]
    fn from(mut v: PublicKey) -> Self {
        std::mem::take(&mut v.0)
    }
}

impl Display for PublicKey {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}
