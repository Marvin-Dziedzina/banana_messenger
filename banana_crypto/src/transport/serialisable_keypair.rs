use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keypair {
    pub private: PrivateKey,
    pub public: PublicKey,
}
impl From<snow::Keypair> for Keypair {
    fn from(keypair: snow::Keypair) -> Self {
        Self {
            private: keypair.private.into(),
            public: keypair.public.into(),
        }
    }
}

impl From<Keypair> for snow::Keypair {
    fn from(ser_keypair: Keypair) -> Self {
        Self {
            private: ser_keypair.private.into(),
            public: ser_keypair.public.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PrivateKey(Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(Vec<u8>);

impl From<&[u8]> for PrivateKey {
    /// Clones the slice and constructs a [`Private`].
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
}

impl From<Vec<u8>> for PrivateKey {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<PrivateKey> for Vec<u8> {
    fn from(mut v: PrivateKey) -> Self {
        std::mem::take(&mut v.0)
    }
}

impl From<&[u8]> for PublicKey {
    /// Clones the slice and constructs a [`Public`].
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
}

impl From<Vec<u8>> for PublicKey {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<PublicKey> for Vec<u8> {
    fn from(mut v: PublicKey) -> Self {
        std::mem::take(&mut v.0)
    }
}
