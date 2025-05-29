use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableKeypair {
    pub private: Private,
    pub public: Public,
}
impl From<snow::Keypair> for SerializableKeypair {
    fn from(keypair: snow::Keypair) -> Self {
        Self {
            private: keypair.private.into(),
            public: keypair.public.into(),
        }
    }
}

impl From<SerializableKeypair> for snow::Keypair {
    fn from(ser_keypair: SerializableKeypair) -> Self {
        Self {
            private: ser_keypair.private.into(),
            public: ser_keypair.public.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Private(Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Public(Vec<u8>);

impl From<&[u8]> for Private {
    /// Clones the slice and constructs a [`Private`].
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
}

impl From<Vec<u8>> for Private {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<Private> for Vec<u8> {
    fn from(mut v: Private) -> Self {
        std::mem::take(&mut v.0)
    }
}

impl From<&[u8]> for Public {
    /// Clones the slice and constructs a [`Public`].
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
}

impl From<Vec<u8>> for Public {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<Public> for Vec<u8> {
    fn from(mut v: Public) -> Self {
        std::mem::take(&mut v.0)
    }
}
