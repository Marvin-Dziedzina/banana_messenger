use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SerializableKeypair {
    pub private: Vec<u8>,
    #[zeroize(skip)]
    pub public: Vec<u8>,
}
impl From<snow::Keypair> for SerializableKeypair {
    fn from(keypair: snow::Keypair) -> Self {
        Self {
            private: keypair.private,
            public: keypair.public,
        }
    }
}

impl From<SerializableKeypair> for snow::Keypair {
    fn from(ser_keypair: SerializableKeypair) -> Self {
        Self {
            private: ser_keypair.private.clone(),
            public: ser_keypair.public.clone(),
        }
    }
}
