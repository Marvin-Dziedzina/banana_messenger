use aead::OsRng;
use x25519_dalek::EphemeralSecret;

pub use x25519_dalek::{PublicKey, SharedSecret};

pub struct KeyExchange {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl KeyExchange {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        Self { secret, public }
    }

    pub fn get_public(&self) -> PublicKey {
        self.public
    }

    pub fn compute_shared_secret(self, public: PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(&public)
    }
}

impl From<EphemeralSecret> for KeyExchange {
    fn from(ephemeral_secret: EphemeralSecret) -> Self {
        let public = PublicKey::from(&ephemeral_secret);
        Self {
            secret: ephemeral_secret,
            public,
        }
    }
}

#[cfg(test)]
mod test_x25519 {
    use super::KeyExchange;

    #[test]
    fn key_exchange() {
        let exchange1 = KeyExchange::new();
        let exchange2 = KeyExchange::new();

        let pub1 = exchange1.get_public();
        let pub2 = exchange2.get_public();

        assert_ne!(exchange1.public, exchange2.public);
        assert_eq!(exchange1.public, pub1);
        assert_eq!(exchange2.public, pub2);

        let shared1 = exchange1.compute_shared_secret(pub2);
        let shared2 = exchange2.compute_shared_secret(pub1);

        assert_eq!(shared1.to_bytes(), shared2.to_bytes());
    }
}
