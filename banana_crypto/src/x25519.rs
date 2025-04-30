use aead::OsRng;
use x25519_dalek::EphemeralSecret;

pub use x25519_dalek::{PublicKey, SharedSecret};

/// Contains both the secret and public components of an X25519 key exchange.
///
/// The public component should be shared with the other party, and their public component should be received in return.
/// Use [`KeyExchange::compute_shared_secret`] with the received public component to compute a [`SharedSecret`].
/// Once both parties perform this computation, they will derive the same shared secret.
pub struct KeyExchange {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl KeyExchange {
    /// Generate a new secret and public component.
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        Self { secret, public }
    }

    /// Get the public component.
    pub fn get_public(&self) -> PublicKey {
        self.public
    }

    /// Generates a [`SharedSecret`] from the other party's public key component.
    ///
    /// The resulting [`SharedSecret`] can be used as a cryptographic key, but must first be parsed.
    /// Parsing is required to ensure the secret is suitable and secure for cryptographic use.
    pub fn compute_shared_secret(self, other_public: PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(&other_public)
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
