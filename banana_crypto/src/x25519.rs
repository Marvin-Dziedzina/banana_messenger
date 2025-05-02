use aead::OsRng;
use x25519_dalek::EphemeralSecret;

pub use x25519_dalek::{PublicKey, SharedSecret};

/// Contains both the secret and public components of an X25519 key exchange.
///
/// The public component should be shared with the other party, and their public component should be received in return.
/// Use [`KeyExchange::compute_shared_secret`] with the received public component to compute a [`SharedSecret`].
/// Once both parties perform this computation, they will derive the same shared secret.
///
/// # Example
///
/// ```
/// use crate::banana_crypto::x25519::KeyExchange;
///
/// let exchange1 = KeyExchange::new();
/// let exchange2 = KeyExchange::new();
///
/// let pub1 = exchange1.get_public_component();
/// let pub2 = exchange2.get_public_component();
///
/// let shared1 = exchange1.compute_shared_secret(pub2);
/// let shared2 = exchange2.compute_shared_secret(pub1);
///
/// assert_eq!(shared1.to_bytes(), shared2.to_bytes());
/// ```
pub struct KeyExchange {
    secret_component: EphemeralSecret,
    public_component: PublicKey,
}

impl KeyExchange {
    /// Generate a new secret and public component.
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        Self {
            secret_component: secret,
            public_component: public,
        }
    }

    /// Get the public component.
    pub fn get_public_component(&self) -> PublicKey {
        self.public_component
    }

    /// Generates a [`SharedSecret`] from the other party's public key component.
    ///
    /// The resulting [`SharedSecret`] can be used as a cryptographic key, but must first be parsed.
    /// Parsing is required to ensure the secret is suitable and secure for cryptographic use.
    pub fn compute_shared_secret(self, other_public_component: PublicKey) -> SharedSecret {
        self.secret_component
            .diffie_hellman(&other_public_component)
    }
}

impl From<EphemeralSecret> for KeyExchange {
    fn from(ephemeral_secret: EphemeralSecret) -> Self {
        let public = PublicKey::from(&ephemeral_secret);
        Self {
            secret_component: ephemeral_secret,
            public_component: public,
        }
    }
}

impl Default for KeyExchange {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test_x25519 {
    use super::KeyExchange;

    #[test]
    fn key_exchange() {
        let exchange1 = KeyExchange::new();
        let exchange2 = KeyExchange::new();

        let pub1 = exchange1.get_public_component();
        let pub2 = exchange2.get_public_component();

        assert_ne!(exchange1.public_component, exchange2.public_component);
        assert_eq!(exchange1.public_component, pub1);
        assert_eq!(exchange2.public_component, pub2);

        let shared1 = exchange1.compute_shared_secret(pub2);
        let shared2 = exchange2.compute_shared_secret(pub1);

        assert_eq!(shared1.to_bytes(), shared2.to_bytes());
    }
}
