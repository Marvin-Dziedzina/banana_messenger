use chacha20poly1305::aead::OsRng;
use ed25519::{Signature, signature::SignerMut};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

pub use ed25519_dalek::SignatureError;

/// The [`KeyPair`] that is used to sign messages and verify [`SignatureBlob`]s.
pub struct KeyPair {
    signing_key: ed25519_dalek::SigningKey,
}

/// The [`SignatureBlob`] that holds all data needed for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBlob {
    signature: Signature,
    pub verifying_key: VerifyingKey,
    pub msg: Vec<u8>,
}

impl KeyPair {
    pub fn new() -> Self {
        Self {
            signing_key: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    /// Sign a byte array.
    pub fn sign(&mut self, msg: &[u8]) -> SignatureBlob {
        SignatureBlob {
            signature: self.signing_key.sign(msg),
            verifying_key: self.get_verifying_key(),
            msg: msg.to_vec(),
        }
    }

    /// Verify a [`SignatureBlob`] with the [`SignatureBlob`] internal signing key.
    pub fn verify(&self, signature_blob: &SignatureBlob) -> Result<(), SignatureError> {
        verify(signature_blob)
    }

    /// Get the verifying key from the singing key.
    pub fn get_verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

/// Verify a [`SignatureBlob`] with the [`SignatureBlob`] internal signing key.
pub fn verify(signature_blob: &SignatureBlob) -> Result<(), SignatureError> {
    signature_blob
        .verifying_key
        .verify_strict(&signature_blob.msg, &signature_blob.signature)
}

impl From<SigningKey> for KeyPair {
    fn from(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }
}

mod test_ed25519 {
    #[allow(unused)]
    use super::KeyPair;

    #[allow(unused)]
    const MSG: &[u8] = b"Test Message";

    #[test]
    fn key_pair() {
        let mut key_pair = KeyPair::new();
        let signature_blob = key_pair.sign(MSG);

        assert!(key_pair.verify(&signature_blob).is_ok());
    }

    #[test]
    fn signature_blob() {
        let mut key_pair = KeyPair::new();
        let signature_blob = key_pair.sign(MSG);

        assert_eq!(signature_blob.msg, MSG);
        assert_eq!(signature_blob.verifying_key, key_pair.get_verifying_key());
    }

    #[test]
    fn key_pair_fail() {
        let mut key_pair = KeyPair::new();
        let mut signature_blob = key_pair.sign(MSG);

        signature_blob.msg[0] = if signature_blob.msg[0] != 0 { 0 } else { 1 };

        assert!(key_pair.verify(&signature_blob).is_err());
        assert_ne!(signature_blob.msg, MSG);
    }

    #[test]
    fn verify_outer() {
        let mut key_pair = KeyPair::new();
        let signature_blob = key_pair.sign(MSG);

        assert!(super::verify(&signature_blob).is_ok());
    }

    #[test]
    fn check_verifying_key() {
        let mut key_pair = KeyPair::new();
        let signature_blob = key_pair.sign(MSG);

        assert_eq!(signature_blob.verifying_key, key_pair.get_verifying_key());
    }

    #[test]
    fn get_verify_key() {
        let key_pair = KeyPair::new();

        assert_eq!(
            key_pair.signing_key.verifying_key(),
            key_pair.get_verifying_key()
        );
    }
}
