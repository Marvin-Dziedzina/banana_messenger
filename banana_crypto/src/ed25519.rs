use aead::OsRng;
use ed25519_dalek::{Signature, SigningKey, ed25519::signature::SignerMut};
use serde::{Deserialize, Serialize};

pub use ed25519_dalek::{SignatureError, VerifyingKey};
use zeroize::ZeroizeOnDrop;

/// The [`KeyPair`] that is used to sign messages and verify [`SignatureBlob`]s.
#[derive(ZeroizeOnDrop)]
pub struct SignerKeyPair {
    signing_key: ed25519_dalek::SigningKey,
}

/// The [`SignatureBlob`] that holds all data needed for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBlob {
    signature: Signature,
    pub msg: Vec<u8>,
}

impl SignerKeyPair {
    pub fn new() -> Self {
        Self {
            signing_key: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    /// Sign a byte array.
    pub fn sign(&mut self, msg: &[u8]) -> SignatureBlob {
        SignatureBlob {
            signature: self.signing_key.sign(msg),
            msg: msg.to_vec(),
        }
    }

    /// Verify a [`SignatureBlob`] with the supplied [`VerifyingKey`].
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        signature_blob: &SignatureBlob,
    ) -> Result<(), SignatureError> {
        verify(verifying_key, signature_blob)
    }

    /// Get the [`VerifyingKey`] from the [`KeyPair`].
    pub fn get_verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

/// Verify a [`SignatureBlob`] with the supplied [`VerifyingKey`].
pub fn verify(
    verifying_key: &VerifyingKey,
    signature_blob: &SignatureBlob,
) -> Result<(), SignatureError> {
    verifying_key.verify_strict(&signature_blob.msg, &signature_blob.signature)
}

impl From<SigningKey> for SignerKeyPair {
    fn from(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }
}

#[cfg(test)]
mod test_ed25519 {
    #[allow(unused)]
    use super::SignerKeyPair;

    #[allow(unused)]
    const MSG: &[u8] = b"Test Message";

    #[test]
    fn key_pair() {
        let mut key_pair = SignerKeyPair::new();
        let signature_blob = key_pair.sign(MSG);

        assert!(
            key_pair
                .verify(&key_pair.get_verifying_key(), &signature_blob)
                .is_ok()
        );
    }

    #[test]
    fn signature_blob() {
        let mut key_pair = SignerKeyPair::new();
        let signature_blob = key_pair.sign(MSG);

        assert_eq!(signature_blob.msg, MSG);
    }

    #[test]
    fn key_pair_fail() {
        let mut key_pair = SignerKeyPair::new();
        let mut signature_blob = key_pair.sign(MSG);

        signature_blob.msg[0] = if signature_blob.msg[0] != 0 { 0 } else { 1 };

        assert!(
            key_pair
                .verify(&key_pair.get_verifying_key(), &signature_blob)
                .is_err()
        );
        assert_ne!(signature_blob.msg, MSG);
    }

    #[test]
    fn verify_outer() {
        let mut key_pair = SignerKeyPair::new();
        let signature_blob = key_pair.sign(MSG);

        assert!(super::verify(&key_pair.get_verifying_key(), &signature_blob).is_ok());
    }

    #[test]
    fn get_verify_key() {
        let key_pair = SignerKeyPair::new();

        assert_eq!(
            key_pair.signing_key.verifying_key(),
            key_pair.get_verifying_key()
        );
    }
}
