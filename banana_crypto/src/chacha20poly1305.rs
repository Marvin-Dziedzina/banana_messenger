use aead::OsRng;
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, Error, Key, KeyInit,
    aead::{Aead, AeadMutInPlace, Buffer, Payload, generic_array::GenericArray},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::SharedSecret;
use zeroize::ZeroizeOnDrop;

/// Symmetric encryption.
#[derive(ZeroizeOnDrop)]
pub struct SymmetricEncryption {
    cipher: ChaCha20Poly1305,
}

/// A secret key.
///
/// Never show this anyone! :)
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct SecretKey {
    key: Vec<u8>,
}

/// Ciphertext that stores the encrypted message the nonce and associated data.
#[derive(Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    ciphertext: Vec<u8>,
    aead_context: AeadContext,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AeadContext {
    nonce: Vec<u8>,
    pub aad: Option<Vec<u8>>,
}

impl SymmetricEncryption {
    pub fn new() -> (SecretKey, Self) {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        (
            SecretKey { key: key.to_vec() },
            Self {
                cipher: ChaCha20Poly1305::new(&key),
            },
        )
    }

    /// Encrypt data. Optionally with associated data.
    fn encrypt(&self, bytes: &[u8], aad: Option<&[u8]>) -> Result<Ciphertext, Error> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let payload = Ciphertext::get_payload_from(bytes, aad);
        let ciphertext = self.cipher.encrypt(&nonce, payload)?;

        Ok(Ciphertext {
            ciphertext,
            aead_context: AeadContext {
                nonce: nonce.to_vec(),
                aad: aad.map(|a| a.to_vec()),
            },
        })
    }

    /// Decrypt data.
    fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Vec<u8>, Error> {
        let payload = ciphertext.get_payload();
        let plaintext = self.cipher.decrypt(
            GenericArray::from_slice(&ciphertext.aead_context.nonce),
            payload,
        )?;

        Ok(plaintext)
    }

    /// Encrypt data in place.
    pub fn encrypt_into(
        &mut self,
        aad: Option<&[u8]>,
        buffer: &mut impl Buffer,
    ) -> Result<AeadContext, Error> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let aad_payload = match aad {
            Some(aad) => aad,
            None => b"",
        };
        self.cipher.encrypt_in_place(&nonce, aad_payload, buffer)?;

        Ok(AeadContext {
            nonce: nonce.to_vec(),
            aad: aad.map(|a| a.to_vec()),
        })
    }

    /// Decrypt data in place.
    pub fn decrypt_into(
        &mut self,
        aead_context: &AeadContext,
        buffer: &mut impl Buffer,
    ) -> Result<(), Error> {
        self.cipher.decrypt_in_place(
            GenericArray::from_slice(&aead_context.nonce),
            aead_context.get_aad(),
            buffer,
        )
    }
}

impl From<SecretKey> for SymmetricEncryption {
    fn from(key: SecretKey) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key.key)),
        }
    }
}

impl From<&SecretKey> for SymmetricEncryption {
    fn from(key: &SecretKey) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key.key)),
        }
    }
}

impl From<SharedSecret> for SymmetricEncryption {
    fn from(shared_secret: SharedSecret) -> Self {
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"", &mut okm)
            .expect("Failed to expand key with HKDF");

        Self::from(SecretKey { key: okm.to_vec() })
    }
}

impl Ciphertext {
    pub fn get_payload(&self) -> Payload {
        Self::get_payload_from(&self.ciphertext, self.aead_context.aad.as_deref())
    }

    pub fn get_payload_from<'a>(msg: &'a [u8], aad: Option<&'a [u8]>) -> Payload<'a, 'a> {
        match aad {
            Some(aad) => Payload { msg, aad },
            None => Payload::from(msg),
        }
    }
}

impl AeadContext {
    pub fn get_aad(&self) -> &[u8] {
        match &self.aad {
            Some(aad) => &aad,
            None => b"",
        }
    }
}

#[cfg(test)]
mod test_chacha20poly1305 {
    #[allow(unused)]
    use super::{Ciphertext, SecretKey, SymmetricEncryption};

    #[test]
    fn crypto() {
        let message = b"Test message".to_vec();

        let (key, chacha1) = SymmetricEncryption::new();
        let ciphertext = chacha1.encrypt(&message, None).unwrap();

        let chacha2 = SymmetricEncryption::from(&key);
        let cleartext = chacha2.decrypt(&ciphertext).unwrap();

        assert_eq!(cleartext, message);
    }

    #[test]
    fn crypto_fail() {
        let message = b"Test message".to_vec();

        let (key, chacha1) = SymmetricEncryption::new();
        let mut ciphertext = chacha1.encrypt(&message, None).unwrap();

        ciphertext.ciphertext.push(0);

        let chacha2 = SymmetricEncryption::from(&key);
        assert!(chacha2.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn crypto_aad() {
        let message = b"Test message".to_vec();
        let aad = b"Test AAD".to_vec();

        let (key, chacha1) = SymmetricEncryption::new();
        let ciphertext = chacha1.encrypt(&message, Some(&aad)).unwrap();

        let chacha2 = SymmetricEncryption::from(&key);
        let cleartext = chacha2.decrypt(&ciphertext).unwrap();

        assert_eq!(cleartext, message);
        assert_eq!(ciphertext.aead_context.aad.unwrap(), aad);
    }

    #[test]
    fn crypto_aad_fail() {
        let message = b"Test message".to_vec();
        let aad = b"Test AAD".to_vec();

        let (key, chacha1) = SymmetricEncryption::new();
        let mut ciphertext = chacha1.encrypt(&message, Some(&aad)).unwrap();

        ciphertext.aead_context.aad = Some(b"Other AAD".to_vec());

        let chacha2 = SymmetricEncryption::from(&key);
        assert!(chacha2.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn crypto_inplace() {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.append(&mut b"MyTestBuffer123".to_vec());

        let original_buf = buffer.clone();

        let (key, mut chacha1) = SymmetricEncryption::new();
        let aead_context = chacha1.encrypt_into(None, &mut buffer).unwrap();

        let mut chacha2 = SymmetricEncryption::from(&key);
        assert!(chacha2.decrypt_into(&aead_context, &mut buffer).is_ok());

        assert_eq!(buffer, original_buf);
    }

    #[test]
    fn crypto_inplace_fail() {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.append(&mut b"MyTestBuffer123".to_vec());

        let (mut key, mut chacha1) = SymmetricEncryption::new();
        let aead_context = chacha1.encrypt_into(None, &mut buffer).unwrap();

        key.key[0] = if key.key[0] != 0 { 0 } else { 1 };

        let mut chacha2 = SymmetricEncryption::from(&key);
        assert!(chacha2.decrypt_into(&aead_context, &mut buffer).is_err());
    }

    #[test]
    fn crypto_inplace_aad() {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.append(&mut b"MyTestBuffer123".to_vec());

        let aad = b"Test AAD";

        let original_buf = buffer.clone();

        let (key, mut chacha1) = SymmetricEncryption::new();
        let aead_context = chacha1.encrypt_into(Some(aad), &mut buffer).unwrap();

        let mut chacha2 = SymmetricEncryption::from(&key);
        assert!(chacha2.decrypt_into(&aead_context, &mut buffer).is_ok());

        assert_eq!(buffer, original_buf);
    }

    #[test]
    fn crypto_inplace_aad_fail() {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.append(&mut b"MyTestBuffer123".to_vec());

        let aad = b"Test AAD";

        let (mut key, mut chacha1) = SymmetricEncryption::new();
        let aead_context = chacha1.encrypt_into(Some(aad), &mut buffer).unwrap();

        key.key[0] = if key.key[0] != 0 { 0 } else { 1 };

        let mut chacha2 = SymmetricEncryption::from(&key);
        assert!(chacha2.decrypt_into(&aead_context, &mut buffer).is_err());
    }
}
