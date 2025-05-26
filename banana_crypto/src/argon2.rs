use aead::OsRng;
use argon2::{
    Argon2 as Argon,
    password_hash::{self, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use serde::{Deserialize, Serialize};

pub type Salt = String;

/// Implementation of the Argon2 hashing algorithm.
pub struct Argon2;

/// Represents an Argon2 hash used to verify passwords.
#[derive(Clone, Serialize, Deserialize)]
pub struct Argon2Hash {
    hash: String,
    salt: String,
}

impl Argon2 {
    fn generate_salt() -> SaltString {
        SaltString::generate(&mut OsRng)
    }

    /// Hashes a password using the Argon2 algorithm
    ///
    /// **Do not use to get a cryptographic key. Use [`Self::hash_key_derivation`]**
    pub fn hash(password: &[u8]) -> Result<Argon2Hash, password_hash::Error> {
        let salt = Argon2::generate_salt();
        let hash = Argon::default().hash_password(password, &salt)?;

        Ok(Argon2Hash {
            hash: hash.to_string(),
            salt: salt.to_string(),
        })
    }

    /// Verifies that a password matches the given Argon2 hash.
    pub fn verify(hash: &Argon2Hash, password: &[u8]) -> Result<(), password_hash::Error> {
        let password_hash = PasswordHash::new(&hash.hash)?;
        Argon::default().verify_password(password, &password_hash)
    }

    /// Hashes a password into a buffer of arbitrary size.
    ///
    /// **This function generates an output that can be used as cryptographic key**
    pub fn hash_key_derivation(password: &[u8], out: &mut [u8]) -> Result<Salt, argon2::Error> {
        let salt = Argon2::generate_salt().to_string();
        Argon::default().hash_password_into(password, salt.as_ref(), out)?;

        Ok(salt)
    }
}

#[cfg(test)]
mod test_argon2 {
    #[allow(unused)]
    use super::Argon2;

    #[allow(unused)]
    const PASSWORD: &[u8; 20] = b"MyPerfectPassword123";

    #[test]
    fn hash_and_verify() {
        let hash = Argon2::hash(PASSWORD).unwrap();
        assert!(Argon2::verify(&hash, PASSWORD).is_ok());
    }

    #[test]
    fn hash_and_verify_fail() {
        let hash = Argon2::hash(PASSWORD).unwrap();
        assert!(Argon2::verify(&hash, b"MyWackyPassword123").is_err());
    }

    #[test]
    fn cryptographic_key_hash() {
        let mut crypt_key = [0u8; 32];
        assert!(Argon2::hash_key_derivation(PASSWORD, &mut crypt_key).is_ok());
    }
}
