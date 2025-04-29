use sha2::{Digest, Sha256};

pub struct Sha2;

impl Sha2 {
    pub fn sha256(msg: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(msg);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod test_sha2 {
    use super::Sha2;

    const MESSAGE: &[u8] = b"Test Message";

    #[test]
    fn sha256() {
        Sha2::sha256(MESSAGE);
    }
}
