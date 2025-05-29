use std::ops::{Deref, DerefMut};

use error::Error;
use serde::{Deserialize, Serialize};
use sled::Db;

pub mod error;

pub struct SledDb {
    db: Db,
}

impl SledDb {
    pub fn open<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<std::path::Path>,
    {
        Ok(Self {
            db: sled::open(path)?,
        })
    }

    pub fn insert<K, V>(&self, key: &K, value: &V) -> Result<Option<V>, Error>
    where
        K: Serialize + for<'a> Deserialize<'a>,
        V: Serialize + for<'a> Deserialize<'a>,
    {
        match self.db.insert(Self::encode(key)?, Self::encode(value)?)? {
            Some(bytes) => Ok(Self::decode(&bytes)?),
            None => Ok(None),
        }
    }

    pub fn get<K, V>(&self, key: &K) -> Result<Option<V>, Error>
    where
        K: Serialize + for<'a> Deserialize<'a>,
        V: Serialize + for<'a> Deserialize<'a>,
    {
        match self.db.get(Self::encode(key)?)? {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn encode<T>(v: T) -> Result<Vec<u8>, Error>
    where
        T: Serialize,
    {
        Ok(bincode::serde::encode_to_vec(v, Self::bincode_config())?)
    }

    pub fn decode<T>(bytes: &[u8]) -> Result<T, Error>
    where
        T: for<'a> Deserialize<'a>,
    {
        Ok(
            bincode::serde::borrow_decode_from_slice(bytes, Self::bincode_config())
                .map(|(x, _)| x)?,
        )
    }

    fn bincode_config() -> bincode::config::Configuration {
        bincode::config::standard()
    }
}

impl Deref for SledDb {
    type Target = Db;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl DerefMut for SledDb {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
