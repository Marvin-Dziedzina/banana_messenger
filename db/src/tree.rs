use std::ops::{Deref, DerefMut};

use serde::{Serialize, de::DeserializeOwned};

use crate::error::Error;

#[derive(Debug, Clone)]
pub struct SledTree {
    tree: sled::Tree,
}

impl SledTree {
    pub fn insert<K, V>(&self, key: &K, value: &V) -> Result<Option<V>, Error>
    where
        K: Serialize + DeserializeOwned,
        V: Serialize + DeserializeOwned,
    {
        match self.tree.insert(Self::encode(key)?, Self::encode(value)?)? {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn get<K, V>(&self, key: &K) -> Result<Option<V>, Error>
    where
        K: Serialize + DeserializeOwned,
        V: Serialize + DeserializeOwned,
    {
        match self.tree.get(Self::encode(key)?)? {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn remove<K, V>(&self, key: &K) -> Result<Option<V>, Error>
    where
        K: Serialize + DeserializeOwned,
        V: Serialize + DeserializeOwned,
    {
        match self.tree.remove(Self::encode(key)?)? {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn flush(&self) -> Result<(), Error> {
        self.tree.flush()?;

        Ok(())
    }

    pub fn encode<T>(v: T) -> Result<Vec<u8>, Error>
    where
        T: Serialize,
    {
        Ok(bincode::serde::encode_to_vec(v, Self::bincode_config())?)
    }

    pub fn decode<T>(bytes: &[u8]) -> Result<T, Error>
    where
        T: DeserializeOwned,
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

impl From<sled::Tree> for SledTree {
    fn from(tree: sled::Tree) -> Self {
        Self { tree }
    }
}

impl From<SledTree> for sled::Tree {
    fn from(tree: SledTree) -> Self {
        tree.tree
    }
}

impl Deref for SledTree {
    type Target = sled::Tree;

    fn deref(&self) -> &Self::Target {
        &self.tree
    }
}

impl DerefMut for SledTree {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tree
    }
}
