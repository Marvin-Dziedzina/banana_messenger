use std::ops::{Deref, DerefMut};

use error::Error;
use serde::{Serialize, de::DeserializeOwned};
use sled::Db;
use tree::SledTree;

pub mod error;
pub mod tree;

#[derive(Debug, Clone)]
pub struct SledDb {
    db: Db,
    default_tree: SledTree,
}

impl SledDb {
    pub fn open<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<std::path::Path>,
    {
        let db = sled::open(path)?;
        let default_tree = SledTree::from(db.deref().clone());
        Ok(Self { db, default_tree })
    }

    #[inline]
    pub fn insert<K, V>(&self, key: &K, value: &V) -> Result<Option<V>, Error>
    where
        K: Serialize + DeserializeOwned,
        V: Serialize + DeserializeOwned,
    {
        self.get_default_tree().insert(key, value)
    }

    #[inline]
    pub fn get<K, V>(&self, key: &K) -> Result<Option<V>, Error>
    where
        K: Serialize + DeserializeOwned,
        V: Serialize + DeserializeOwned,
    {
        self.get_default_tree().get(key)
    }

    #[inline]
    pub fn flush(&self) -> Result<(), Error> {
        self.get_default_tree().flush()
    }

    #[inline]
    pub fn open_tree<V>(&self, name: V) -> Result<SledTree, Error>
    where
        V: AsRef<[u8]>,
    {
        Ok(self.db.open_tree(name)?.into())
    }

    #[inline]
    pub fn get_default_tree(&self) -> &SledTree {
        &self.default_tree
    }
}

impl From<sled::Db> for SledDb {
    fn from(db: sled::Db) -> Self {
        let default_tree = SledTree::from(db.deref().clone());
        Self { db, default_tree }
    }
}

impl From<SledDb> for sled::Db {
    fn from(db: SledDb) -> Self {
        db.db
    }
}

impl Deref for SledDb {
    type Target = Db;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl DerefMut for SledDb {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.db
    }
}

#[cfg(test)]
mod tests {
    // use super::*;
}
