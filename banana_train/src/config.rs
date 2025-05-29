use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub addr: SocketAddr,

    pub keypair_db_path: PathBuf,
    pub users_db_path: PathBuf,
}

impl Config {
    pub fn create(path: &Path) -> anyhow::Result<Self> {
        let default = Self::default();
        fs::write(path, toml::to_string(&default)?)?;

        Ok(default)
    }

    pub fn open(path: &Path) -> anyhow::Result<Self> {
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn try_open(path: &Path) -> anyhow::Result<Self> {
        match Self::open(path) {
            Ok(config) => Ok(config),
            Err(_) => Ok(Self::create(path)?),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 14555)),
            keypair_db_path: PathBuf::from_str("keypair.db")
                .expect("Failed to parse default for keypair db path"),
            users_db_path: PathBuf::from_str("users.db")
                .expect("Failed to parse default for user db path"),
        }
    }
}
