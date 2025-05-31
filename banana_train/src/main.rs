use std::{path::PathBuf, str::FromStr};

use banana_train::BananaTrain;

mod banana_train;
mod config;
mod error;
mod message;
mod tasks;

const CONFIG_PATH: &str = "banana_train.conf";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt::init();

    let config_path = PathBuf::from_str(CONFIG_PATH).expect("Failed to get config path");

    BananaTrain::new(config_path).await.run().await
}
