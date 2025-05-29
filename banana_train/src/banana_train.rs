use std::{collections::HashMap, path::PathBuf};

use banana_crypto::transport::PublicKey;
use db::SledDb;
use netwrk::{Listener, ReliableStream};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::{BananaMessage, config::Config};

const MAX_BUFFERED_CONNECTIONS: usize = 10;
const MAX_BUFFERED_MESSAGES: usize = 32;

const KEYPAIR_KEY: &str = "keypair";

#[derive(Debug)]
pub struct BananaTrain {
    config: Config,

    users_db: SledDb,

    listener: Option<Listener<BananaMessage>>,
    streams: HashMap<PublicKey, ReliableStream<BananaMessage>>,
}

impl BananaTrain {
    pub async fn new(config_path: PathBuf) -> Self {
        let config = Config::try_open(&config_path).expect("Failed to read config");

        let keypair_db =
            SledDb::open(&config.keypair_db_path).expect("Failed to access keypair db");

        let (listener, keypair) = Listener::bind(
            &config.addr,
            keypair_db
                .get(&KEYPAIR_KEY.to_owned())
                .expect("Failed to read keypair"),
            MAX_BUFFERED_MESSAGES,
            MAX_BUFFERED_CONNECTIONS,
        )
        .await
        .expect("Could not bind listener");

        keypair_db
            .insert(&KEYPAIR_KEY.to_owned(), &keypair)
            .expect("Failed to save keypair");
        keypair_db.flush().expect("Failed to flush keypair db");

        let users_db = SledDb::open(&config.users_db_path).expect("Failed to open users db");

        Self {
            config,
            users_db,
            listener: Some(listener),
            streams: HashMap::new(),
        }
    }

    pub async fn run(self) -> Result<(), anyhow::Error> {
        info!("Starting BananaTrain...");

        let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);

        // Spawn shutdown listener
        {
            tokio::spawn(async move {
                Self::shutdown_signal().await;

                match shutdown_tx.send(()) {
                    Ok(_) => info!("Shutting down"),
                    Err(_) => warn!("Failed to send shutdown signal"),
                };
            });
        }

        info!("BananaTrain started");
        loop {
            tokio::task::yield_now().await;

            tokio::select! {
                _ = shutdown_rx.recv() => {
                    return self.shutdown().await;
                }
            };
        }
    }

    async fn shutdown(mut self) -> Result<(), anyhow::Error> {
        if let Some(listener) = std::mem::take(&mut self.listener) {
            let streams = listener.close().await?;
            for (stream, _) in streams {
                self.streams
                    .insert(stream.remote_public_key().await, stream);
            }
        };

        for (public_key, stream) in std::mem::take(&mut self.streams) {
            let (_, remaining) = match stream.close().await {
                Ok(res) => res,
                Err(e) => {
                    warn!("Failed to close stream from {}: {}", public_key, e);
                    continue;
                }
            };

            let messages = match remaining {
                Some(messages) => messages,
                None => continue,
            };

            for msg in messages {
                match self.process_message(msg).await {
                    Ok(_) => (),
                    Err(e) => {
                        warn!("Failed to process message: {}", e);
                    }
                };
            }
        }

        if let Err(e) = self.users_db.flush() {
            warn!("Failed to flush user db: {}", e);
        };

        Ok(())
    }

    async fn process_message(&mut self, msg: BananaMessage) -> Result<(), anyhow::Error> {
        todo!()
    }

    async fn shutdown_signal() {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal handler");

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = signal.recv() => {}
        }

        debug!("Shutdown signal received");
    }
}
