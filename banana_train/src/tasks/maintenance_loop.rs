use std::{collections::HashMap, sync::Arc, time::Duration};

use banana_crypto::transport::PublicKey;
use db::SledDb;
use tracing::{debug, warn};

use crate::{
    banana_train::{ArcMutex, ArcRwLock, BananaTrain, Status, Stream},
    config::Config,
};

impl BananaTrain {
    pub(crate) async fn maintenance_loop(
        status: ArcRwLock<Status>,
        config: Arc<Config>,
        db: SledDb,
        streams: ArcRwLock<HashMap<PublicKey, ArcMutex<Stream>>>,
    ) -> Result<(), anyhow::Error> {
        use std::time::Instant;

        let mut last_save = Instant::now();
        let mut last_prune = Instant::now();
        loop {
            match *status.read().await {
                Status::Run => (),
                Status::Pause => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Status::ShuttingDown => {
                    debug!("Maintenance loop is shutdown");
                    return Ok(());
                }
            };

            // Flush db.
            if last_save.elapsed() >= config.db_save_interval {
                last_save = Instant::now();

                if let Err(e) = db.flush_async().await {
                    warn!("Failed to flush database: {}", e);
                    continue;
                };

                debug!("Database flushed");
            };

            // Prune dead streams.
            if last_prune.elapsed() >= config.connection_prune_interval {
                last_prune = Instant::now();

                let mut connections_to_prune = Vec::new();
                for (public_key, stream) in Self::get_streams(&streams).await.iter() {
                    if stream.lock().await.is_dead() {
                        connections_to_prune.push(public_key.clone());
                    };
                }

                let mut streams_wlock = streams.write().await;
                for public_key in connections_to_prune {
                    match streams_wlock.remove(&public_key) {
                        Some(_) => debug!("Pruned {}", public_key),
                        None => warn!("Failed to prune {}", public_key),
                    };
                }
            };

            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}
