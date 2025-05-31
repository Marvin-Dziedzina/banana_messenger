use std::{collections::HashMap, sync::Arc};

use banana_crypto::transport::PublicKey;
use common::BananaMessage;
use db::tree::SledTree;
use netwrk::{Listener, ReliableStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::{
    banana_train::{ArcMutex, ArcRwLock, BananaTrain, Status},
    error::Error,
};

impl BananaTrain {
    pub(crate) async fn listener(
        status: ArcRwLock<Status>,
        message_db: SledTree,
        listener: ArcMutex<Listener<BananaMessage>>,
        streams: ArcRwLock<HashMap<PublicKey, ArcMutex<ReliableStream<BananaMessage>>>>,
    ) -> Result<(), anyhow::Error> {
        let addr = listener
            .lock()
            .await
            .local_address()
            .await
            .expect("Failed to get local listener address");
        info!("Listening to {}:{}", addr.ip(), addr.port());

        loop {
            match *status.read().await {
                Status::Run => (),
                Status::Pause => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Status::ShuttingDown => {
                    return Ok(());
                }
            };

            let stream = match listener.lock().await.try_accept().await {
                Ok(Some((stream, _))) => Arc::new(Mutex::new(stream)),
                Ok(None) => continue,
                Err(netwrk::Error::Dead) => continue,
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            let public_key = {
                let mut stream_lock = stream.lock().await;
                let public_key = stream_lock.remote_public_key().await;
                match Self::forward_stored_messages(&stream, &message_db, &public_key).await {
                    Err(Error::Dead) => {
                        if let Err(e) = stream_lock.close().await {
                            warn!("Failed to close dead stream is listener: {}", e);
                        };
                    }
                    Err(e) => {
                        warn!("Failed to downcast error in listener: {}", e);
                    }
                    _ => (),
                };

                public_key
            };

            if let Some(stream) = streams.write().await.insert(public_key, stream.clone()) {
                error!("A client that was still connected, connected again");
                if let Err(e) = stream.lock().await.close().await {
                    warn!("Failed to close the duplicate connection: {}", e);
                };
            };
        }
    }
}
