use std::collections::HashMap;

use banana_crypto::transport::PublicKey;
use common::{BananaMessage, SenderPublicKey};
use tracing::{debug, error, trace, warn};

use crate::banana_train::{ArcMutex, ArcRwLock, BananaTrain, Status, Stream};

impl BananaTrain {
    pub(crate) async fn stream_processor(
        status: ArcRwLock<Status>,
        streams: ArcRwLock<HashMap<PublicKey, ArcMutex<Stream>>>,
        message_channel_sender: tokio::sync::mpsc::Sender<(SenderPublicKey, BananaMessage)>,
        stream_processor_done_sender: tokio::sync::oneshot::Sender<()>,
    ) -> Result<(), anyhow::Error> {
        loop {
            match *status.read().await {
                Status::Run => (),
                Status::Pause => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Status::ShuttingDown => {
                    trace!("Shutting down stream handler");
                    let drained_streams: Vec<(PublicKey, ArcMutex<Stream>)> =
                        streams.write().await.drain().collect();
                    for (sender_public_key, stream) in drained_streams.iter() {
                        let (_, remaining) = match stream.lock().await.close().await {
                            Ok(res) => res,
                            Err(e) => {
                                warn!("Failed to close stream: {}", e);
                                continue;
                            }
                        };

                        let remaining = match remaining {
                            Some(remaining) => remaining,
                            None => continue,
                        };

                        trace!(
                            "{} Reamaining Messages: {}",
                            sender_public_key,
                            remaining.len()
                        );

                        for remain in remaining {
                            if let Err(e) = message_channel_sender
                                .send((sender_public_key.clone(), remain))
                                .await
                            {
                                error!("Failed to send remaining message to processor: {}", e);
                                continue;
                            };
                        }
                    }

                    if stream_processor_done_sender.send(()).is_err() {
                        error!("Failed to send the stream_processor done signal");
                        panic!("Failed to send the stream_processor done signal");
                    };

                    debug!("Stream processor is shutdown");
                    return Ok(());
                }
            };

            for (sender_public_key, stream) in Self::get_streams(&streams).await.iter() {
                let batch = match stream.lock().await.try_receive_batch() {
                    Some(batch) => batch,
                    None => {
                        trace!("Nothing to read from {}", sender_public_key);
                        continue;
                    }
                };

                trace!("Got {} messages from {}", batch.len(), sender_public_key);

                for msg in batch {
                    if let Err(e) = message_channel_sender
                        .send((sender_public_key.clone(), msg))
                        .await
                    {
                        error!("Failed to send message to processor: {}", e);
                        continue;
                    };
                }
            }
        }
    }
}
