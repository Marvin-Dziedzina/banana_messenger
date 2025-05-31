use std::{collections::HashMap, time::Duration};

use banana_crypto::transport::PublicKey;
use common::{BananaMessage, SenderPublicKey};
use db::tree::SledTree;
use tracing::{debug, error, trace, warn};

use crate::{
    banana_train::{ArcMutex, ArcRwLock, BananaTrain, Status, Stream},
    error::Error,
};

impl BananaTrain {
    pub(crate) async fn process_messages(
        status: ArcRwLock<Status>,
        db: SledTree,
        streams: ArcRwLock<HashMap<PublicKey, ArcMutex<Stream>>>,
        mut message_channel_receiver: tokio::sync::mpsc::Receiver<(SenderPublicKey, BananaMessage)>,
        message_channel_sender: tokio::sync::mpsc::Sender<(SenderPublicKey, BananaMessage)>,
        stream_processor_done_receiver: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), anyhow::Error> {
        loop {
            match *status.read().await {
                Status::Run => (),
                Status::Pause => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Status::ShuttingDown => {
                    trace!("Message processor shutting down");
                    match stream_processor_done_receiver.await {
                        Ok(_) => (),
                        Err(e) => {
                            error!("Failed to receive the stream processor done signal: {}", e);
                        }
                    };

                    // Drop the sender or else the while will forever wait for a value that never comes.
                    drop(message_channel_sender);
                    trace!("Got stream processor done signal");

                    while let Some((sender_public_key, banana_message)) =
                        message_channel_receiver.recv().await
                    {
                        match banana_message {
                            BananaMessage::SendMessage((receiver_public_key, message)) => {
                                trace!(
                                    "Got message from {} for {} while shutting down",
                                    sender_public_key, receiver_public_key
                                );
                                if let Err(e) = Self::insert_message_into_db(
                                    &db,
                                    &receiver_public_key,
                                    sender_public_key.clone(),
                                    message,
                                )
                                .await
                                {
                                    error!(
                                        "Failed to insert messages from {} for {} into database: {}",
                                        sender_public_key, receiver_public_key, e
                                    );
                                };
                            }
                            BananaMessage::ForwardedMessage(_) => {
                                warn!(
                                    "Received forwarded message from {}: Should not happen",
                                    sender_public_key
                                );
                            }
                            BananaMessage::ForwardRequest => {
                                warn!(
                                    "Received forward request from {}: Ignoring",
                                    sender_public_key
                                );
                            }
                        };
                    }

                    debug!("Message processor is shutdown");
                    return Ok(());
                }
            };

            let received_message = tokio::select! {
                received_message =  message_channel_receiver.recv() => {
                    Some(received_message)
                }
                _ = tokio::time::sleep(Duration::from_millis(250)) => {
                    None
                }
            };

            let (sender_public_key, banana_message) = match received_message {
                Some(Some(bundle)) => bundle,
                Some(None) => return Err(Error::ChannelClosed.into()),
                None => continue,
            };

            // Forward messages from `message_channel_receiver` or store them in the `db`.
            match banana_message {
                BananaMessage::SendMessage((receiver_public_key, message)) => {
                    let streams_lock = streams.read().await;

                    let stream = match streams_lock.get(&receiver_public_key) {
                        Some(stream) => stream,
                        None => {
                            trace!(
                                "Message from {} for {} inserted into database",
                                sender_public_key.clone(),
                                receiver_public_key
                            );

                            if let Err(e) = Self::insert_message_into_db(
                                &db,
                                &receiver_public_key,
                                sender_public_key.clone(),
                                message,
                            )
                            .await
                            {
                                warn!(
                                    "Failed to store message from {} for {} in database. Message dropped: {}",
                                    sender_public_key, receiver_public_key, e
                                );
                            };
                            continue;
                        }
                    };

                    match Self::forward_message(
                        stream,
                        &sender_public_key,
                        &receiver_public_key,
                        message.clone(),
                    )
                    .await
                    {
                        Ok(_) => (),
                        Err(Error::Dead) => {
                            if streams.write().await.remove(&receiver_public_key).is_none() {
                                error!("Failed to remove a missing stream while using the stream");
                                return Err(anyhow::Error::msg(
                                    "Failed to remove a missing stream while using the stream",
                                ));
                            };
                        }
                        Err(Error::FailedToForward) => {
                            if let Err(e) = Self::insert_message_into_db(
                                &db,
                                &receiver_public_key,
                                sender_public_key,
                                message,
                            )
                            .await
                            {
                                warn!(
                                    "Failed to store message in database after failing to forward it: {}",
                                    e
                                );
                            };
                            continue;
                        }
                        Err(e) => {
                            warn!(
                                "Failed to forward a message to {}: {}",
                                receiver_public_key, e
                            );
                        }
                    };
                }
                BananaMessage::ForwardedMessage(_) => {
                    warn!("Received forwarded message. Should not happen");
                    continue;
                }
                BananaMessage::ForwardRequest => {
                    let stream = {
                        let streams_rlock = streams.read().await;
                        match streams_rlock.get(&sender_public_key) {
                            Some(stream) => stream.clone(),
                            None => {
                                warn!(
                                    "Failed to find stream corresponding to {}",
                                    sender_public_key
                                );
                                continue;
                            }
                        }
                    };

                    match Self::forward_stored_messages(&stream, &db, &sender_public_key).await {
                        Ok(_) => (),
                        Err(Error::Dead) => {
                            warn!("Stream that requested a stored messages forwading is dead");
                            let mut streams_wlock = streams.write().await;
                            match streams_wlock.remove(&sender_public_key) {
                                Some(stream) => match stream.lock().await.close().await {
                                    Ok((_, messages_option)) => {
                                        if let Some(messages) = messages_option {
                                            for msg in messages {
                                                if let Err(e) = message_channel_sender
                                                    .send((sender_public_key.clone(), msg))
                                                    .await
                                                {
                                                    warn!(
                                                        "Failed to send message into message channel: {}",
                                                        e
                                                    );
                                                };
                                            }
                                        };
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to close stream that requested a stored messages forwarding but it dead: {}",
                                            e
                                        );
                                    }
                                },
                                None => {
                                    warn!(
                                        "Could not find stream that requested a stored message forwarding"
                                    );
                                }
                            };
                        }
                        Err(e) => {
                            warn!(
                                "Failed to forward stored message on request to {}: {}",
                                sender_public_key, e
                            );
                            continue;
                        }
                    };
                }
            };
        }
    }
}
