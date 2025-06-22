use std::{collections::HashMap, path::PathBuf, sync::Arc};

use banana_crypto::transport::PublicKey;
use common::{BananaMessage, ReceiverPublicKey, SenderPublicKey};
use db::{SledDb, tree::SledTree};
use netwrk::{Listener, ReliableStream};
use tokio::{
    sync::{Mutex, RwLock, broadcast},
    task::JoinHandle,
};
use tracing::{debug, error, info, trace, warn};

use crate::{config::Config, error::Error, message::Message};

pub type ArcRwLock<T> = Arc<RwLock<T>>;
pub type ArcMutex<T> = Arc<Mutex<T>>;

pub type TaskHandle = JoinHandle<Result<(), anyhow::Error>>;
pub type Stream = ReliableStream<BananaMessage>;

const KEYPAIR_KEY: &str = "keypair";
const MESSAGES_TREE: &str = "MESSAGES";

#[derive(Debug)]
pub struct BananaTrain {
    status: ArcRwLock<Status>,

    _config: Arc<Config>,

    db: SledDb,

    listener: Option<ArcMutex<Listener<BananaMessage>>>,
    streams: ArcRwLock<HashMap<PublicKey, ArcMutex<Stream>>>,

    listener_handle: TaskHandle,
    general_purpose_processor_handle: TaskHandle,
    stream_processor_handle: TaskHandle,
    message_processor_handle: TaskHandle,
}

impl BananaTrain {
    pub async fn new(config_path: PathBuf) -> Result<Self, anyhow::Error> {
        let config = Arc::new(Config::try_open(&config_path)?);

        let db = SledDb::open(&config.db_path)?;

        let (listener, keypair) = Listener::bind(
            &config.addr,
            db.get(&KEYPAIR_KEY.to_owned())?,
            config.max_buffered_connections,
            config.max_buffered_messages,
        )
        .await?;
        let listener = Arc::new(Mutex::new(listener));

        db.insert(&KEYPAIR_KEY.to_owned(), &keypair)?;
        db.flush()?;

        let streams = Arc::new(RwLock::new(HashMap::new()));

        let status = Arc::new(RwLock::new(Status::Pause));

        let (message_channel_sender, message_channel_receiver) =
            tokio::sync::mpsc::channel(config.max_message_channel_capacity);
        let (stream_processor_done_sender, stream_processor_done_receiver) =
            tokio::sync::oneshot::channel();

        let listener_handle = tokio::spawn(Self::listener(
            status.clone(),
            db.open_tree(MESSAGES_TREE)?,
            listener.clone(),
            streams.clone(),
        ));
        let db_flushing_handler_handle = tokio::spawn(Self::maintenance_loop(
            status.clone(),
            config.clone(),
            db.clone(),
            streams.clone(),
        ));
        let handle_streams_handle = tokio::spawn(Self::stream_processor(
            status.clone(),
            streams.clone(),
            message_channel_sender.clone(),
            stream_processor_done_sender,
        ));
        let message_processor_handle = tokio::spawn(Self::message_processor(
            status.clone(),
            db.open_tree(MESSAGES_TREE)?,
            streams.clone(),
            message_channel_receiver,
            message_channel_sender,
            stream_processor_done_receiver,
        ));

        Ok(Self {
            status,

            _config: config,

            db,

            listener: Some(listener),
            streams,

            listener_handle,
            general_purpose_processor_handle: db_flushing_handler_handle,
            stream_processor_handle: handle_streams_handle,
            message_processor_handle,
        })
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

        *self.status.write().await = Status::Run;
        info!("BananaTrain started");

        tokio::select! {
            _ = shutdown_rx.recv() => {}
        };

        self.shutdown().await
    }

    async fn shutdown(mut self) -> Result<(), anyhow::Error> {
        if let Some(listener) = std::mem::take(&mut self.listener) {
            trace!("Shutting listener down");
            let unprocessed_streams = listener.lock().await.close().await?;
            for (stream, _) in unprocessed_streams {
                self.streams.write().await.insert(
                    stream.remote_public_key().await,
                    Arc::new(Mutex::new(stream)),
                );
            }

            trace!("Listener shutdown");
        };

        *self.status.write().await = Status::ShuttingDown;
        if let Err(e) = self.listener_handle.await {
            error!("Error occured in listener: {}", e);
        };
        trace!("Listener shutdown");

        if let Err(e) = self.general_purpose_processor_handle.await {
            error!("Error occured in general_purpose_processor: {}", e);
        };
        trace!("General purpose processor shutdown");

        if let Err(e) = self.stream_processor_handle.await {
            error!("Error occured in stream_processor: {}", e);
        };
        trace!("Stream processor shutdown");

        if let Err(e) = self.message_processor_handle.await {
            error!("Error occured in message_processor: {}", e);
        };
        trace!("Message processor shutdown");

        if let Err(e) = self.db.flush() {
            warn!("Failed to flush user db: {}", e);
        };
        debug!("Shutdown database flush done");

        Ok(())
    }

    pub(crate) async fn insert_message_into_db(
        db: &SledTree,
        receiver_public_key: &ReceiverPublicKey,
        sender_public_key: SenderPublicKey,
        message: Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        Self::extend_messages_in_db(
            db,
            receiver_public_key,
            vec![Message::new(sender_public_key, message)],
        )
        .await
    }

    pub(crate) async fn extend_messages_in_db(
        db: &SledTree,
        receiver_public_key: &ReceiverPublicKey,
        messages: Vec<Message>,
    ) -> Result<(), anyhow::Error> {
        let mut user_messages = match db.get(receiver_public_key) {
            Ok(Some(user_messages)) => user_messages,
            Ok(None) => Vec::new(),
            Err(e) => {
                error!("Failed to access db. Message dropped: {}", e);
                return Err(e.into());
            }
        };

        user_messages.extend(messages);

        if let Err(e) = db.insert(receiver_public_key, &user_messages) {
            error!(
                "Failed to insert message into database. Message dropped: {}",
                e
            );
            return Err(e.into());
        };

        Ok(())
    }

    pub(crate) async fn forward_message(
        stream: &Arc<Mutex<Stream>>,
        sender_public_key: &SenderPublicKey,
        receiver_public_key: &ReceiverPublicKey,
        message: Vec<u8>,
    ) -> Result<(), Error> {
        match stream
            .lock()
            .await
            .send(BananaMessage::ForwardedMessage((
                sender_public_key.clone(),
                message,
            )))
            .await
        {
            Ok(_) => (),
            Err(netwrk::Error::Dead) => {
                return Err(Error::Dead);
            }
            Err(e) => {
                warn!(
                    "Failed to forward message from {} to {}: {}",
                    sender_public_key, receiver_public_key, e
                );
                return Err(Error::FailedToForward);
            }
        };

        trace!(
            "Message from {} for {} forwarded",
            sender_public_key, receiver_public_key
        );

        Ok(())
    }

    pub(crate) async fn forward_stored_messages(
        stream: &Arc<Mutex<Stream>>,
        db: &SledTree,
        public_key: &PublicKey,
    ) -> Result<(), Error> {
        match db.get::<PublicKey, Vec<Message>>(public_key) {
            Ok(Some(messages)) => {
                let mut message_batch: Vec<BananaMessage> = Vec::new();
                for message in messages {
                    message_batch.push(message.into());
                }

                match stream.lock().await.send_batch(message_batch.clone()).await {
                    Ok(_) => (),
                    Err(netwrk::Error::Dead) => {
                        warn!("Stream closed while listener initialized stream");
                        return Err(Error::Dead);
                    }
                    Err(e) => {
                        warn!(
                            "Error occures while trying to send stored messages. Storing messages again: {}",
                            e
                        );

                        let mut db_messages: Vec<Message> = Vec::new();
                        for msg in message_batch {
                            let message = match Message::try_from(msg) {
                                Ok(message) => message,
                                Err(_) => {
                                    panic!("Failed to convert BananaMessage")
                                }
                            };

                            db_messages.push((message.sender, message.message).into());
                        }

                        match Self::extend_messages_in_db(db, public_key, db_messages).await {
                            Ok(_) => (),
                            Err(e) => {
                                warn!("Failed to restore messages: {}", e);
                            }
                        };
                    }
                };
            }
            Ok(None) => (),
            Err(e) => {
                warn!("Failed to get {} messages from database: {}", public_key, e);
            }
        };

        Ok(())
    }

    /// Get a [`Vec`] of all currently connected streams.
    #[inline]
    pub(crate) async fn get_streams(
        streams: &ArcRwLock<HashMap<PublicKey, ArcMutex<Stream>>>,
    ) -> Vec<(PublicKey, ArcMutex<Stream>)> {
        let streams_rlock = streams.read().await;
        streams_rlock
            .iter()
            .map(|(k, s)| (k.clone(), s.clone()))
            .collect()
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

#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    Run,
    Pause,
    ShuttingDown,
}
