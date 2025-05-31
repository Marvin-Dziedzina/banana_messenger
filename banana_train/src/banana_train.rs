use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

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

const KEYPAIR_KEY: &str = "keypair";
const MESSAGES_TREE: &str = "MESSAGES";

#[derive(Debug)]
pub struct BananaTrain {
    status: Arc<RwLock<Status>>,

    config: Arc<Config>,

    db: SledDb,

    listener: Option<Arc<Mutex<Listener<BananaMessage>>>>,
    streams: Arc<RwLock<HashMap<PublicKey, Arc<Mutex<ReliableStream<BananaMessage>>>>>>,

    listener_handle: JoinHandle<Result<(), anyhow::Error>>,
    general_purpose_processor_handle: JoinHandle<Result<(), anyhow::Error>>,
    stream_processor_handle: JoinHandle<Result<(), anyhow::Error>>,
    message_processor_handle: JoinHandle<Result<(), anyhow::Error>>,
}

impl BananaTrain {
    pub async fn new(config_path: PathBuf) -> Self {
        let config = Arc::new(Config::try_open(&config_path).expect("Failed to read config"));

        let db = SledDb::open(&config.db_path).expect("Failed to access database");

        let (listener, keypair) = Listener::bind(
            &config.addr,
            db.get(&KEYPAIR_KEY.to_owned())
                .expect("Failed to read keypair"),
            config.max_buffered_connections,
            config.max_buffered_messages,
        )
        .await
        .expect("Could not bind listener");
        let listener = Arc::new(Mutex::new(listener));

        db.insert(&KEYPAIR_KEY.to_owned(), &keypair)
            .expect("Failed to save keypair");
        db.flush().expect("Failed to flush keypair db");

        let streams = Arc::new(RwLock::new(HashMap::new()));

        let status = Arc::new(RwLock::new(Status::Pause));

        let (message_channel_sender, message_channel_receiver) =
            tokio::sync::mpsc::channel(config.max_message_channel_capacity);
        let (stream_processor_done_sender, stream_processor_done_receiver) =
            tokio::sync::oneshot::channel();

        let listener_handle = tokio::spawn(Self::listener(
            status.clone(),
            db.open_tree(MESSAGES_TREE)
                .expect("Failed to open message tree for listener"),
            listener.clone(),
            streams.clone(),
        ));
        let db_flushing_handler_handle = tokio::spawn(Self::general_purpose_processor(
            status.clone(),
            config.clone(),
            db.clone(),
            streams.clone(),
        ));
        let handle_streams_handle = tokio::spawn(Self::handle_streams(
            status.clone(),
            streams.clone(),
            message_channel_sender.clone(),
            stream_processor_done_sender,
        ));
        let message_processor_handle = tokio::spawn(Self::process_messages(
            status.clone(),
            db.open_tree(MESSAGES_TREE)
                .expect("Failed to open the message tree for message processor"),
            streams.clone(),
            message_channel_receiver,
            message_channel_sender,
            stream_processor_done_receiver,
        ));

        Self {
            status,

            config,

            db,

            listener: Some(listener),
            streams,

            listener_handle,
            general_purpose_processor_handle: db_flushing_handler_handle,
            stream_processor_handle: handle_streams_handle,
            message_processor_handle,
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
            let streams = listener.lock().await.close().await?;
            for (stream, _) in streams {
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

    async fn listener(
        status: Arc<RwLock<Status>>,
        message_db: SledTree,
        listener: Arc<Mutex<Listener<BananaMessage>>>,
        streams: Arc<RwLock<HashMap<PublicKey, Arc<Mutex<ReliableStream<BananaMessage>>>>>>,
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

    async fn handle_streams(
        status: Arc<RwLock<Status>>,
        streams: Arc<RwLock<HashMap<PublicKey, Arc<Mutex<ReliableStream<BananaMessage>>>>>>,
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
                    for (sender_public_key, stream) in streams.write().await.drain() {
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

                    debug!("Stream handler is shutdown");
                    return Ok(());
                }
            };

            for (sender_public_key, stream) in streams.read().await.iter() {
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

    async fn process_messages(
        status: Arc<RwLock<Status>>,
        db: SledTree,
        streams: Arc<RwLock<HashMap<PublicKey, Arc<Mutex<ReliableStream<BananaMessage>>>>>>,
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

                    trace!("Message processor got stream processor done signal");

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

                    trace!("Message processor is shutdown");

                    return Ok(());
                }
            };

            let received_message = tokio::select! {
                received_message =  message_channel_receiver.recv() => {
                    received_message
                }
                _ = tokio::time::sleep(Duration::from_millis(250)) => {
                    None
                }
            };

            let (sender_public_key, banana_message) = match received_message {
                Some(bundle) => bundle,
                None => return Err(Error::ChannelClosed.into()),
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

    async fn insert_message_into_db(
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

    async fn extend_messages_in_db(
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

    async fn general_purpose_processor(
        status: Arc<RwLock<Status>>,
        config: Arc<Config>,
        db: SledDb,
        streams: Arc<RwLock<HashMap<PublicKey, Arc<Mutex<ReliableStream<BananaMessage>>>>>>,
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
                Status::ShuttingDown => return Ok(()),
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
                {
                    let streams_rlock = streams.read().await;
                    for (public_key, stream) in streams_rlock.iter() {
                        if stream.lock().await.is_dead() {
                            connections_to_prune.push(public_key.clone());
                        };
                    }
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

    async fn forward_message(
        stream: &Arc<Mutex<ReliableStream<BananaMessage>>>,
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

    async fn forward_stored_messages(
        stream: &Arc<Mutex<ReliableStream<BananaMessage>>>,
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
