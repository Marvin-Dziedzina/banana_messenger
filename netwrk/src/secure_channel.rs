use std::{
    collections::VecDeque,
    marker::PhantomData,
    mem,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use banana_crypto::{
    chacha20poly1305::Cipher,
    ed25519::{self, SignatureBlob, SignerKeyPair, VerifyingKey},
    x25519::KeyExchange,
};
use log::{trace, warn};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{BufReader, BufWriter},
    net::{
        TcpStream, ToSocketAddrs,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{
        Mutex,
        watch::{Receiver, Sender},
    },
    task::JoinHandle,
};

use crate::{Error, NetworkMessage, bincode_config, protocol};

/// The handshake needs to be done in this timeframe. If not the connection could not be established.
const HANDSHAKE_TIMEOUT_S: f32 = 10.0;
/// If no sign of life gets picked up in this period a [`NetworkMessage::KeepAlive`] will get sent.
const KEEP_ALIVE_INTERVALL_S: f32 = 3.0;
/// If no sign of life gets picked up in this period the connection is considered dead.
const CONNECTION_TIMEOUT_S: f32 = 10.0;

/// A secure channel over which messages `M` can be sent.
pub struct SecureChannel<M>
where
    M: Serialize + for<'a> Deserialize<'a> + Send,
{
    is_alive: Arc<AtomicBool>,
    shutdown_channel_sender: Sender<bool>,

    writer: Arc<Mutex<BufWriter<OwnedWriteHalf>>>,

    message_buffer: Arc<Mutex<VecDeque<M>>>,

    signer_key_pair: Arc<Mutex<SignerKeyPair>>,
    cipher: Arc<Cipher>,

    handle_incoming_messages_task: JoinHandle<Result<(), Error>>,
    keep_alive_task: JoinHandle<Result<(), Error>>,

    phantom_data: PhantomData<M>,
}

impl<M> SecureChannel<M>
where
    M: Serialize + for<'a> Deserialize<'a> + Send + 'static,
{
    /// Connect to a address.
    pub async fn connect<A: ToSocketAddrs>(
        addr: A,
        signer_key_pair: SignerKeyPair,
        other_verifying_key: VerifyingKey,
    ) -> Result<Self, Error> {
        let tcp_stream = TcpStream::connect(addr).await?;
        Self::from_tcp_stream(tcp_stream, signer_key_pair, other_verifying_key).await
    }

    /// Creates a [`SecureChannel`] from a [`TcpStream`].
    async fn from_tcp_stream(
        tcp_stream: TcpStream,
        signer_key_pair: SignerKeyPair,
        other_verifying_key: VerifyingKey,
    ) -> Result<Self, Error> {
        let (owned_read_half, owned_write_half) = tcp_stream.into_split();
        let reader = Arc::new(Mutex::new(BufReader::new(owned_read_half)));
        let writer = Arc::new(Mutex::new(BufWriter::new(owned_write_half)));

        let is_alive = Arc::new(AtomicBool::new(true));
        let signer_key_pair = Arc::new(Mutex::new(signer_key_pair));

        let message_buffer = Arc::new(Mutex::new(VecDeque::with_capacity(128)));

        let cipher = tokio::time::timeout(
            Duration::from_secs_f32(HANDSHAKE_TIMEOUT_S),
            Self::handle_handshake(
                &is_alive,
                &writer,
                &reader,
                &signer_key_pair,
                &other_verifying_key,
            ),
        )
        .await
        .map_err(Error::Elapsed)?
        .map(Arc::new)?;

        let last_heared_time = Arc::new(Mutex::new(SystemTime::now()));
        let (shutdown_channel_sender, shutdown_channel_receiver) =
            tokio::sync::watch::channel(false);
        let handle_incoming_messages_task = tokio::spawn(Self::handle_incoming_messages(
            is_alive.clone(),
            last_heared_time.clone(),
            shutdown_channel_receiver.clone(),
            reader,
            writer.clone(),
            message_buffer.clone(),
            other_verifying_key,
            signer_key_pair.clone(),
            cipher.clone(),
        ));

        let keep_alive_task = tokio::spawn(Self::keep_alive(
            is_alive.clone(),
            last_heared_time.clone(),
            shutdown_channel_receiver,
            shutdown_channel_sender.clone(),
            writer.clone(),
            signer_key_pair.clone(),
        ));

        Ok(Self {
            is_alive,
            shutdown_channel_sender,

            writer,

            message_buffer,

            signer_key_pair,
            cipher,

            handle_incoming_messages_task,
            keep_alive_task,

            phantom_data: PhantomData,
        })
    }

    /// Close the connection.
    pub async fn close(self) -> Result<VecDeque<M>, Error> {
        if self.is_connected() {
            Self::write_unencrypted(&self.writer, &self.signer_key_pair, NetworkMessage::Close)
                .await?;

            self.is_alive.store(false, Ordering::Relaxed);
        };

        match self.shutdown_channel_sender.send(true) {
            Ok(_) => (),
            Err(e) => {
                warn!("Failed to shutdown tasks: {}", e);

                self.handle_incoming_messages_task.abort();
                self.keep_alive_task.abort();
            }
        };

        let _ = self
            .handle_incoming_messages_task
            .await
            .map_err(Error::TaskJoin)?;
        let _ = self.keep_alive_task.await.map_err(Error::TaskJoin)?;

        Ok(mem::take(&mut *self.message_buffer.lock().await))
    }

    /// Handles all incoming messages.
    async fn handle_incoming_messages(
        is_alive: Arc<AtomicBool>,
        last_heared_time: Arc<Mutex<SystemTime>>,
        mut shutdown_channel_receiver: Receiver<bool>,

        reader: Arc<Mutex<BufReader<OwnedReadHalf>>>,
        writer: Arc<Mutex<BufWriter<OwnedWriteHalf>>>,

        message_buffer: Arc<Mutex<VecDeque<M>>>,
        other_verifying_key: VerifyingKey,

        signer_key_pair: Arc<Mutex<SignerKeyPair>>,
        cipher: Arc<Cipher>,
    ) -> Result<(), Error> {
        loop {
            if !is_alive.load(Ordering::Relaxed) {
                return Err(Error::Dead);
            };

            let network_message = tokio::select! {
                _ = shutdown_channel_receiver.changed() => {
                    if *shutdown_channel_receiver.borrow() {
                        break;
                    } else {
                        continue;
                    };
                }
                result = Self::read_encrypted(&reader, &other_verifying_key) => {
                    match result {
                        Ok(network_message) => network_message,
                        Err(e) => {
                            warn!("Failed to read NetworkMessage: {}", e);
                            continue;
                        }
                    }
                }
            };

            match network_message {
                NetworkMessage::Close => {
                    is_alive.store(false, Ordering::Relaxed);
                    continue;
                }
                NetworkMessage::KeepAlive => {
                    match Self::write_unencrypted(
                        &writer,
                        &signer_key_pair,
                        NetworkMessage::KeepAliveResponse,
                    )
                    .await
                    {
                        Ok(_) => (),
                        Err(e) => {
                            warn!("Failed to send KeepAliveResponse: {}", e);
                            continue;
                        }
                    };
                }
                NetworkMessage::KeepAliveResponse => {
                    trace!("KeepAliveResponse received")
                }
                NetworkMessage::ComponentExchange(_) => {
                    warn!("Got component exchange but component exchange already done");
                }
                NetworkMessage::Message(ciphertext) => {
                    let message_bytes = match cipher.decrypt(&ciphertext) {
                        Ok(message_bytes) => message_bytes,
                        Err(e) => {
                            warn!("Failed to decrypt ciphertext: {}", e);
                            continue;
                        }
                    };

                    let message: M = match Self::decode_data(&message_bytes) {
                        Ok(message) => message,
                        Err(e) => {
                            warn!("Failed to decode message bytes: {}", e);
                            continue;
                        }
                    };

                    message_buffer.lock().await.push_back(message);
                }
            };

            *last_heared_time.lock().await = SystemTime::now();
        }

        Ok(())
    }

    /// Keep the connection alive.
    async fn keep_alive(
        is_alive: Arc<AtomicBool>,
        last_heared_time: Arc<Mutex<SystemTime>>,
        mut shutdown_channel_receiver: Receiver<bool>,
        shutdown_channel_sender: Sender<bool>,

        writer: Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
        signer_key_pair: Arc<Mutex<SignerKeyPair>>,
    ) -> Result<(), Error> {
        let mut interval = tokio::time::interval(Duration::from_secs_f32(KEEP_ALIVE_INTERVALL_S));
        // Invalidate the first tick.
        interval.tick().await;

        loop {
            if !is_alive.load(Ordering::Relaxed) {
                return Err(Error::Dead);
            };

            tokio::select! {
                _ = shutdown_channel_receiver.changed() => {
                    if *shutdown_channel_receiver.borrow() {
                        return Err(Error::Dead);
                    } else {
                        continue;
                    };
                }
                _ = interval.tick() => {
                    let elapsed = match last_heared_time.lock().await.elapsed() {
                        Ok(elapsed) => elapsed,
                        Err(e) => {
                            warn!("Failed to get the elapsed time: {}", e);
                            continue;
                        }
                    };

                    if elapsed > Duration::from_secs_f32(CONNECTION_TIMEOUT_S) {
                        is_alive.store(false, Ordering::Relaxed);
                        match shutdown_channel_sender.send(true) {
                            Ok(_) => (),
                            Err(e) => {
                                warn!("Failed to send shutdown signal over channel: {}", e);
                            }
                        };
                        return Err(Error::Dead);
                    } else if elapsed > Duration::from_secs_f32(KEEP_ALIVE_INTERVALL_S) {
                        match Self::write_unencrypted(&writer, &signer_key_pair, NetworkMessage::KeepAlive).await {
                            Ok(_) => (),
                            Err(e) => {
                                warn!("Failed to write KeepAlive request: {}", e);
                                continue;
                            }
                        };
                    };
                }
            }
        }
    }

    /// Read a message `M` from the socket.
    pub async fn read(&mut self) -> Option<M> {
        self.message_buffer.lock().await.pop_front()
    }

    /// Read a packet and verify its signature.
    async fn read_encrypted(
        reader: &Arc<Mutex<BufReader<OwnedReadHalf>>>,
        other_verifying_key: &VerifyingKey,
    ) -> Result<NetworkMessage, Error> {
        let mut buf = Vec::new();
        Self::read_raw(reader, &mut buf).await?;

        let signature_blob: SignatureBlob = Self::decode_data(&buf)?;
        ed25519::verify(other_verifying_key, &signature_blob).map_err(Error::Signature)?;

        Self::decode_data(&signature_blob.msg)
    }

    /// Read a raw packet.
    async fn read_raw(
        reader: &Arc<Mutex<BufReader<OwnedReadHalf>>>,
        buf: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let mut reader_lock = reader.lock().await;

        protocol::read_packet(&mut *reader_lock, buf)
            .await
            .map(|_| ())
            .map_err(|e| e.into())
    }

    /// Send a encrypted and signed message `M`.
    pub async fn write(&mut self, network_message: M) -> Result<(), Error> {
        if !self.is_connected() {
            return Err(Error::Dead);
        };

        let data = Self::encode_data(network_message)?;
        let cipertext = self.cipher.encrypt(&data, None).map_err(Error::Cipher)?;

        Self::write_unencrypted(
            &self.writer,
            &self.signer_key_pair,
            NetworkMessage::Message(cipertext),
        )
        .await?;

        Ok(())
    }

    /// Sign and write a network message.
    async fn write_unencrypted(
        writer: &Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
        signer_key_pair: &Arc<Mutex<SignerKeyPair>>,
        network_message: NetworkMessage,
    ) -> Result<(), Error> {
        let network_message_bytes = Self::encode_data(network_message)?;

        let mut signer_key_pair_lock = signer_key_pair.lock().await;
        let signature_blob = signer_key_pair_lock.sign(&network_message_bytes);
        let signerd_data = Self::encode_data(signature_blob)?;

        Self::write_raw(writer, signerd_data).await
    }

    /// Send a raw message. No encryption, no signature. Just raw bytes.
    async fn write_raw(
        writer: &Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        let mut writer = writer.lock().await;

        protocol::write_packet(&mut *writer, &data)
            .await
            .map_err(|e| e.into())
    }

    /// Get the connection status.
    pub fn is_connected(&self) -> bool {
        self.is_alive.load(Ordering::Relaxed)
    }

    /// Handles the handshake.
    ///
    /// Returns
    async fn handle_handshake(
        is_alive: &Arc<AtomicBool>,

        writer: &Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
        reader: &Arc<Mutex<BufReader<OwnedReadHalf>>>,

        signer_key_pair: &Arc<Mutex<SignerKeyPair>>,
        other_verifying_key: &VerifyingKey,
    ) -> Result<Cipher, Error> {
        if !is_alive.load(Ordering::Relaxed) {
            return Err(Error::Dead);
        };

        let key_exchange = KeyExchange::new();
        let public_component = key_exchange.get_public_component();

        Self::write_unencrypted(
            writer,
            signer_key_pair,
            NetworkMessage::ComponentExchange(public_component),
        )
        .await?;

        loop {
            let network_message = match Self::read_encrypted(reader, other_verifying_key).await {
                Ok(network_message) => network_message,
                Err(e) => {
                    match &e {
                        Error::Protocol(protocol_e) => match protocol_e {
                            protocol::Error::CorruptConnection => {
                                let mut reader_lock = reader.lock().await;
                                protocol::recover(&mut *reader_lock).await?;
                            }
                            _ => (),
                        },
                        _ => (),
                    }
                    warn!("Failed to read packet: {}", e);
                    continue;
                }
            };

            match network_message {
                NetworkMessage::Close => {
                    is_alive.store(false, Ordering::Relaxed);
                    return Err(Error::Dead);
                }
                NetworkMessage::ComponentExchange(other_public_component) => {
                    let shared_secret: banana_crypto::x25519::SharedSecret =
                        key_exchange.compute_shared_secret(other_public_component);
                    let cipher = Cipher::from(shared_secret);
                    return Ok(cipher);
                }
                _ => continue,
            }
        }
    }

    fn encode_data<D>(network_message: D) -> Result<Vec<u8>, Error>
    where
        D: Serialize,
    {
        bincode::serde::encode_to_vec(network_message, bincode_config())
            .map_err(Error::BincodeEncode)
    }

    fn decode_data<D>(data: &[u8]) -> Result<D, Error>
    where
        D: for<'a> Deserialize<'a>,
    {
        Ok(
            bincode::serde::borrow_decode_from_slice(data, bincode_config())
                .map_err(Error::BincodeDecode)?
                .0,
        )
    }
}

#[cfg(test)]
mod test_secure_channel {
    use std::{net::SocketAddr, sync::Once, time::Duration};

    use banana_crypto::ed25519::{SignerKeyPair, VerifyingKey};
    use serde::{Deserialize, Serialize};
    use tokio::net::{TcpListener, ToSocketAddrs};

    use crate::secure_channel::{CONNECTION_TIMEOUT_S, KEEP_ALIVE_INTERVALL_S};

    use super::SecureChannel;

    static INIT: Once = Once::new();

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum TestMessage {
        Message(String),
        Number(i32),
    }

    #[tokio::test]
    async fn test_keep_alive_timeout() {
        let (secure_channel_1, secure_channel_2) =
            get_connected_secure_channels::<TestMessage>().await;

        secure_channel_2.shutdown_channel_sender.send(true).unwrap();
        secure_channel_2
            .is_alive
            .store(false, std::sync::atomic::Ordering::Relaxed);
        drop(secure_channel_2);

        assert!(secure_channel_1.is_connected());

        tokio::time::sleep(Duration::from_secs_f32(
            CONNECTION_TIMEOUT_S + KEEP_ALIVE_INTERVALL_S + 2.0,
        ))
        .await;

        assert!(!secure_channel_1.is_connected());

        assert!(secure_channel_1.close().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_keep_alive() {
        let (secure_channel_1, secure_channel_2) =
            get_connected_secure_channels::<TestMessage>().await;

        tokio::time::sleep(Duration::from_secs_f32(
            CONNECTION_TIMEOUT_S + KEEP_ALIVE_INTERVALL_S + 2.0,
        ))
        .await;

        assert!(secure_channel_1.is_connected());
        assert!(secure_channel_2.is_connected());

        assert!(secure_channel_1.close().await.unwrap().is_empty());
        assert!(secure_channel_2.close().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_life_cycle() {
        let (mut secure_channel_1, mut secure_channel_2) =
            get_connected_secure_channels::<TestMessage>().await;

        secure_channel_1
            .write(TestMessage::Number(100))
            .await
            .unwrap();
        secure_channel_2
            .write(TestMessage::Number(50))
            .await
            .unwrap();

        assert!(secure_channel_1.is_connected());
        assert!(secure_channel_2.is_connected());

        assert!(!secure_channel_1.handle_incoming_messages_task.is_finished());
        assert!(!secure_channel_2.handle_incoming_messages_task.is_finished());

        tokio::time::sleep(Duration::from_millis(1)).await;

        assert_eq!(
            TestMessage::Number(50),
            secure_channel_1.read().await.unwrap()
        );
        assert_eq!(
            TestMessage::Number(100),
            secure_channel_2.read().await.unwrap()
        );

        assert!(secure_channel_1.close().await.unwrap().is_empty());
        assert!(secure_channel_2.close().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_new() {
        get_connected_secure_channels::<TestMessage>().await;
    }

    async fn get_connected_secure_channels<
        M: Serialize + for<'a> Deserialize<'a> + Send + 'static,
    >() -> (SecureChannel<M>, SecureChannel<M>) {
        init_env_logger();

        let signer_key_pair = SignerKeyPair::new();
        let verifying_key = signer_key_pair.get_verifying_key();

        let free_socket_addr = get_free_local_addr().await;
        let listener_handle = tokio::spawn(listen_for_connection::<M, SocketAddr>(
            free_socket_addr,
            signer_key_pair.clone(),
            verifying_key,
        ));

        tokio::time::sleep(Duration::from_millis(1)).await;

        let secure_channel_1 =
            SecureChannel::<M>::connect(free_socket_addr, signer_key_pair, verifying_key)
                .await
                .unwrap();

        let secure_channel_2 = listener_handle.await.unwrap();

        (secure_channel_1, secure_channel_2)
    }

    async fn listen_for_connection<
        M: Serialize + for<'a> Deserialize<'a> + Send + 'static,
        A: ToSocketAddrs,
    >(
        addr: A,
        signer_key_pair: SignerKeyPair,
        other_verifying_key: VerifyingKey,
    ) -> SecureChannel<M> {
        let listener = TcpListener::bind(addr).await.unwrap();
        let tcp_stream = listener.accept().await.map(|(stream, _)| stream).unwrap();
        SecureChannel::from_tcp_stream(tcp_stream, signer_key_pair, other_verifying_key)
            .await
            .unwrap()
    }

    fn init_env_logger() {
        INIT.call_once(|| {
            env_logger::builder().is_test(true).init();
        });
    }

    async fn get_free_local_addr() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
    }
}
