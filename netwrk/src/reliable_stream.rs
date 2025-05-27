use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use log::{debug, warn};
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpStream, ToSocketAddrs},
    sync::Mutex,
    task::JoinHandle,
};

use crate::{
    Error, NetworkMessage, Reason, VERSION_MAJOR_MINOR, decode, encode,
    encrypted_socket::{EncryptedSocket, HandshakeType},
    serialisable_keypair::SerializableKeypair,
};

/// A [`ReliableStream`].
#[derive(Debug)]
pub struct ReliableStream<M>
where
    M: Serialize + for<'a> Deserialize<'a> + Send + 'static,
{
    is_dead: Arc<AtomicBool>,

    inner: Arc<Mutex<EncryptedSocket>>,
    message_receiver: tokio::sync::mpsc::Receiver<M>,

    handle_incoming_task: JoinHandle<Reason>,
}

impl<M> ReliableStream<M>
where
    M: Serialize + for<'a> Deserialize<'a> + Send + 'static,
{
    /// Create a new initiator stream. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    pub async fn connect_initiator<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<SerializableKeypair>,
        max_buffered_messages: usize,
    ) -> Result<(Self, SerializableKeypair), Error> {
        Self::connect_handshake(
            addr,
            keypair,
            HandshakeType::Initiator,
            max_buffered_messages,
        )
        .await
    }

    /// Create a new responder stream. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    pub async fn connect_responder<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<SerializableKeypair>,
        max_buffered_messages: usize,
    ) -> Result<(Self, SerializableKeypair), Error> {
        Self::connect_handshake(
            addr,
            keypair,
            HandshakeType::Responder,
            max_buffered_messages,
        )
        .await
    }

    /// Connect with a [`HandshakeType`]. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    async fn connect_handshake<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<SerializableKeypair>,
        handshake_type: crate::encrypted_socket::HandshakeType,
        max_buffered_messages: usize,
    ) -> Result<(Self, SerializableKeypair), Error> {
        let (inner, keypair) = match handshake_type {
            HandshakeType::Initiator => EncryptedSocket::new_initiator(addr, keypair).await,
            HandshakeType::Responder => EncryptedSocket::new_responder(addr, keypair).await,
        }?;
        let netwrk_stream = Self::from_inner_stream(inner, max_buffered_messages).await?;

        Ok((netwrk_stream, keypair))
    }

    /// Create a [`Stream`] from a [`TcpStream`] and [`HandshakeType`]. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    pub async fn from_stream(
        tcp_stream: TcpStream,
        keypair: Option<SerializableKeypair>,
        handshake_type: crate::encrypted_socket::HandshakeType,
        max_buffered_messages: usize,
    ) -> Result<(Self, SerializableKeypair), Error> {
        let (inner, keypair) =
            EncryptedSocket::from_tcp_stream(tcp_stream, keypair, handshake_type).await?;
        let netwrk_stream = Self::from_inner_stream(inner, max_buffered_messages).await?;

        Ok((netwrk_stream, keypair))
    }

    /// Create a [`Stream`] from a [`InnerStream`].
    pub async fn from_inner_stream(
        inner_stream: EncryptedSocket,
        max_buffered_messages: usize,
    ) -> Result<Self, Error> {
        let is_dead = Arc::new(AtomicBool::new(false));
        let inner = Arc::new(Mutex::new(inner_stream));
        let (message_sender, message_receiver) = tokio::sync::mpsc::channel(max_buffered_messages);

        let is_dead_c = is_dead.clone();
        let inner_c = inner.clone();
        let handle_incoming_task = tokio::spawn(Self::handle_incoming_messages(
            is_dead_c,
            inner_c,
            message_sender,
        ));

        let reliable_stream = Self {
            is_dead,

            inner,
            message_receiver,

            handle_incoming_task,
        };

        Self::send_netwrk_message(
            &mut reliable_stream.inner.lock().await,
            NetworkMessage::Version(VERSION_MAJOR_MINOR.to_string()),
        )
        .await?;

        Ok(reliable_stream)
    }

    /// Send a message `M`.
    pub async fn send(&mut self, message: M) -> Result<(), Error> {
        if self.is_dead() {
            return Err(Error::Dead);
        };

        Self::send_message(&mut self.inner.lock().await, message).await
    }

    /// Send a batch of messages `M`.
    pub async fn send_batch(&mut self, messages: Vec<M>) -> Result<(), Error> {
        if self.is_dead() {
            return Err(Error::Dead);
        };

        let mut inner_lock = self.inner.lock().await;
        for msg in messages {
            Self::send_message(&mut inner_lock, msg).await?;
        }

        Ok(())
    }

    /// Send a `M`.
    async fn send_message<'a>(
        inner: &mut tokio::sync::MutexGuard<'a, EncryptedSocket>,
        message: M,
    ) -> Result<(), Error> {
        Self::send_netwrk_message(inner, NetworkMessage::Message(message)).await
    }

    /// Send a [`NetworkMessage`].
    async fn send_netwrk_message<'a>(
        inner: &mut tokio::sync::MutexGuard<'a, EncryptedSocket>,
        netwrk_message: NetworkMessage<M>,
    ) -> Result<(), Error> {
        inner.send(&encode(netwrk_message)?).await
    }

    /// Receive a available message. Returns [`None`] if no messages are available.
    pub async fn try_receive(&mut self) -> Option<M> {
        if self.is_closed() {
            return None;
        };

        self.message_receiver.try_recv().ok()
    }

    /// Receive all currently available messages.
    pub fn receive_batch(&mut self) -> Option<Vec<M>> {
        use tokio::sync::mpsc::error::TryRecvError;

        if self.is_closed() {
            return None;
        };

        let mut buf = Vec::new();
        loop {
            match self.message_receiver.try_recv() {
                Ok(msg) => buf.push(msg),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    Self::set_is_dead(&self.is_dead, true);
                    break;
                }
            }
        }

        if !buf.is_empty() { Some(buf) } else { None }
    }

    /// Receive all available messages. Yields when one or more messages are read.
    pub async fn async_batch_receive(&mut self) -> Option<Vec<M>> {
        if self.is_closed() {
            return None;
        };

        let mut buf = Vec::new();
        if let Some(first) = self.message_receiver.recv().await {
            buf.push(first);
        };
        while let Ok(msg) = self.message_receiver.try_recv() {
            buf.push(msg);
        }

        Some(buf)
    }

    /// Receive the next message. Yield once a message is available.
    pub async fn receive(&mut self) -> Option<M> {
        if self.is_closed() {
            return None;
        };

        self.message_receiver.recv().await
    }

    /// Close the connection. After that call you can not send and receive any messages anymore.
    ///
    /// The current messages in buffer will be returned.
    pub async fn close(mut self) -> Result<(Reason, Option<Vec<M>>), Error> {
        if !self.is_dead() {
            Self::send_netwrk_message(
                &mut self.inner.lock().await,
                NetworkMessage::<M>::Disconnect(Reason::Disconnect),
            )
            .await?;
            Self::set_is_dead(&self.is_dead, true);
        };

        let msgs = self.receive_batch();
        self.message_receiver.close();
        let reason = self.handle_incoming_task.await?;

        Ok((reason, msgs))
    }

    /// Get the remote public key.
    pub async fn remote_public_key(&self) -> Vec<u8> {
        self.inner.lock().await.get_remote_public_key()
    }

    async fn handle_incoming_messages(
        is_dead: Arc<AtomicBool>,
        inner_stream: Arc<Mutex<EncryptedSocket>>,
        message_sender: tokio::sync::mpsc::Sender<M>,
    ) -> Reason {
        loop {
            if is_dead.load(Ordering::Relaxed) {
                return Reason::Dead;
            };

            while let Ok(Some(bytes)) = inner_stream.lock().await.try_read().await {
                let netwrk_message: NetworkMessage<M> = match decode(&bytes) {
                    Ok(netwrk_message) => netwrk_message,
                    Err(e) => {
                        warn!("Failed to decode netwrk message: {}", e);
                        continue;
                    }
                };

                match netwrk_message {
                    NetworkMessage::Message(msg) => {
                        if let Err(e) = message_sender.send(msg).await {
                            warn!("Failed to send message to channel: {}", e);
                            continue;
                        };
                    }

                    NetworkMessage::Version(v) => {
                        debug!(
                            "Netwrk Version: {{ Local: {}; Remote: {} }}",
                            VERSION_MAJOR_MINOR, v
                        );
                        if v != VERSION_MAJOR_MINOR {
                            return Reason::VersionMismatch;
                        }
                    }

                    NetworkMessage::Ping => {}
                    NetworkMessage::Pong => {}

                    NetworkMessage::Disconnect(reason) => {
                        Self::set_is_dead(&is_dead, true);
                        return reason;
                    }
                };
            }
        }
    }

    /// Is message receiver closed.
    fn is_closed(&self) -> bool {
        self.message_receiver.is_closed()
    }

    /// Is [`ReliableStream`] dead.
    pub fn is_dead(&self) -> bool {
        self.is_dead.load(Ordering::Relaxed)
    }

    fn set_is_dead(is_dead: &Arc<AtomicBool>, b: bool) {
        is_dead.store(b, Ordering::Release);
    }

    /// Generate a new [`SerializableKeypair`].
    ///
    /// This [`SerializableKeypair`] can be stored.
    pub fn generate_keypair() -> SerializableKeypair {
        EncryptedSocket::generate_keypair()
    }

    /// Get the local address.
    pub async fn local_address(&self) -> Result<std::net::SocketAddr, Error> {
        self.inner.lock().await.local_address()
    }

    /// Get the remote address.
    pub async fn remote_address(&self) -> Result<std::net::SocketAddr, Error> {
        self.inner.lock().await.remote_address()
    }
}

#[cfg(test)]
mod reliable_stream_test {
    use std::time::Duration;

    use serde::{Deserialize, Serialize};
    use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

    use crate::{encrypted_socket::HandshakeType, serialisable_keypair::SerializableKeypair};

    use super::ReliableStream;

    const ADDR: &'static str = "127.0.0.1:0";
    const MAX_BUFFERED_MESSAGES: usize = 64;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    enum TestMessage {
        Foo,
        Bar,
    }

    #[tokio::test]
    async fn test_reliable_stream() {
        let ((mut stream, key), (mut other_stream, other_key)) = get_reliable_streams().await;

        stream.send(TestMessage::Foo).await.unwrap();

        assert_eq!(other_stream.receive().await.unwrap(), TestMessage::Foo);

        other_stream.send(TestMessage::Bar).await.unwrap();

        assert_eq!(stream.receive().await.unwrap(), TestMessage::Bar);

        assert_eq!(key.public, other_stream.remote_public_key().await);
        assert_eq!(other_key.public, stream.remote_public_key().await);

        assert!(!stream.is_dead());
        assert!(!other_stream.is_dead());

        stream.close().await.unwrap();

        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(other_stream.is_dead());
        other_stream.close().await.unwrap();
    }

    #[tokio::test]
    async fn generate_keypair() {
        let _ = ReliableStream::<TestMessage>::generate_keypair();
    }

    #[tokio::test]
    async fn test_local_address() {
        let ((stream, _), (other_stream, _)) = get_reliable_streams().await;

        let _ = stream.local_address().await.unwrap();
        let _ = other_stream.local_address().await.unwrap();
    }

    #[tokio::test]
    async fn test_remote_address() {
        let ((stream, _), (other_stream, _)) = get_reliable_streams().await;

        let _ = stream.remote_address().await.unwrap();
        let _ = other_stream.remote_address().await.unwrap();
    }

    async fn get_reliable_streams() -> (
        (ReliableStream<TestMessage>, SerializableKeypair),
        (ReliableStream<TestMessage>, SerializableKeypair),
    ) {
        let (stream, other_stream) = get_streams(ADDR).await;

        let other_handle = tokio::spawn(ReliableStream::from_stream(
            other_stream,
            None,
            HandshakeType::Responder,
            MAX_BUFFERED_MESSAGES,
        ));

        let handle = tokio::spawn(ReliableStream::from_stream(
            stream,
            None,
            HandshakeType::Initiator,
            MAX_BUFFERED_MESSAGES,
        ));

        let pair = handle.await.unwrap().unwrap();
        let other_pair = other_handle.await.unwrap().unwrap();

        (pair, other_pair)
    }

    async fn get_streams<A: ToSocketAddrs>(addr: A) -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(addr).await.unwrap();
        let other_addr = listener.local_addr().unwrap();

        let stream_task = tokio::spawn(TcpStream::connect(other_addr));

        let (stream, _) = listener.accept().await.unwrap();
        let other_stream = stream_task.await.unwrap().unwrap();

        (stream, other_stream)
    }

    #[tokio::test]
    async fn test_get_netwrk_streams() {
        let _ = get_reliable_streams().await;
    }

    #[tokio::test]
    async fn test_get_streams() {
        let _ = get_streams(ADDR).await;
    }
}
