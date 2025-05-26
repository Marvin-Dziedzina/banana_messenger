use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use log::warn;
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpStream, ToSocketAddrs},
    sync::Mutex,
    task::JoinHandle,
};

use crate::{
    Error, MESSAGE_PROCESSING_INTERVALL, NetworkMessage, decode, encode,
    encrypted_socket::{EncryptedSocket, HandshakeType},
    serialisable_keypair::SerializableKeypair,
};

#[derive(Debug)]
pub struct ReliableStream<M>
where
    M: Serialize + for<'a> Deserialize<'a> + Send + 'static,
{
    is_dead: Arc<AtomicBool>,

    inner: Arc<Mutex<EncryptedSocket>>,
    message_receiver: tokio::sync::mpsc::Receiver<M>,

    handle_incoming_task: JoinHandle<Result<(), Error>>,
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

        Ok(Self {
            is_dead,

            inner,
            message_receiver,

            handle_incoming_task,
        })
    }

    /// Send a message `M`.
    pub async fn send(&mut self, message: M) -> Result<(), Error> {
        if self.is_dead() {
            return Err(Error::Dead);
        };

        Self::send_netwrk_message(&self.inner, NetworkMessage::Message(message)).await
    }

    /// Receive the next available message.
    pub async fn receive(&mut self) -> Option<M> {
        if self.message_receiver.is_closed() {
            return None;
        };

        self.message_receiver.try_recv().ok()
    }

    /// Receive all currently available messages.
    pub fn batch_receive(&mut self) -> Option<Vec<M>> {
        if self.message_receiver.is_closed() {
            return None;
        };

        let mut buf = Vec::new();

        while let Ok(msg) = self.message_receiver.try_recv() {
            buf.push(msg);
        }

        if !buf.is_empty() { Some(buf) } else { None }
    }

    /// Wait for the next message to arrive. When there is a message in buffer it will immediately return.
    pub async fn wait_until_receive(&mut self) -> Option<M> {
        if self.message_receiver.is_closed() {
            return None;
        };

        self.message_receiver.recv().await
    }

    /// Close the connection. After that call you can not send and receive any messages anymore.
    ///
    /// The current messages in buffer will be returned.
    pub async fn close(mut self) -> Result<Option<Vec<M>>, Error> {
        if !self.is_dead() {
            Self::send_netwrk_message(&self.inner, NetworkMessage::<M>::Disconnect).await?;
            self.is_dead.store(true, Ordering::Release);
        };

        let msgs = self.batch_receive();
        self.message_receiver.close();
        self.handle_incoming_task.await??;

        Ok(msgs)
    }

    async fn send_netwrk_message(
        inner: &Arc<Mutex<EncryptedSocket>>,
        netwrk_message: NetworkMessage<M>,
    ) -> Result<(), Error> {
        inner.lock().await.send(&encode(netwrk_message)?).await
    }

    /// Get the remote public key.
    pub async fn remote_public_key(&self) -> Vec<u8> {
        self.inner.lock().await.get_remote_public_key()
    }

    async fn handle_incoming_messages(
        is_dead: Arc<AtomicBool>,
        inner_stream: Arc<Mutex<EncryptedSocket>>,
        message_sender: tokio::sync::mpsc::Sender<M>,
    ) -> Result<(), Error> {
        loop {
            if is_dead.load(Ordering::Relaxed) {
                return Ok(());
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

                    NetworkMessage::Disconnect => {
                        is_dead.store(true, Ordering::Release);
                        return Ok(());
                    }
                };

                tokio::time::sleep(MESSAGE_PROCESSING_INTERVALL).await;
            }
        }
    }

    /// Is [`NetwrkStream`] dead.
    pub fn is_dead(&self) -> bool {
        self.is_dead.load(Ordering::Relaxed)
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
mod client_test {
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
        let ((mut stream, key), (mut other_stream, other_key)) = get_netwrk_streams().await;

        stream.send(TestMessage::Foo).await.unwrap();

        assert_eq!(
            other_stream.wait_until_receive().await.unwrap(),
            TestMessage::Foo
        );

        other_stream.send(TestMessage::Bar).await.unwrap();

        assert_eq!(stream.wait_until_receive().await.unwrap(), TestMessage::Bar);

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
        let ((stream, _), (other_stream, _)) = get_netwrk_streams().await;

        let _ = stream.local_address().await.unwrap();
        let _ = other_stream.local_address().await.unwrap();
    }

    #[tokio::test]
    async fn test_remote_address() {
        let ((stream, _), (other_stream, _)) = get_netwrk_streams().await;

        let _ = stream.remote_address().await.unwrap();
        let _ = other_stream.remote_address().await.unwrap();
    }

    async fn get_netwrk_streams() -> (
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
        let _ = get_netwrk_streams().await;
    }

    #[tokio::test]
    async fn test_get_streams() {
        let _ = get_streams(ADDR).await;
    }
}
