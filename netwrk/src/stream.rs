use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use log::{debug, warn};
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpStream, ToSocketAddrs},
    sync::{Mutex, Notify},
    task::JoinHandle,
};

use crate::{
    Error, MESSAGE_PROCESSING_INTERVALL, NetwrkMessage, decode, encode,
    inner_stream::{HandshakeType, InnerStream},
    serialisable_keypair::SerializableKeypair,
};

#[derive(Debug)]
pub struct Stream<M>
where
    M: Serialize + for<'a> Deserialize<'a> + Send + 'static,
{
    is_dead: Arc<AtomicBool>,

    inner: Arc<Mutex<InnerStream>>,
    message_buf: Arc<Mutex<VecDeque<M>>>,
    new_msg_notify: Arc<Notify>,

    handle_incoming_task: JoinHandle<Result<(), Error>>,
}

impl<M> Stream<M>
where
    M: Serialize + for<'a> Deserialize<'a> + Send + 'static,
{
    pub async fn connect_initiator<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<SerializableKeypair>,
    ) -> Result<(Self, SerializableKeypair), Error> {
        Self::connect_handshake(addr, keypair, HandshakeType::Initiator).await
    }

    pub async fn connect_responder<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<SerializableKeypair>,
    ) -> Result<(Self, SerializableKeypair), Error> {
        Self::connect_handshake(addr, keypair, HandshakeType::Responder).await
    }

    async fn connect_handshake<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<SerializableKeypair>,
        handshake_type: crate::inner_stream::HandshakeType,
    ) -> Result<(Self, SerializableKeypair), Error> {
        let (inner, keypair) = match handshake_type {
            HandshakeType::Responder => InnerStream::new_responder(addr, keypair).await,
            HandshakeType::Initiator => InnerStream::new_initiator(addr, keypair).await,
        }?;
        let netwrk_stream = Self::from_inner_stream(inner).await?;

        Ok((netwrk_stream, keypair))
    }

    pub async fn from_stream(
        tcp_stream: TcpStream,
        keypair: Option<SerializableKeypair>,
        handshake_type: crate::inner_stream::HandshakeType,
    ) -> Result<(Self, SerializableKeypair), Error> {
        let (inner, keypair) =
            InnerStream::from_tcp_stream(tcp_stream, keypair, handshake_type).await?;
        let netwrk_stream = Self::from_inner_stream(inner).await?;

        Ok((netwrk_stream, keypair))
    }

    pub async fn from_inner_stream(inner_stream: InnerStream) -> Result<Self, Error> {
        let is_dead = Arc::new(AtomicBool::new(false));
        let inner = Arc::new(Mutex::new(inner_stream));
        let message_buf = Arc::new(Mutex::new(VecDeque::with_capacity(u8::MAX as usize)));
        let new_msg_notify = Arc::new(Notify::new());

        let is_dead_c = is_dead.clone();
        let inner_c = inner.clone();
        let message_buf_c = message_buf.clone();
        let new_msg_notify_c = new_msg_notify.clone();
        let handle_incoming_task = tokio::spawn(Self::handle_incoming_messages(
            is_dead_c,
            inner_c,
            message_buf_c,
            new_msg_notify_c,
        ));

        Ok(Self {
            is_dead,

            inner,
            message_buf,
            new_msg_notify,

            handle_incoming_task,
        })
    }

    /// Send a message `M`.
    pub async fn send(&mut self, message: M) -> Result<(), Error> {
        if self.is_dead() {
            return Err(Error::Dead);
        };

        Self::send_netwrk_message(&self.inner, NetwrkMessage::Message(message)).await
    }

    /// Receive the next available message.
    pub async fn receive(&mut self) -> Option<M> {
        self.message_buf.lock().await.pop_front()
    }

    /// Receive all currently available messages.
    pub async fn batch_receive(&mut self) -> Option<Vec<M>> {
        let msgs: Vec<M> = std::mem::take(&mut *self.message_buf.lock().await).into();

        if !msgs.is_empty() { Some(msgs) } else { None }
    }

    /// Wait for the next message to arrive. When there is a message in buffer it will immediately return.
    pub async fn wait_until_receive(&mut self) -> M {
        loop {
            if let Some(msg) = self.receive().await {
                return msg;
            };

            // Wait for a notification or timeout.
            tokio::select! {
                _ = self.new_msg_notify.notified() => {
                    debug!("Wait until recive notified");
                }
            _ = tokio::time::sleep(MESSAGE_PROCESSING_INTERVALL *10) => {
                debug!("Wait until recive timeout. Checking manually");
            }
            };
        }
    }

    /// Close the connection. After that call you can not send and receive any messages anymore.
    ///
    /// The current messages in buffer will be returned.
    pub async fn close(self) -> Result<VecDeque<M>, Error> {
        if !self.is_dead() {
            Self::send_netwrk_message(&self.inner, NetwrkMessage::<M>::Disconnect).await?;
            self.is_dead.store(true, Ordering::Release);
        };

        self.handle_incoming_task.await??;

        Ok(std::mem::take(&mut *self.message_buf.lock().await))
    }

    async fn send_netwrk_message(
        inner: &Arc<Mutex<InnerStream>>,
        netwrk_message: NetwrkMessage<M>,
    ) -> Result<(), Error> {
        inner.lock().await.send(&encode(netwrk_message)?).await
    }

    /// Get the remote public key.
    pub async fn get_remote_public_key(&self) -> Vec<u8> {
        self.inner.lock().await.get_remote_public_key()
    }

    async fn handle_incoming_messages(
        is_dead: Arc<AtomicBool>,
        inner_stream: Arc<Mutex<InnerStream>>,
        message_buf: Arc<Mutex<VecDeque<M>>>,
        new_msg_notify: Arc<Notify>,
    ) -> Result<(), Error> {
        while let Ok(res) = inner_stream.lock().await.try_read().await {
            if is_dead.load(Ordering::Relaxed) {
                return Ok(());
            };

            let bytes = match res {
                Some(bytes) => bytes,
                None => continue,
            };

            let netwrk_message: NetwrkMessage<M> = match decode(&bytes) {
                Ok(netwrk_message) => netwrk_message,
                Err(e) => {
                    warn!("Failed to decode netwrk message: {}", e);
                    continue;
                }
            };

            match netwrk_message {
                NetwrkMessage::Message(msg) => {
                    message_buf.lock().await.push_back(msg);
                    new_msg_notify.notify_waiters();
                }

                NetwrkMessage::Disconnect => {
                    is_dead.store(true, Ordering::Release);
                    return Ok(());
                }
            };

            tokio::time::sleep(MESSAGE_PROCESSING_INTERVALL).await;
        }

        Ok(())
    }

    /// Is [`NetwrkStream`] dead.
    pub fn is_dead(&self) -> bool {
        self.is_dead.load(Ordering::Relaxed)
    }

    /// Generate a new [`SerializableKeypair`].
    ///
    /// This [`SerializableKeypair`] can be stored.
    pub fn generate_keypair() -> SerializableKeypair {
        InnerStream::generate_keypair()
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

    use crate::inner_stream::HandshakeType;

    use super::Stream;

    const ADDR: &'static str = "127.0.0.1:0";

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    enum TestMessage {
        Foo,
        Bar,
    }

    #[tokio::test]
    async fn test_netwrk_stream() {
        let (mut stream, mut other_stream) = get_netwrk_streams().await;

        stream.send(TestMessage::Foo).await.unwrap();

        assert_eq!(other_stream.wait_until_receive().await, TestMessage::Foo);

        other_stream.send(TestMessage::Bar).await.unwrap();

        assert_eq!(stream.wait_until_receive().await, TestMessage::Bar);

        assert!(!stream.is_dead());
        assert!(!other_stream.is_dead());

        stream.close().await.unwrap();

        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(other_stream.is_dead());
        other_stream.close().await.unwrap();
    }

    #[tokio::test]
    async fn generate_keypair() {
        let _ = Stream::<TestMessage>::generate_keypair();
    }

    #[tokio::test]
    async fn test_local_address() {
        let (stream, other_stream) = get_netwrk_streams().await;

        let _ = stream.local_address().await.unwrap();
        let _ = other_stream.local_address().await.unwrap();
    }

    #[tokio::test]
    async fn test_remote_address() {
        let (stream, other_stream) = get_netwrk_streams().await;

        let _ = stream.remote_address().await.unwrap();
        let _ = other_stream.remote_address().await.unwrap();
    }

    async fn get_netwrk_streams() -> (Stream<TestMessage>, Stream<TestMessage>) {
        let (stream, other_stream) = get_streams(ADDR).await;

        let other_handle = tokio::spawn(Stream::from_stream(
            other_stream,
            None,
            HandshakeType::Responder,
        ));

        let handle = tokio::spawn(Stream::from_stream(stream, None, HandshakeType::Initiator));

        let (stream, _) = handle.await.unwrap().unwrap();
        let other_stream = other_handle.await.unwrap().map(|(v, _)| v).unwrap();

        (stream, other_stream)
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
