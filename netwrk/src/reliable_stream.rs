use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use banana_crypto::transport::{HandshakeRole, Keypair, PublicKey, Transport};
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpStream, ToSocketAddrs},
    sync::{Mutex, mpsc::error::TryRecvError},
    task::JoinHandle,
};
use tracing::{debug, error, info, trace, warn};

use crate::{
    Error, NetworkMessage, Reason, VERSION_MAJOR_MINOR, decode, encode,
    encrypted_socket::EncryptedSocket, set_atomic_bool,
};

/// A [`ReliableStream`].
#[derive(Debug)]
pub struct ReliableStream<M>
where
    M: std::fmt::Debug + Serialize + for<'a> Deserialize<'a> + Send + 'static,
{
    is_dead: Arc<AtomicBool>,

    inner: Arc<Mutex<EncryptedSocket>>,
    message_receiver: tokio::sync::mpsc::Receiver<M>,

    handle_incoming_task: Option<JoinHandle<Reason>>,
}

impl<M> ReliableStream<M>
where
    M: std::fmt::Debug + Serialize + for<'a> Deserialize<'a> + Send + 'static,
{
    /// Create a new initiator stream. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    pub async fn connect_initiator<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<Keypair>,
        max_buffered_messages: usize,
        connection_timeout: std::time::Duration,
    ) -> Result<(Self, Keypair), Error> {
        Self::connect_handshake(
            addr,
            keypair,
            HandshakeRole::Initiator,
            max_buffered_messages,
            connection_timeout,
        )
        .await
    }

    /// Create a new responder stream. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    pub async fn connect_responder<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<Keypair>,
        max_buffered_messages: usize,
        connection_timeout: std::time::Duration,
    ) -> Result<(Self, Keypair), Error> {
        Self::connect_handshake(
            addr,
            keypair,
            HandshakeRole::Responder,
            max_buffered_messages,
            connection_timeout,
        )
        .await
    }

    /// Connect with a [`HandshakeType`]. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    async fn connect_handshake<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<Keypair>,
        handshake_role: HandshakeRole,
        max_buffered_messages: usize,
        connection_timeout: std::time::Duration,
    ) -> Result<(Self, Keypair), Error> {
        let (inner, keypair) = match handshake_role {
            HandshakeRole::Initiator => EncryptedSocket::new_initiator(addr, keypair).await,
            HandshakeRole::Responder => EncryptedSocket::new_responder(addr, keypair).await,
        }?;
        let netwrk_stream =
            Self::from_inner_stream(inner, max_buffered_messages, connection_timeout).await?;

        Ok((netwrk_stream, keypair))
    }

    /// Create a [`Stream`] from a [`TcpStream`] and [`HandshakeType`]. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    pub async fn from_stream(
        tcp_stream: TcpStream,
        keypair: Option<Keypair>,
        handshake_role: HandshakeRole,
        max_buffered_messages: usize,
        connection_timeout: std::time::Duration,
    ) -> Result<(Self, Keypair), Error> {
        let (inner, keypair) =
            EncryptedSocket::from_tcp_stream(tcp_stream, keypair, handshake_role).await?;
        let netwrk_stream =
            Self::from_inner_stream(inner, max_buffered_messages, connection_timeout).await?;

        Ok((netwrk_stream, keypair))
    }

    /// Create a [`Stream`] from a [`InnerStream`].
    pub async fn from_inner_stream(
        inner_stream: EncryptedSocket,
        max_buffered_messages: usize,
        connection_timeout: std::time::Duration,
    ) -> Result<Self, Error> {
        let is_dead = Arc::new(AtomicBool::new(false));
        let inner = Arc::new(Mutex::new(inner_stream));
        let (message_sender, message_receiver) = tokio::sync::mpsc::channel(max_buffered_messages);

        let is_dead_c = is_dead.clone();
        let inner_c = inner.clone();
        let handle_incoming_task = tokio::spawn(Self::handle_incoming_messages(
            is_dead_c,
            connection_timeout,
            inner_c,
            message_sender,
        ));

        let reliable_stream = Self {
            is_dead,

            inner,
            message_receiver,

            handle_incoming_task: Some(handle_incoming_task),
        };

        Self::send_netwrk_message(
            &mut reliable_stream.inner.lock().await,
            NetworkMessage::Version(VERSION_MAJOR_MINOR.to_string()),
        )
        .await?;

        Ok(reliable_stream)
    }

    /// Send a message `M`.
    ///
    /// # Errors
    ///
    /// Will result in [`Error::Dead`] if the stream is dead.
    pub async fn send(&mut self, message: M) -> Result<(), Error> {
        if self.is_dead() {
            return Err(Error::Dead);
        };

        Self::send_message(&mut self.inner.lock().await, message).await
    }

    /// Send a batch of messages `M`.
    ///
    /// # Error
    ///
    /// Will result in [`Error::Dead`] if the stream is dead.
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

    /// Receive the next message. Yield once a message is available.
    pub async fn receive(&mut self) -> Option<M> {
        if self.is_closed() {
            return None;
        };

        self.message_receiver.recv().await
    }

    /// Receive a available message. Returns [`None`] if no messages are available at the moment.
    ///
    /// This function should not be run in a loop without any await in a single threaded runtime. If done it will always return [`None`].
    pub fn try_receive(&mut self) -> Option<M> {
        if self.is_closed() {
            return None;
        };

        match self.message_receiver.try_recv() {
            Ok(msg) => Some(msg),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                set_atomic_bool(&self.is_dead, true);
                None
            }
        }
    }

    /// Receive all available messages. Yields when at least one messages where read.
    pub async fn receive_batch(&mut self) -> Option<Vec<M>> {
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

    /// Receive all currently available messages.
    ///
    /// This function should not be run in a loop without any await in a single threaded runtime. If done it will always return [`None`].
    pub fn try_receive_batch(&mut self) -> Option<Vec<M>> {
        if self.is_closed() {
            return None;
        };

        let mut buf = Vec::new();
        loop {
            match self.message_receiver.try_recv() {
                Ok(msg) => buf.push(msg),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    set_atomic_bool(&self.is_dead, true);
                    break;
                }
            }
        }

        if !buf.is_empty() { Some(buf) } else { None }
    }

    /// Close the connection. After that call you can not send and receive any messages anymore.
    ///
    /// The current messages in buffer will be returned.
    pub async fn close(&mut self) -> Result<(Reason, Option<Vec<M>>), Error> {
        if !self.is_dead() {
            Self::send_netwrk_message(
                &mut self.inner.lock().await,
                NetworkMessage::<M>::Disconnect(Reason::Disconnect),
            )
            .await?;
            set_atomic_bool(&self.is_dead, true);
        };

        let msgs = self.try_receive_batch();
        self.message_receiver.close();
        let reason = match std::mem::take(&mut self.handle_incoming_task) {
            Some(handle_incoming_task) => handle_incoming_task.await?,
            None => Reason::Dead,
        };
        info!("Close: {}", reason);

        Ok((reason, msgs))
    }

    async fn handle_incoming_messages(
        is_dead: Arc<AtomicBool>,
        connection_timeout: std::time::Duration,
        inner_stream: Arc<Mutex<EncryptedSocket>>,
        message_sender: tokio::sync::mpsc::Sender<M>,
    ) -> Reason {
        use std::time::{Duration, Instant};

        use tokio::sync::mpsc::error::TrySendError;

        let stream_start = Instant::now();

        let mut last_heard = Instant::now();
        let mut last_timeout_ping = Instant::now();
        let mut round_trip_time = Duration::from_millis(200);

        trace!(
            "Connection Timeout: {} ms",
            connection_timeout.mul_f32(0.7).as_millis()
        );

        loop {
            if is_dead.load(Ordering::Relaxed) {
                return Reason::Dead;
            };

            tokio::task::yield_now().await;

            {
                // Check if timeouted or if ping should be sent.
                let now = Instant::now();
                let now_since_last_heard = now.duration_since(last_heard);
                if now_since_last_heard > connection_timeout {
                    set_atomic_bool(&is_dead, true);
                    debug!("Stream timeouted");
                    continue;
                } else if now_since_last_heard // TODO: May be a case where it won't ever ping.
                >= connection_timeout.mul_f32(0.7)
                    && now.duration_since(last_timeout_ping) > round_trip_time * 2
                {
                    if let Err(e) = Self::send_netwrk_message(
                        &mut inner_stream.lock().await,
                        NetworkMessage::Ping(stream_start.elapsed().as_nanos()),
                    )
                    .await
                    {
                        warn!("Failed to send ping: {}", e);
                        continue;
                    };

                    debug!("Ping sent");
                    last_timeout_ping = Instant::now();
                };
            }

            let mut inner_lock = inner_stream.lock().await;
            while let Ok(Some(bytes)) = inner_lock.try_read().await {
                let netwrk_message: NetworkMessage<M> = match decode(bytes) {
                    Ok(netwrk_message) => netwrk_message,
                    Err(e) => {
                        // TODO: Consider dropping connection when too frequent malformed packages arrive.
                        warn!("Failed to decode network message: {}", e);
                        continue;
                    }
                };

                // Random is for offset of pings. The streams should not fire their pings at the same time every time.
                last_heard =
                    Instant::now() - Duration::from_millis((rand::random::<u8>() % 100) as u64);
                trace!(
                    "Got network message at {}: {:?}",
                    stream_start.elapsed().as_millis() as u64,
                    netwrk_message
                );

                match netwrk_message {
                    NetworkMessage::Message(msg) => {
                        match message_sender.try_send(msg) {
                            Ok(_) => (),
                            Err(TrySendError::Full(_)) => {
                                warn!("Channel full: messages are being dropped");
                            }
                            Err(TrySendError::Closed(_)) => {
                                error!("Channel receiver was dropped");
                                set_atomic_bool(&is_dead, true);
                            }
                        };
                    }

                    NetworkMessage::Version(v) => {
                        info!(
                            "Netwrk Version: {{ Local: {}; Remote: {} }}",
                            VERSION_MAJOR_MINOR, v
                        );
                        if v != VERSION_MAJOR_MINOR {
                            set_atomic_bool(&is_dead, true);
                            return Reason::VersionMismatch;
                        }
                    }

                    NetworkMessage::Ping(timestamp) => {
                        debug!("Ping received");
                        if let Err(e) = Self::send_netwrk_message(
                            &mut inner_lock,
                            NetworkMessage::Pong(timestamp),
                        )
                        .await
                        {
                            warn!("Failed to send Pong: {}", e);
                        };
                        debug!("Pong sent")
                    }
                    NetworkMessage::Pong(timestamp) => {
                        debug!("Pong received");

                        let rtt_nanos = stream_start.elapsed().as_nanos() - timestamp;
                        let secs = (rtt_nanos / 1_000_000_000) as u64;
                        let sub_nanos = (rtt_nanos % 1_000_000_000) as u32;
                        round_trip_time = Duration::new(secs, sub_nanos);

                        info!("RTT: {} ms", round_trip_time.as_millis());
                    }

                    NetworkMessage::Disconnect(reason) => {
                        info!("Received disconnect: {}", reason);
                        set_atomic_bool(&is_dead, true);
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

    /// Get the local address.
    pub async fn local_address(&self) -> Result<std::net::SocketAddr, Error> {
        self.inner.lock().await.local_address()
    }

    /// Get the remote address.
    pub async fn remote_address(&self) -> Result<std::net::SocketAddr, Error> {
        self.inner.lock().await.remote_address()
    }

    /// Get the remote public key.
    pub async fn remote_public_key(&self) -> PublicKey {
        self.inner.lock().await.remote_public_key()
    }

    /// Generate a new [`SerializableKeypair`].
    ///
    /// This [`SerializableKeypair`] can be stored.
    pub fn generate_keypair() -> Keypair {
        Transport::generate_keypair()
    }
}

#[cfg(test)]
mod reliable_stream_test {
    use std::time::Duration;

    use banana_crypto::transport::{HandshakeRole, Keypair};
    use serde::{Deserialize, Serialize};
    use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
    use tracing::debug;

    use crate::netwrk_test::init_logger;

    use super::ReliableStream;

    const ADDR: &'static str = "127.0.0.1:0";
    const MAX_BUFFERED_MESSAGES: usize = 64;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

        assert_eq!(key.public_key, other_stream.remote_public_key().await);
        assert_eq!(other_key.public_key, stream.remote_public_key().await);

        tokio::time::sleep(Duration::from_secs(3)).await;

        assert!(!stream.is_dead());
        assert!(!other_stream.is_dead());

        stream.close().await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(other_stream.is_dead());
        other_stream.close().await.unwrap();
    }

    #[tokio::test]
    async fn stress_test() {
        let ((mut stream, _), (mut other_stream, _)) = get_reliable_streams().await;

        let send_task = tokio::spawn(async move {
            for i in 0..10000 {
                debug!("Stream Iter: {}", i);
                stream.send(TestMessage::Foo).await.unwrap();

                // Clear channel
                let _ = stream.receive_batch().await;
            }

            tokio::time::sleep(Duration::from_millis(300)).await;

            assert!(stream.close().await.is_ok());
        });

        let other_send_task = tokio::spawn(async move {
            for i in 0..10000 {
                debug!("Other Stream Iter: {}", i);
                other_stream.send(TestMessage::Bar).await.unwrap();

                // Cleas channel
                let _ = other_stream.receive_batch().await;
            }

            tokio::time::sleep(Duration::from_millis(300)).await;

            assert!(other_stream.close().await.is_ok());
        });

        send_task.await.unwrap();
        other_send_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_try_receive() {
        let ((mut stream, _), (mut other_stream, _)) = get_reliable_streams().await;

        assert!(stream.send(TestMessage::Foo).await.is_ok());

        loop {
            tokio::task::yield_now().await;

            if let Some(msg) = other_stream.try_receive() {
                assert_eq!(msg, TestMessage::Foo);
                break;
            };
        }

        assert!(stream.close().await.is_ok());
        assert!(other_stream.close().await.is_ok());
    }

    #[tokio::test]
    async fn test_receive_batch() {
        let ((mut stream, _), (mut other_stream, _)) = get_reliable_streams().await;

        let msgs = vec![TestMessage::Foo, TestMessage::Bar, TestMessage::Bar];

        assert!(stream.send_batch(msgs.clone()).await.is_ok());

        assert_eq!(msgs, other_stream.receive_batch().await.unwrap());

        assert!(stream.close().await.is_ok());
        assert!(other_stream.close().await.is_ok());
    }

    #[tokio::test]
    async fn test_try_receive_batch() {
        let ((mut stream, _), (mut other_stream, _)) = get_reliable_streams().await;

        let msgs = vec![TestMessage::Foo, TestMessage::Bar, TestMessage::Foo];

        assert!(stream.send_batch(msgs.clone()).await.is_ok());

        loop {
            tokio::task::yield_now().await;

            if let Some(received) = other_stream.try_receive_batch() {
                assert_eq!(received, msgs);
                break;
            };
        }

        assert!(stream.close().await.is_ok());
        assert!(other_stream.close().await.is_ok());
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
        (ReliableStream<TestMessage>, Keypair),
        (ReliableStream<TestMessage>, Keypair),
    ) {
        let (stream, other_stream) = get_streams(ADDR).await;

        let other_handle = tokio::spawn(ReliableStream::from_stream(
            other_stream,
            None,
            HandshakeRole::Responder,
            MAX_BUFFERED_MESSAGES,
            Duration::from_secs(1),
        ));

        let handle = tokio::spawn(ReliableStream::from_stream(
            stream,
            None,
            HandshakeRole::Initiator,
            MAX_BUFFERED_MESSAGES,
            Duration::from_secs(1),
        ));

        let pair = handle.await.unwrap().unwrap();
        let other_pair = other_handle.await.unwrap().unwrap();

        (pair, other_pair)
    }

    async fn get_streams<A: ToSocketAddrs>(addr: A) -> (TcpStream, TcpStream) {
        init_logger();

        let listener = TcpListener::bind(addr).await.unwrap();
        let other_addr = listener.local_addr().unwrap();

        let stream_task = tokio::spawn(TcpStream::connect(other_addr));

        let (stream, _) = listener.accept().await.unwrap();
        let other_stream = stream_task.await.unwrap().unwrap();

        (stream, other_stream)
    }

    #[tokio::test]
    async fn test_get_reliable_streams() {
        let _ = get_reliable_streams().await;
    }

    #[tokio::test]
    async fn test_get_streams() {
        let _ = get_streams(ADDR).await;
    }
}
