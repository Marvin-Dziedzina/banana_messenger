use banana_crypto::transport::{Handshake, HandshakeRole, Keypair, PublicKey, Transport};
use bytes::Bytes;
use futures::{SinkExt, StreamExt, TryStreamExt, future::poll_fn};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{info, trace};

use crate::Error;

#[derive(Debug)]
pub struct EncryptedSocket {
    /// Sender and receiver
    sink: Framed<TcpStream, LengthDelimitedCodec>,
    /// En- and decryption
    transport: Transport,

    buf: Box<[u8; u16::MAX as usize]>,
}

impl EncryptedSocket {
    /// Create a new initiator [`InnerStream`] from a address. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    #[inline]
    pub async fn new_initiator<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<Keypair>,
    ) -> Result<(Self, Keypair), Error> {
        Self::from_tcp_stream(
            TcpStream::connect(addr).await?,
            keypair,
            HandshakeRole::Initiator,
        )
        .await
    }

    /// Create a new responder [`InnerStream`] from a address. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    #[inline]
    pub async fn new_responder<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<Keypair>,
    ) -> Result<(Self, Keypair), Error> {
        Self::from_tcp_stream(
            TcpStream::connect(addr).await?,
            keypair,
            HandshakeRole::Responder,
        )
        .await
    }

    /// Create a [`InnerStream`] from a [`TcpStream`]. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    #[inline]
    pub async fn from_tcp_stream(
        tcp_stream: TcpStream,
        keypair: Option<Keypair>,
        handshake_role: HandshakeRole,
    ) -> Result<(Self, Keypair), Error> {
        let (handshake, keypair) = match handshake_role {
            HandshakeRole::Initiator => Handshake::new(keypair, handshake_role)?,
            HandshakeRole::Responder => Handshake::new(keypair, handshake_role)?,
        };

        Self::from_handshake(tcp_stream, handshake)
            .await
            .map(|v| (v, keypair))
    }

    /// Create [`InnerStream`] from a [`TcpStream`] and [`snow::HandshakeState`].
    #[inline]
    pub async fn from_handshake(
        tcp_stream: TcpStream,
        handshake: Handshake,
    ) -> Result<Self, Error> {
        let mut sink = Framed::new(tcp_stream, LengthDelimitedCodec::new());

        let transport = Self::handshake(&mut sink, handshake).await?;

        Ok(Self {
            sink,
            transport,
            buf: Box::new([0u8; u16::MAX as usize]),
        })
    }

    /// Send bytes to the target.
    ///
    /// # Errors
    ///
    /// Will result in either [`Error::Snow`] or [`Error::Io`] if the encryption or the stream fails.
    #[inline]
    pub async fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let len = self.transport.write_message(bytes, &mut *self.buf)?;
        self.sink
            .send(Bytes::copy_from_slice(&self.buf[..len]))
            .await?;

        Ok(())
    }

    /// Reads a message from stream. Yield once a message available and read.
    ///
    /// # Errors
    ///
    /// Will result in a [`Error::Io`] if a the stream errors.
    #[inline]
    pub async fn read(&mut self) -> Result<Option<&[u8]>, Error> {
        let bytes = match self.sink.try_next().await? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        self.transport_read(&bytes).await
    }

    /// Try to read from stream. Returns immediately when no message is available.
    pub async fn try_read(&mut self) -> Result<Option<&[u8]>, Error> {
        use std::task::Poll;

        let bytes = match poll_fn(|cx| match self.sink.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Ok(Some(bytes))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(Error::Io(e))),
            Poll::Ready(None) => Poll::Ready(Err(Error::Dead)),
            Poll::Pending => Poll::Ready(Ok(None)),
        })
        .await
        {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };

        self.transport_read(&bytes).await
    }

    #[inline]
    async fn transport_read(&mut self, bytes: &[u8]) -> Result<Option<&[u8]>, Error> {
        let len = match self.transport.read_message(bytes, &mut *self.buf) {
            Ok(bytes) => bytes,
            Err(e) => return Err(Error::TransportError(e)),
        };

        Ok(Some(&self.buf[..len]))
    }

    /// Get the remote public key.
    #[inline]
    pub fn remote_public_key(&self) -> PublicKey {
        self.transport.remote_public_key()
    }

    /// Get the local address.
    #[inline]
    pub fn local_address(&self) -> Result<std::net::SocketAddr, Error> {
        Ok(self.sink.get_ref().local_addr()?)
    }

    /// Get the remote address.
    #[inline]
    pub fn remote_address(&self) -> Result<std::net::SocketAddr, Error> {
        Ok(self.sink.get_ref().peer_addr()?)
    }

    #[inline]
    async fn handshake(
        sink: &mut Framed<TcpStream, LengthDelimitedCodec>,
        handshake: Handshake,
    ) -> Result<Transport, Error> {
        match handshake.get_handshake_role() {
            HandshakeRole::Initiator => Self::initiator_handshake(sink, handshake).await,
            HandshakeRole::Responder => Self::responder_handshake(sink, handshake).await,
        }
    }

    async fn initiator_handshake(
        sink: &mut Framed<TcpStream, LengthDelimitedCodec>,
        mut initiator: Handshake,
    ) -> Result<Transport, Error> {
        let mut buf = [0u8; 65535];

        // Send ephemeral public key
        trace!("Initiator: Send ephemeral public key");
        let len = initiator.write_message(&mut buf)?;
        sink.send(Bytes::copy_from_slice(&buf[..len])).await?;
        trace!("Initiator: Sent ephemeral public key");

        // Receive ephemeral and static public keys
        trace!("Initiator: Receive ephemeral and static public keys");
        let bytes = sink.next().await.unwrap()?;
        initiator.read_message(&bytes, &mut buf)?;
        trace!("Initiator: Received ephemeral and static public keys");

        // Send static public key
        trace!("Initiator: Send static public key");
        let len = initiator.write_message(&mut buf)?;
        sink.send(Bytes::copy_from_slice(&buf[..len])).await?;
        trace!("Initiator: Sent static public key");

        let transport = Transport::try_from(initiator)?;

        info!("Initiator handshake successful");

        Ok(transport)
    }

    async fn responder_handshake(
        sink: &mut Framed<TcpStream, LengthDelimitedCodec>,
        mut responder: Handshake,
    ) -> Result<Transport, Error> {
        let mut buf = [0u8; 65535];

        // Receive ephemeral public key
        trace!("Responder: Receive ephemeral public key");
        let bytes = sink.next().await.unwrap()?;
        let _ = responder.read_message(&bytes, &mut buf)?;
        trace!("Responder: Received ephemeral public key");

        // Send ephemeral and static public keys
        trace!("Responder: Send ephemeral and static public keys");
        let len = responder.write_message(&mut buf)?;
        sink.send(Bytes::copy_from_slice(&buf[..len])).await?;
        trace!("Responder: Sent ephemeral and static public keys");

        // Receive static public key
        trace!("Responder: Receive static public key");
        let bytes = sink.next().await.unwrap()?;
        responder.read_message(&bytes, &mut buf)?;
        trace!("Responder: Received static public key");

        let transport = Transport::try_from(responder)?;

        info!("Responder handshake successful");

        Ok(transport)
    }
}

#[cfg(test)]
mod test_inner_stream {
    use std::time::Duration;

    use serde::{Deserialize, Serialize};
    use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

    use crate::{encrypted_socket::EncryptedSocket, netwrk_test::init_logger};

    use super::HandshakeRole;

    const ADDR: &'static str = "127.0.0.1:0";

    #[derive(Debug, Clone, Serialize, Deserialize)]
    enum TestMessage {
        Msg(String),
    }

    #[tokio::test]
    async fn test_send_receive_stream() {
        let (mut stream, mut other_stream) = get_inner_streams().await;

        let msg1 = "Test MSG".as_bytes();
        let msg2 = "Second".as_bytes();
        stream.send(msg1).await.unwrap();

        tokio::time::sleep(Duration::from_millis(1)).await;

        let bytes1 = other_stream.read().await.unwrap().unwrap();
        assert_eq!(bytes1, msg1);

        other_stream.send(msg2).await.unwrap();

        let bytes2 = stream.read().await.unwrap().unwrap();
        assert_eq!(bytes2, msg2);
    }

    #[tokio::test]
    async fn test_local_address() {
        let (stream, other_stream) = get_inner_streams().await;

        let _ = stream.local_address().unwrap();
        let _ = other_stream.local_address().unwrap();
    }

    #[tokio::test]
    async fn test_remote_address() {
        let (stream, other_stream) = get_inner_streams().await;

        let _ = stream.remote_address().unwrap();
        let _ = other_stream.remote_address().unwrap();
    }

    #[tokio::test]
    async fn test_get_inner_streams() {
        let _ = get_inner_streams();
    }

    #[tokio::test]
    async fn test_establish_connection() {
        establish_connection(ADDR).await;
    }

    async fn get_inner_streams() -> (EncryptedSocket, EncryptedSocket) {
        let (stream, other_stream) = establish_connection(ADDR).await;

        let other = tokio::spawn(EncryptedSocket::from_tcp_stream(
            other_stream,
            None,
            HandshakeRole::Responder,
        ));
        let handle = tokio::spawn(EncryptedSocket::from_tcp_stream(
            stream,
            None,
            HandshakeRole::Initiator,
        ));

        (
            handle.await.unwrap().map(|(v, _)| v).unwrap(),
            other.await.unwrap().map(|(v, _)| v).unwrap(),
        )
    }

    async fn establish_connection<A: ToSocketAddrs + Clone + std::marker::Send + 'static>(
        addr: A,
    ) -> (TcpStream, TcpStream) {
        init_logger();

        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let other_stream_handle = tokio::spawn(TcpStream::connect(addr));

        let (stream, _) = listener.accept().await.unwrap();
        let other_stream = other_stream_handle.await.unwrap().unwrap();

        (stream, other_stream)
    }
}
