use bytes::Bytes;
use futures::{SinkExt, StreamExt, TryStreamExt, future::poll_fn};
use log::info;
use snow::TransportState;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::{Error, FramedStream, NOISE_PARAMS, serialisable_keypair::SerializableKeypair};

#[derive(Debug)]
pub struct EncryptedSocket {
    /// Sender and receiver
    sink: FramedStream,
    /// En- and decryption
    transport: TransportState,

    /// Preallocated send buffer.
    pub buf: Box<[u8; u16::MAX as usize]>,
}

impl EncryptedSocket {
    /// Create a new initiator [`InnerStream`] from a address. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    pub async fn new_initiator<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<SerializableKeypair>,
    ) -> Result<(Self, SerializableKeypair), Error> {
        Self::from_tcp_stream(
            TcpStream::connect(addr).await?,
            keypair,
            HandshakeType::Initiator,
        )
        .await
    }

    /// Create a new responder [`InnerStream`] from a address. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    pub async fn new_responder<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<SerializableKeypair>,
    ) -> Result<(Self, SerializableKeypair), Error> {
        Self::from_tcp_stream(
            TcpStream::connect(addr).await?,
            keypair,
            HandshakeType::Responder,
        )
        .await
    }

    /// Create a [`InnerStream`] from a [`TcpStream`]. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    pub async fn from_tcp_stream(
        tcp_stream: TcpStream,
        keypair: Option<SerializableKeypair>,
        handshake_type: HandshakeType,
    ) -> Result<(Self, SerializableKeypair), Error> {
        let builder = snow::Builder::new(NOISE_PARAMS.parse().unwrap());
        let keypair = match keypair {
            Some(ser_keypair) => ser_keypair.into(),
            None => builder.generate_keypair()?,
        };
        let builder = builder.local_private_key(&keypair.private);

        let handshake = match handshake_type {
            HandshakeType::Responder => builder.build_responder(),
            HandshakeType::Initiator => builder.build_initiator(),
        }?;

        Self::from_handshake(tcp_stream, handshake)
            .await
            .map(|v| (v, SerializableKeypair::from(keypair)))
    }

    /// Create [`InnerStream`] from a [`TcpStream`] and [`snow::HandshakeState`].
    pub async fn from_handshake(
        tcp_stream: TcpStream,
        handshake_state: snow::HandshakeState,
    ) -> Result<Self, Error> {
        let mut sink = Self::get_framed_stream(tcp_stream);

        let transport = Self::handshake(&mut sink, handshake_state).await?;

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
    pub async fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let len = self.transport.write_message(bytes, &mut *self.buf)?;
        self.sink
            .send(Bytes::copy_from_slice(&self.buf[..len]))
            .await?;

        Ok(())
    }

    /// Reads a message from stream.
    ///
    /// # Errors
    ///
    /// Will result in a [`Error::Io`] if a the stream errors.
    pub async fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let bytes = match self.sink.try_next().await? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        self.transport_read(&bytes).await
    }

    /// Try to read from stream. Returns immediately when no message is available.
    pub async fn try_read(&mut self) -> Result<Option<Vec<u8>>, Error> {
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

    async fn transport_read(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let len = match self.transport.read_message(bytes, &mut *self.buf) {
            Ok(len) => len,
            Err(e) => return Err(Error::Snow(e)),
        };

        Ok(Some(self.buf[..len].to_vec()))
    }

    /// Get the remote public key.
    pub fn get_remote_public_key(&self) -> Vec<u8> {
        self.transport
            .get_remote_static()
            .expect("Must be available after handshake")
            .to_vec()
    }

    /// Generate a new [`SerializableKeypair`].
    pub fn generate_keypair() -> SerializableKeypair {
        snow::Builder::new(NOISE_PARAMS.parse().unwrap())
            .generate_keypair()
            .expect("Failed to generate new keypair")
            .into()
    }

    /// Get the local address.
    pub fn local_address(&self) -> Result<std::net::SocketAddr, Error> {
        self.sink.get_ref().local_addr().map_err(Error::Io)
    }

    /// Get the remote address.
    pub fn remote_address(&self) -> Result<std::net::SocketAddr, Error> {
        self.sink.get_ref().peer_addr().map_err(Error::Io)
    }

    async fn handshake(
        sink: &mut FramedStream,
        handshake_state: snow::HandshakeState,
    ) -> Result<TransportState, Error> {
        if handshake_state.is_initiator() {
            Self::initiator_handshake(sink, handshake_state).await
        } else {
            Self::responder_handshake(sink, handshake_state).await
        }
    }

    async fn initiator_handshake(
        sink: &mut FramedStream,
        mut initiator: snow::HandshakeState,
    ) -> Result<TransportState, Error> {
        let mut buf = [0u8; 65535];

        // Send ephemeral public key
        let len = initiator.write_message(&[], &mut buf)?;
        sink.send(Bytes::copy_from_slice(&buf[..len])).await?;

        // Receive ephemeral and static public keys
        let bytes = sink.next().await.unwrap()?;
        initiator.read_message(&bytes, &mut buf)?;

        // Send static public key
        let len = initiator.write_message(&[], &mut buf)?;
        sink.send(Bytes::copy_from_slice(&buf[..len])).await?;

        let transport = initiator.into_transport_mode()?;

        info!("Initiator handshake successful");

        Ok(transport)
    }

    async fn responder_handshake(
        sink: &mut FramedStream,
        mut responder: snow::HandshakeState,
    ) -> Result<TransportState, Error> {
        let mut buf = [0u8; 65535];

        // Receive ephemeral public key
        let bytes = sink.next().await.unwrap()?;
        let _ = responder.read_message(&bytes, &mut buf)?;

        // Send ephemeral and static public keys
        let len = responder.write_message(&[], &mut buf)?;
        sink.send(Bytes::copy_from_slice(&buf[..len])).await?;

        // Receive static public key
        let bytes = sink.next().await.unwrap()?;
        responder.read_message(&bytes, &mut buf)?;

        let transport = responder.into_transport_mode()?;

        info!("Responder handshake successful");

        Ok(transport)
    }

    fn get_framed_stream(stream: TcpStream) -> FramedStream {
        Framed::new(stream, LengthDelimitedCodec::new())
    }
}

pub enum HandshakeType {
    Responder,
    Initiator,
}

#[cfg(test)]
mod test_inner_stream {
    use std::time::Duration;

    use futures::{SinkExt, StreamExt};
    use serde::{Deserialize, Serialize};
    use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

    use crate::encrypted_socket::EncryptedSocket;

    use super::HandshakeType;

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
    async fn test_sink() {
        let (stream, other_stream) = establish_connection(ADDR).await;
        let (mut stream, mut other_stream) = (
            EncryptedSocket::get_framed_stream(stream),
            EncryptedSocket::get_framed_stream(other_stream),
        );

        let msg = "Test 1".as_bytes();

        stream.send(msg.into()).await.unwrap();
        let bytes = other_stream.next().await.unwrap().unwrap();

        assert_eq!(msg, bytes);
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
    async fn test_generate_keypair() {
        let _ = EncryptedSocket::generate_keypair();
    }

    #[tokio::test]
    async fn test_get_inner_streams() {
        let _ = get_inner_streams();
    }

    #[tokio::test]
    async fn test_get_framed_stream() {
        let (stream, other_stream) = establish_connection(ADDR).await;
        let _ = EncryptedSocket::get_framed_stream(stream);
        let _ = EncryptedSocket::get_framed_stream(other_stream);
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
            HandshakeType::Responder,
        ));
        let handle = tokio::spawn(EncryptedSocket::from_tcp_stream(
            stream,
            None,
            HandshakeType::Initiator,
        ));

        (
            handle.await.unwrap().map(|(v, _)| v).unwrap(),
            other.await.unwrap().map(|(v, _)| v).unwrap(),
        )
    }

    async fn establish_connection<A: ToSocketAddrs + Clone + std::marker::Send + 'static>(
        addr: A,
    ) -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let other_stream_handle = tokio::spawn(TcpStream::connect(addr));

        let (stream, _) = listener.accept().await.unwrap();
        let other_stream = other_stream_handle.await.unwrap().unwrap();

        (stream, other_stream)
    }
}
