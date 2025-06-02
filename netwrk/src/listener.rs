use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use banana_crypto::transport::{HandshakeRole, Keypair, Transport};
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpListener, ToSocketAddrs},
    sync::{Mutex, mpsc::error::TryRecvError},
    task::JoinHandle,
};
use tracing::warn;

use crate::{Error, get_atomic_bool, reliable_stream::ReliableStream, set_atomic_bool};

#[derive(Debug)]
pub struct Listener<M>
where
    M: std::fmt::Debug + Serialize + for<'a> Deserialize<'a> + Send + 'static,
{
    is_dead: Arc<AtomicBool>,

    listener: Option<Arc<Mutex<TcpListener>>>,

    listener_task: Option<JoinHandle<Result<(), Error>>>,
    connection_receiver: tokio::sync::mpsc::Receiver<(ReliableStream<M>, SocketAddr)>,
    connection_sender: tokio::sync::mpsc::Sender<(ReliableStream<M>, SocketAddr)>,

    keypair: Arc<Keypair>,
    max_buffered_messages: usize,
}

impl<M> Listener<M>
where
    M: std::fmt::Debug + Serialize + for<'a> Deserialize<'a> + Send + 'static,
{
    /// Bind the listener to a address `A`. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    pub async fn bind<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<Keypair>,
        max_buffered_connections: usize,
        max_buffered_messages: usize,
    ) -> Result<(Self, Keypair), Error> {
        let keypair = match keypair {
            Some(keypair) => keypair,
            None => Transport::generate_keypair(),
        };

        let (connection_sender, connection_receiver) =
            tokio::sync::mpsc::channel(max_buffered_connections);

        Ok((
            Self {
                is_dead: Arc::new(AtomicBool::new(false)),

                listener: Some(Arc::new(Mutex::new(TcpListener::bind(addr).await?))),
                connection_receiver,
                connection_sender,

                listener_task: None,

                keypair: Arc::new(keypair.clone()),
                max_buffered_messages,
            },
            keypair,
        ))
    }

    /// Await the next incoming connection.
    ///
    /// This function will yield once a connection is established.
    ///
    /// # Errors
    ///
    /// Will result in [`Error::AlreadyRunning`] if the accept listener is already running.
    pub async fn accept(&self) -> Result<Option<(ReliableStream<M>, SocketAddr)>, Error> {
        if self.listener_task.is_some() {
            return Err(Error::AlreadyRunning);
        };

        Self::accept_incoming(
            &self.get_tcp_listener()?,
            &self.keypair,
            self.max_buffered_messages,
        )
        .await
    }

    /// Accept the next connection if ready else return [`None`].
    ///
    /// # Errors
    ///
    /// Will result in [`Error::AlreadyRunning`] if the accept listener is already running.
    pub async fn try_accept(&self) -> Result<Option<(ReliableStream<M>, SocketAddr)>, Error> {
        if self.listener_task.is_some() {
            return Err(Error::AlreadyRunning);
        };

        Self::try_accept_incoming(
            &self.get_tcp_listener()?,
            &self.keypair,
            self.max_buffered_messages,
        )
        .await
    }

    /// Get a established connection if available. Only usable if the listener is running.
    ///
    /// # Errors
    ///
    /// Will result in a [`Error::NotRunning`] if the listener task is not running.
    pub async fn get_connection(
        &mut self,
    ) -> Result<Option<(ReliableStream<M>, SocketAddr)>, Error> {
        if self.listener_task.is_none() {
            return Err(Error::NotRunning);
        };

        match self.connection_receiver.try_recv() {
            Ok(conn) => Ok(Some(conn)),
            Err(e) => match e {
                TryRecvError::Empty => Ok(None),
                TryRecvError::Disconnected => panic!("Listener needs to be running"),
            },
        }
    }

    /// Get all currently established connections.
    ///
    /// # Errors
    ///
    /// Will result in a [`Error::NotRunning`] if the listener task is not running.
    pub fn get_connection_batch(&mut self) -> Result<Vec<(ReliableStream<M>, SocketAddr)>, Error> {
        if self.listener_task.is_none() {
            return Err(Error::NotRunning);
        };

        Ok(Self::get_connection_batch_from_receiver(
            &mut self.connection_receiver,
            &self.is_dead,
        ))
    }

    /// Wait until a connection is established. If no is available wait for one. Only usable id the listener is running.
    ///
    /// # Errors
    ///
    /// Will result in a [`Error::NotRunning`] if the listener task is not running.
    pub async fn wait_until_connect(
        &mut self,
    ) -> Result<Option<(ReliableStream<M>, SocketAddr)>, Error> {
        if self.listener_task.is_none() {
            return Err(Error::NotRunning);
        };

        Ok(self.connection_receiver.recv().await)
    }

    fn get_connection_batch_from_receiver(
        connection_receiver: &mut tokio::sync::mpsc::Receiver<(ReliableStream<M>, SocketAddr)>,
        is_dead: &Arc<AtomicBool>,
    ) -> Vec<(ReliableStream<M>, SocketAddr)> {
        use tokio::sync::mpsc::error::TryRecvError;

        let mut buf = Vec::new();
        loop {
            match connection_receiver.try_recv() {
                Ok(conn) => buf.push(conn),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    set_atomic_bool(is_dead, true);
                }
            }
        }

        buf
    }

    /// Start the listener that listens for incoming connections.
    ///
    /// # Errors
    ///
    /// Will result in a [`Error::AlreadyRunning`] if the listener is already running.
    pub async fn listen(&mut self) -> Result<(), Error> {
        if self.listener_task.is_none() {
            self.listener_task = Some(tokio::spawn(Self::listener_task(
                self.is_dead.clone(),
                self.get_tcp_listener()?,
                self.connection_sender.clone(),
                self.keypair.clone(),
                self.max_buffered_messages,
            )));
            Ok(())
        } else {
            Err(Error::AlreadyRunning)
        }
    }

    /// Stop the listener.
    pub async fn stop_listening(&mut self) -> Result<Vec<(ReliableStream<M>, SocketAddr)>, Error> {
        if let Some(listener_task) = std::mem::take(&mut self.listener_task) {
            set_atomic_bool(&self.is_dead, true);

            listener_task.await??;

            set_atomic_bool(&self.is_dead, false);
        };

        Ok(Self::get_connection_batch_from_receiver(
            &mut self.connection_receiver,
            &self.is_dead,
        ))
    }

    async fn listener_task(
        is_dead: Arc<AtomicBool>,
        listener: Arc<Mutex<TcpListener>>,
        connection_sender: tokio::sync::mpsc::Sender<(ReliableStream<M>, SocketAddr)>,
        keypair: Arc<Keypair>,
        max_buffered_messages: usize,
    ) -> Result<(), Error> {
        loop {
            if get_atomic_bool(&is_dead) {
                return Ok(());
            };

            tokio::task::yield_now().await;

            let res_conn =
                Self::try_accept_incoming(&listener, &keypair, max_buffered_messages).await;

            let conn = match res_conn {
                Ok(Some(conn)) => conn,
                Ok(None) => continue,
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            if let Err(e) = connection_sender.send(conn).await {
                warn!("Failed to send connection through channel: {}", e);
            };
        }
    }

    /// Close the listener and return all established connections that where not collected. The [`VecDeque`] will be empty if the listener task was never started.
    pub async fn close(&mut self) -> Result<Vec<(ReliableStream<M>, SocketAddr)>, Error> {
        let res = self.stop_listening().await;
        {
            std::mem::take(&mut self.listener);
        }

        set_atomic_bool(&self.is_dead, true);

        res
    }

    /// Get the local address.
    #[inline]
    pub async fn local_address(&self) -> Result<SocketAddr, Error> {
        Ok(self.get_tcp_listener()?.lock().await.local_addr()?)
    }

    async fn accept_incoming(
        listener: &Arc<Mutex<TcpListener>>,
        keypair: &Arc<Keypair>,
        max_buffered_messages: usize,
    ) -> Result<Option<(ReliableStream<M>, SocketAddr)>, Error> {
        let raw_conn = listener.lock().await.accept().await?;

        Self::reliable_stream_from_raw_conn(raw_conn, keypair, max_buffered_messages).await
    }

    async fn try_accept_incoming(
        listener: &Arc<Mutex<TcpListener>>,
        keypair: &Arc<Keypair>,
        max_buffered_messages: usize,
    ) -> Result<Option<(ReliableStream<M>, SocketAddr)>, Error> {
        use futures::future::poll_fn;
        use std::task::Poll;

        let listener_lock = listener.lock().await;
        let raw_conn = poll_fn(|cx| match listener_lock.poll_accept(cx) {
            Poll::Ready(Ok(conn)) => Poll::Ready(Some(conn)),
            Poll::Ready(Err(_)) => Poll::Ready(None),
            Poll::Pending => Poll::Ready(None),
        })
        .await;

        let conn = match raw_conn {
            Some(conn) => conn,
            None => return Ok(None),
        };

        Self::reliable_stream_from_raw_conn(conn, keypair, max_buffered_messages).await
    }

    async fn reliable_stream_from_raw_conn(
        (tcp_stream, addr): (tokio::net::TcpStream, SocketAddr),
        keypair: &Arc<Keypair>,
        max_buffered_messages: usize,
    ) -> Result<Option<(ReliableStream<M>, SocketAddr)>, Error> {
        Ok(Some((
            ReliableStream::from_stream(
                tcp_stream,
                Some(keypair.as_ref().to_owned()),
                HandshakeRole::Responder,
                max_buffered_messages,
                Duration::from_secs(30),
            )
            .await?
            .0,
            addr,
        )))
    }

    fn get_tcp_listener(&self) -> Result<Arc<Mutex<TcpListener>>, Error> {
        match &self.listener {
            Some(listener) => Ok(listener.clone()),
            None => Err(Error::Dead),
        }
    }
}

#[cfg(test)]
mod test_listener {
    use std::time::Duration;

    use banana_crypto::transport::Keypair;
    use serde::{Deserialize, Serialize};
    use tokio::{net::ToSocketAddrs, task::JoinHandle};

    use crate::{listener::Listener, reliable_stream::ReliableStream};

    const ADDR: &str = "127.0.0.1:0";
    const MAX_BUFFERED_CONNECTIONS: usize = 2;
    const MAX_BUFFERED_MESSAGES: usize = 10;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    enum TestMessage {
        Foo,
        Bar,
    }

    #[tokio::test]
    async fn test_listener() {
        let (mut listener, keypair) = Listener::<TestMessage>::bind(
            ADDR,
            None,
            MAX_BUFFERED_CONNECTIONS,
            MAX_BUFFERED_MESSAGES,
        )
        .await
        .unwrap();
        let local_addr = listener.local_address().await.unwrap();

        let initiator_handle = connect_stream_to_listener(local_addr).await;

        let (mut stream, _) = listener.accept().await.unwrap().unwrap();
        let (mut remote_stream, remote_keypair) = initiator_handle.await.unwrap().unwrap();

        stream.send(TestMessage::Foo).await.unwrap();

        let recv_msg = remote_stream.receive().await.unwrap();
        assert_eq!(TestMessage::Foo, recv_msg);
        assert_eq!(keypair.public_key, remote_stream.remote_public_key().await);
        assert_eq!(remote_keypair.public_key, stream.remote_public_key().await);

        listener.close().await.unwrap();

        let other_handle = connect_stream_to_listener(local_addr).await;

        assert!(other_handle.await.unwrap().is_err());
    }

    async fn connect_stream_to_listener<A: ToSocketAddrs + Send + 'static>(
        addr: A,
    ) -> JoinHandle<Result<(ReliableStream<TestMessage>, Keypair), crate::Error>> {
        tokio::spawn(ReliableStream::connect_initiator(
            addr,
            None,
            MAX_BUFFERED_MESSAGES,
            Duration::from_secs(60),
        ))
    }
}
