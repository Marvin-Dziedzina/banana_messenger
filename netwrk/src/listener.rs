use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use log::{debug, warn};
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpListener, ToSocketAddrs},
    sync::{Mutex, Notify},
    task::JoinHandle,
};

use crate::{
    CONNECTION_ACCEPTION_TIMEOUT, Error,
    inner_stream::{HandshakeType, InnerStream},
    serialisable_keypair::SerializableKeypair,
    stream::Stream,
};

#[derive(Debug)]
pub struct Listener<M>
where
    M: Serialize + for<'a> Deserialize<'a> + Send + 'static,
{
    is_dead: Arc<AtomicBool>,

    listener: Arc<Mutex<TcpListener>>,

    listener_task: Option<JoinHandle<Result<(), Error>>>,
    stream_buf: Arc<Mutex<VecDeque<(Stream<M>, SocketAddr)>>>,
    new_connection_notify: Arc<Notify>,

    keypair: Arc<SerializableKeypair>,
}

impl<M> Listener<M>
where
    M: Serialize + for<'a> Deserialize<'a> + Send + 'static,
{
    /// Bind the listener to a address `A`. Will return a newly generated [`SerializableKeypair`] if `keypair` is [`None`] otherwise it will return the supplied [`SerializableKeypair`].
    pub async fn bind<A: ToSocketAddrs>(
        addr: A,
        keypair: Option<SerializableKeypair>,
    ) -> Result<(Self, SerializableKeypair), Error> {
        let keypair = match keypair {
            Some(keypair) => keypair,
            None => InnerStream::generate_keypair(),
        };

        Ok((
            Self {
                is_dead: Arc::new(AtomicBool::new(false)),

                listener: Arc::new(Mutex::new(TcpListener::bind(addr).await?)),

                listener_task: None,
                stream_buf: Arc::new(Mutex::new(VecDeque::new())),
                new_connection_notify: Arc::new(Notify::new()),

                keypair: Arc::new(keypair.clone()),
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
    pub async fn accept(&self) -> Result<(Stream<M>, SocketAddr), Error> {
        if self.listener_task.is_some() {
            return Err(Error::AlreadyRunning);
        };

        Self::accept_incoming(&self.listener, &self.keypair).await
    }

    /// Accept the next connection if ready else return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Will result in [`Error::AlreadyRunning`] if the accept listener is already running.
    pub async fn try_accept(&self) -> Result<Option<(Stream<M>, SocketAddr)>, Error> {
        use futures::future::poll_fn;
        use std::task::Poll;

        if self.listener_task.is_some() {
            return Err(Error::AlreadyRunning);
        };

        let listener_lock = self.listener.lock().await;
        let raw_conn = poll_fn(|cx| match listener_lock.poll_accept(cx) {
            Poll::Ready(Ok(conn)) => Poll::Ready(Some(conn)),
            Poll::Ready(Err(_)) => Poll::Ready(None),
            Poll::Pending => Poll::Ready(None),
        })
        .await;

        let conn = match raw_conn {
            Some((tcp_stream, addr)) => (
                Stream::from_stream(
                    tcp_stream,
                    Some(self.keypair.as_ref().to_owned()),
                    HandshakeType::Responder,
                )
                .await?
                .0,
                addr,
            ),
            None => return Ok(None),
        };

        Ok(Some(conn))
    }

    /// Get a established connection if available. Only usable if the listener is running.
    ///
    /// # Errors
    ///
    /// Will result in a [`Error::NotRunning`] if the listener task is not running.
    pub async fn get_connection(&mut self) -> Result<Option<(Stream<M>, SocketAddr)>, Error> {
        if self.listener_task.is_none() {
            return Err(Error::NotRunning);
        };

        Ok(self.stream_buf.lock().await.pop_front())
    }

    /// Wait until a connection is established. If no is available wait for one. Only usable id the listener is running.
    ///
    /// # Errors
    ///
    /// Will result in a [`Error::NotRunning`] if the listener task is not running.
    pub async fn wait_until_connect(&mut self) -> Result<Option<(Stream<M>, SocketAddr)>, Error> {
        loop {
            if self.listener_task.is_none() {
                return Err(Error::NotRunning);
            };

            {
                let mut stream_buf_lock = self.stream_buf.lock().await;
                if !stream_buf_lock.is_empty() {
                    return Ok(stream_buf_lock.pop_front());
                };
            }

            tokio::select! {
                _ = self.new_connection_notify.notified() => {
                    debug!("Wait until connect notified");
                }
                _ = tokio::time::sleep(CONNECTION_ACCEPTION_TIMEOUT) => {
                    debug!("Wait until connect timeout. Manually checking");
                }
            };
        }
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
                self.listener.clone(),
                self.stream_buf.clone(),
                self.new_connection_notify.clone(),
                self.keypair.clone(),
            )));
            Ok(())
        } else {
            Err(Error::AlreadyRunning)
        }
    }

    /// Stop the listener.
    pub async fn stop_listening(&mut self) -> Result<VecDeque<(Stream<M>, SocketAddr)>, Error> {
        if let Some(listener_task) = std::mem::take(&mut self.listener_task) {
            self.is_dead.store(true, Ordering::Release);

            listener_task.await??;

            self.is_dead.store(false, Ordering::Release);
        };

        Ok(std::mem::take(&mut *self.stream_buf.lock().await))
    }

    async fn listener_task(
        is_dead: Arc<AtomicBool>,
        listener: Arc<Mutex<TcpListener>>,
        stream_buf: Arc<Mutex<VecDeque<(Stream<M>, SocketAddr)>>>,
        new_connection_notify: Arc<Notify>,
        keypair: Arc<SerializableKeypair>,
    ) -> Result<(), Error> {
        loop {
            if is_dead.load(Ordering::Acquire) {
                return Ok(());
            };

            let res_conn = tokio::select! {
                conn = Self::accept_incoming(&listener, &keypair) => {conn}
                _ = tokio::time::sleep(CONNECTION_ACCEPTION_TIMEOUT) => {
                    continue
                }
            };

            let conn = match res_conn {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            stream_buf.lock().await.push_back(conn);
            new_connection_notify.notify_waiters();
        }
    }

    /// Close the listener and return all established connections that where not collected. The [`VecDeque`] will be empty if the listener task was never started.
    pub async fn close(mut self) -> Result<VecDeque<(Stream<M>, SocketAddr)>, Error> {
        let res = self.stop_listening().await;

        self.is_dead.store(false, Ordering::Release);

        res
    }

    /// Get the local address.
    pub async fn local_address(&self) -> Result<SocketAddr, Error> {
        self.listener.lock().await.local_addr().map_err(Error::Io)
    }

    async fn accept_incoming(
        listener: &Arc<Mutex<TcpListener>>,
        keypair: &Arc<SerializableKeypair>,
    ) -> Result<(Stream<M>, SocketAddr), Error> {
        let (tcp_stream, addr) = listener.lock().await.accept().await?;
        let (stream, _) = Stream::from_stream(
            tcp_stream,
            Some(keypair.as_ref().to_owned()),
            HandshakeType::Responder,
        )
        .await?;

        Ok((stream, addr))
    }
}

#[cfg(test)]
mod test_listener {
    use std::time::Duration;

    use serde::{Deserialize, Serialize};
    use tokio::{net::ToSocketAddrs, task::JoinHandle};

    use crate::{listener::Listener, stream::Stream};

    const ADDR: &str = "127.0.0.1:0";

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    enum TestMessage {
        Foo,
        Bar,
    }

    #[tokio::test]
    async fn test_listener() {
        let (listener, keypair) = Listener::<TestMessage>::bind(ADDR, None).await.unwrap();
        let local_addr = listener.local_address().await.unwrap();

        let initiator_handle = connect_stream_to_listener(local_addr).await;

        let (mut stream, _) = listener.accept().await.unwrap();
        let (mut remote_stream, remote_keypair) = initiator_handle.await.unwrap().unwrap();

        stream.send(TestMessage::Foo).await.unwrap();

        tokio::time::sleep(Duration::from_millis(1)).await;

        let recv_msg = remote_stream.receive().await.unwrap();
        assert_eq!(TestMessage::Foo, recv_msg);
        assert_eq!(keypair.public, remote_stream.remote_public_key().await);
        assert_eq!(remote_keypair.public, stream.remote_public_key().await);

        listener.close().await.unwrap();

        let other_handle = connect_stream_to_listener(local_addr).await;

        assert!(other_handle.await.unwrap().is_err());
    }

    async fn connect_stream_to_listener<A: ToSocketAddrs + Send + 'static>(
        addr: A,
    ) -> JoinHandle<
        Result<
            (
                Stream<TestMessage>,
                crate::serialisable_keypair::SerializableKeypair,
            ),
            crate::Error,
        >,
    > {
        tokio::spawn(Stream::connect_initiator(addr, None))
    }
}
