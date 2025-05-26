use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use log::warn;
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

    /// Start listening for incoming connections.
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

    pub async fn close(self) -> Result<(), Error> {
        if !self.is_dead.load(Ordering::Acquire) {
            self.is_dead.store(true, Ordering::Release);
        };

        if let Some(listener_task) = self.listener_task {
            listener_task.await??;
        };

        Ok(())
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
mod test_listener {}
