use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Conversion failed")]
    FailedConversion(String),
    #[error("Failed to forward message")]
    FailedToForward,
    #[error("Dead")]
    Dead,
    #[error("Channel closed")]
    ChannelClosed,
}
