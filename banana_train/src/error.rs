use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Conversion failed")]
    FailedConversion(String),
    #[error("Dead")]
    Dead,
}
