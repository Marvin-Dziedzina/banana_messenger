use banana_crypto::transport::PublicKey;
use serde::{Deserialize, Serialize};

pub type SenderPublicKey = PublicKey;
pub type ReceiverPublicKey = PublicKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BananaMessage {
    /// A user sent a message to the [`BananaTrain`].
    SendMessage((ReceiverPublicKey, Vec<u8>)),
    /// The server relayed a message.
    ForwardedMessage((SenderPublicKey, Vec<u8>)),
    /// The user requests all stored messages to be forwarded.
    ForwardRequest,
}
