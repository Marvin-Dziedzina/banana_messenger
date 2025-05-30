use common::{BananaMessage, SenderPublicKey};
use serde::{Deserialize, Serialize};

use crate::error::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub sender: SenderPublicKey,
    pub message: Vec<u8>,
}

impl Message {
    pub fn new(sender: SenderPublicKey, message: Vec<u8>) -> Self {
        Self { sender, message }
    }
}

impl From<Message> for BananaMessage {
    fn from(message: Message) -> Self {
        Self::ForwardedMessage(message.into())
    }
}

impl From<Message> for (SenderPublicKey, Vec<u8>) {
    fn from(message: Message) -> Self {
        (message.sender, message.message)
    }
}

impl From<(SenderPublicKey, Vec<u8>)> for Message {
    fn from((sender, message): (SenderPublicKey, Vec<u8>)) -> Self {
        Message::new(sender, message)
    }
}

impl TryFrom<BananaMessage> for Message {
    type Error = anyhow::Error;

    fn try_from(banana_message: BananaMessage) -> Result<Self, Self::Error> {
        match banana_message {
            BananaMessage::ForwardedMessage(msg) => Ok(msg.into()),
            _ => Err(Error::FailedConversion("BananaMessage to Message".to_string()).into()),
        }
    }
}
