# Banana Messenger

Cryptographic algorithms:
- Password hashing: Argon2id
- Asymmetric encryption: p384
- Symmetric encryption: chacha20poly1305
- Signatures: Ed25519

Database: rusqlite

## Banana Messenger Core

The Banana Messenger Core is a crate that every front end can simply use to access the Banana Messenger network. The Banana Messenger Core has a easy and carefree API. Easy means that its simple to use and hard to get something wrong. Carefree means that the Banana Messenger Core cares about all keys, encryption, decryption, storing, sending, receiving, users, chats, chat histories and all related data. That is needed so that app developers can easily use this API without compromising important data.

First the Banana Messenger Core needs to get unlocked. For that a Username and Password is needed. The Password is used to decrypt all data corresponding to the selected account. The account is determined by the Username The Banana Messenger Core supports multiple logins.

A new account can be created by supplying a Username and Password.

On startup after login the Banana Messenger Core should connect to a Banana Train from a list of trusted Banana Trains. It should choose the one with the lowest ping.

To open a new chat with a user the Banana Messenger Core can search for a user by name or public key by requesting a Banana Train. The Banana Train will respond with the found accounts. If one is picked the Banana Train will respond with the public key of the target account.

To send a message into a chat the chat needs to be opened first. When the chat is open a message can be sent. This message will get encrypted by Banana Messenger Core and sent to the current Banana Train connection.

The connected Banana Train will send new messages to the Banana Messenger Core. These messages will be decrypted and stored in the corresponding chat.

Chats can be deleted and no data of them should be left.

While being logged in the current account can be deleted. All data and chats connected to the current account will be deleted when deleting the account.

While a account is active the user can log out. All data will be encrypted and stored. The Banana Train connection will be teriminated.

While being logged out all accounts can be deleted.

The Banana Messenger Core has a limited amount of tries to log in. If all 4 tries are used all accounts and associated data will be deleted. Before the last try is entered there should be a warning.

## Banana Train

The Banana Train is the server where Banana Messenger Cores can connect to. The Banana Train serves as a connection point to communicate with other Banana Messenger Cores.

#### Banana Messenger Core

The Banana Messenger Core announces its presents to a Banana Train. All Banana Trains maintain a list of all connections they have directly and all connections that other Banana Trains have. This is nessecary to rout messages correctly. These lists will be shared between all Banana Trains.

When a Banana Train receives a message from a Banana Messenger Core the Banana Train will first look up if the receiveing Banana Messenger Core is registered at the current Banana Train. If the account is found it will be checked if the account is currently online. If the account is online the message will be sent to the accounts Banana Messenger Core. If the account is offline the message will be put into a outbox and will be forwarded when the account comes online the next time. This outbox will delete messages that are older than the maximal outbox message age. If the account is not found locally then all other Banana Train accounts are checked. If a match is found the message will be relayed to the recievers Banana Train.

#### Banana Train

Banana Trains communicate with each other.

Not yet
