# Banana Messenger

Banana Messenger is a simple encrypted messenger that allows you to send private messages and create groups.

## Banana Messenger

Banana Messenger requires a simple account that is not linked with your personal data.

There is a small set of data you need to provide such as:
- Username
- Password

You shouldn't have used the data anywhere other than Banana Messenger. This is for your privacy and security.

All data should get stored encrypted locally.

On login all basic data for that specific user should get decrypted and loaded. If for example a chat gets opened the data from that chat should get decrypted and loaded.

Short:
- Data is encrypted
- Loing Data:
  - Username used for local users
  - Username used to start private messages
  - Password used for local encryption
- Connect to Banana Train for communication
- Encrypted private messaging
- Encrypted group chats
- Send encrypted messages
- Receive encrypted messages and decrypt them

## Banana Train

Everyone can host a Banana Train (The Server).

The Banana Trains maintain a shared list of all currently connected users.

If you know the public key of another user or a group chat, you can read and send messages from/to the user or group chat.

The public key is used as public id but users can also be found by username.

Short:
- Clients:
  - Add client that announces to list
  - Sync the client list with other servers
  - Send user public key if requested
- Messaging
  - Receive messages from client
  - Relay to destination server if client not directly connected
  - Relay to client if directly connected 
  - If client not online, cache message until online if cache flag active