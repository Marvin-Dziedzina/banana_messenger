use std::{fmt::Display, io};

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};

const VERSION: u8 = 0;
const MAGIC: u16 = 0xABCD;

const VERSION_BE_BYTES: [u8; 1] = VERSION.to_be_bytes();
const MAGIC_BE_BYTES: [u8; 2] = MAGIC.to_be_bytes();

const VERSION_LEN: usize = 1;
const MAGIC_LEN: usize = 2;
const DATA_LENGTH_LEN: usize = 4;
const PRE_MESSAGE_LEN: usize = MAGIC_LEN + VERSION_LEN + DATA_LENGTH_LEN;

type Version = u8;
type Magic = u16;
type DataLength = u32;

type OwnVersion = Version;
type RemoteVersion = Version;

#[derive(Debug)]
pub enum Error {
    VersionMismatch((OwnVersion, RemoteVersion)),
    CorruptConnection,
    Io(io::Error),
    UnexpectedEof(String),
    TypeConversion(String),
    DataTooLarge,
}

// The protocol is as follows:
// [MAGIC: u16][VERSION: u8][DATA_LENGTH: u32][DATA]

/// Reads a packet from a reader.
///
/// Writes the read bytes into `buf`.
/// Return the number of bytes read into `buf`.
pub async fn read_packet<R>(reader: &mut R, buf: &mut Vec<u8>) -> Result<usize, Error>
where
    R: AsyncRead + Unpin,
{
    let packet_len = read_packet_header(reader).await?;
    read_packet_data(reader, packet_len, buf).await
}

/// Recovers a corrupted reader.
/// The next packet can be read by calling [`read_packet`].
pub async fn recover<R>(reader: &mut R) -> Result<(), Error>
where
    R: AsyncRead + AsyncBufRead + Unpin,
{
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Err(Error::UnexpectedEof(
                "Recover reached a unexpected EOF".to_string(),
            ));
        };

        let idx = buf.windows(2).position(|window| window == MAGIC_BE_BYTES);
        if let Some(idx) = idx {
            reader.consume(idx);
            break;
        };

        let len = buf.len();
        reader.consume(len);
    }

    Ok(())
}

/// Read the packet header.
async fn read_packet_header<R>(reader: &mut R) -> Result<u32, Error>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; PRE_MESSAGE_LEN];
    reader.read_exact(&mut header).await?;

    let magic: Magic = Magic::from_be_bytes(header[..MAGIC_LEN].try_into().unwrap());
    // Check magic
    if magic != MAGIC {
        return Err(Error::CorruptConnection);
    };

    let version: Version = Version::from_be_bytes(
        header[MAGIC_LEN..MAGIC_LEN + VERSION_LEN]
            .try_into()
            .unwrap(),
    );
    // Check version
    if version != VERSION {
        return Err(Error::VersionMismatch((VERSION, version)));
    };

    Ok(DataLength::from_be_bytes(
        header[MAGIC_LEN + VERSION_LEN..PRE_MESSAGE_LEN]
            .try_into()
            .unwrap(),
    ))
}

/// Read the packet data.
///
/// Returns the number of bytes read.
async fn read_packet_data<R>(
    reader: &mut R,
    packet_len: DataLength,
    buf: &mut Vec<u8>,
) -> Result<usize, Error>
where
    R: AsyncRead + Unpin,
{
    // Convert length u32 to length usize
    let resize_len = match usize::try_from(packet_len) {
        Ok(resize_len) => resize_len,
        Err(e) => {
            return Err(Error::TypeConversion(format!(
                "Failed to convert u32 to usize while reading packet data: {}",
                e
            )));
        }
    };
    buf.resize(resize_len, 0);
    reader.read_exact(buf).await?;

    Ok(buf.len())
}

/// Write data to a writer.
///
/// Data will be encoded.
pub async fn write_packet<W>(writer: &mut W, data: &[u8]) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    encode_packet(data, &mut buf)?;
    writer.write_all(&buf).await?;
    writer.flush().await?;

    Ok(())
}

/// Encode the packet.
pub fn encode_packet(data: &[u8], buf: &mut Vec<u8>) -> Result<usize, Error> {
    if data.len() > DataLength::MAX as usize {
        return Err(Error::DataTooLarge);
    };

    buf.clear();
    buf.reserve(PRE_MESSAGE_LEN + data.len());
    buf.extend(&MAGIC_BE_BYTES);
    buf.extend(&VERSION_BE_BYTES);
    buf.extend(&(data.len() as u32).to_be_bytes());
    buf.extend(data);

    Ok(buf.len())
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionMismatch((own, remote)) => {
                write!(f, "Version Mismatch: (Own: {}, Remote: {})", own, remote)
            }
            Self::CorruptConnection => write!(f, "Connection Corrupt"),
            Self::Io(e) => write!(f, "Io Error: {}", e),
            Self::UnexpectedEof(e) => write!(f, "Unexpected EOF: {}", e),
            Self::TypeConversion(e) => write!(f, "Type Conversion Error: {}", e),
            Self::DataTooLarge => write!(f, "Data too large"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

#[cfg(test)]
mod test_protocol {
    use std::io::Cursor;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};

    use crate::protocol::{
        DATA_LENGTH_LEN, DataLength, Error, MAGIC, MAGIC_LEN, Magic, PRE_MESSAGE_LEN, VERSION,
        VERSION_LEN, Version, encode_packet,
    };

    use super::{read_packet, recover, write_packet};

    const TEST_PACKET: &[u8] = b"My Test Packet";

    #[tokio::test]
    async fn test_read_write() {
        let mut writer = BufWriter::new(Vec::new());
        write_packet(&mut writer, TEST_PACKET).await.unwrap();
        writer.flush().await.unwrap();

        let mut reader = BufReader::new(Cursor::new(writer.into_inner()));
        let mut buf = Vec::new();
        read_packet(&mut reader, &mut buf).await.unwrap();

        assert_eq!(buf, TEST_PACKET);
    }

    #[tokio::test]
    async fn test_recover() {
        let mut writer = BufWriter::new(Vec::new());
        write_packet(&mut writer, TEST_PACKET).await.unwrap();
        write_packet(&mut writer, TEST_PACKET).await.unwrap();
        writer.flush().await.unwrap();

        let mut reader = BufReader::new(Cursor::new(writer.into_inner()));
        reader.read_u8().await.unwrap();

        recover(&mut reader).await.unwrap();
        let mut buf = Vec::new();
        read_packet(&mut reader, &mut buf).await.unwrap();

        assert_eq!(buf, TEST_PACKET);
    }

    #[tokio::test]
    async fn test_version_mismatch() {
        // Build a valid packet
        const TEST_PACKET: &[u8] = b"My Test Packet";
        let mut packet = Vec::new();
        encode_packet(TEST_PACKET, &mut packet).unwrap();

        // Corrupt the version‐byte in the header
        //    HEADER = [ MAGIC(2 bytes) | VERSION(1 byte) | LENGTH(4 bytes) | DATA... ]
        let bad_version = VERSION.wrapping_add(1);
        packet[MAGIC_LEN] = bad_version;

        // Try to read it
        let mut reader = BufReader::new(Cursor::new(packet));
        let mut buf = Vec::new();
        let err = read_packet(&mut reader, &mut buf).await.unwrap_err();

        // Assert we got exactly the mismatch variant—and that the remote version is the bad one
        match err {
            Error::VersionMismatch((own, remote)) => {
                assert_eq!(own, VERSION);
                assert_eq!(remote, bad_version);
            }
            other => panic!("expected VersionMismatch, got {:?}", other),
        }
    }

    #[test]
    fn test_prepare_packet() {
        let mut buf = Vec::with_capacity(1);
        let len = super::encode_packet(TEST_PACKET, &mut buf).unwrap();

        assert_eq!(buf.len(), len);

        test_packet(&buf);
    }

    fn test_packet(packet: &[u8]) {
        assert_eq!(
            Magic::from_be_bytes(packet[..MAGIC_LEN].try_into().unwrap()),
            MAGIC
        );
        assert_eq!(
            Version::from_be_bytes(
                packet[MAGIC_LEN..MAGIC_LEN + VERSION_LEN]
                    .try_into()
                    .unwrap()
            ),
            VERSION
        );
        assert_eq!(
            DataLength::from_be_bytes(
                packet[MAGIC_LEN + VERSION_LEN..MAGIC_LEN + VERSION_LEN + DATA_LENGTH_LEN]
                    .try_into()
                    .unwrap()
            ),
            DataLength::try_from(TEST_PACKET.len()).unwrap()
        );
        assert_eq!(&packet[PRE_MESSAGE_LEN..], TEST_PACKET);
    }
}
