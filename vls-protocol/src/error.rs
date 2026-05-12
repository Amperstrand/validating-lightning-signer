use alloc::string::String;
use alloc::string::ToString;
use bitcoin::consensus::encode::Error as BitcoinError;
use core::fmt::{Display, Formatter};
use serde_bolt::bitcoin;

/// Error
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    UnexpectedType(u16),
    BadFraming,
    /// Bitcoin consensus decoding error
    Bitcoin(String),
    /// Includes the message type for trailing bytes
    TrailingBytes(usize, u16),
    /// A framed message whose type is not known to this signer.
    /// Contains the unrecognized message type and the size of the message body
    /// (excluding the 2-byte type prefix).
    UnknownMessageType(u16, usize),
    ShortRead,
    MessageTooLarge,
    Eof,
    Io(String),
    DeveloperField,
}

// convert bitcoin consensus decode error to our error
impl From<BitcoinError> for Error {
    fn from(e: BitcoinError) -> Self {
        Error::Bitcoin(e.to_string())
    }
}

impl From<serde_bolt::io::Error> for Error {
    fn from(e: serde_bolt::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

/// Result
pub type Result<T> = core::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::UnexpectedType(t) => write!(f, "unexpected message type #{}", t),
            Error::BadFraming => write!(f, "bad framing"),
            Error::Bitcoin(e) => write!(f, "bitcoin consensus decode error: {}", e),
            Error::TrailingBytes(n, t) => {
                write!(f, "{} trailing bytes after message #{}", n, t)
            }
            Error::UnknownMessageType(t, body_len) => {
                write!(f, "UNHANDLED MESSAGE #{} ({} body bytes)", t, body_len)
            }
            Error::ShortRead => write!(f, "short read"),
            Error::MessageTooLarge => write!(f, "message too large"),
            Error::Eof => write!(f, "unexpected EOF"),
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::DeveloperField => write!(f, "developer field not allowed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
