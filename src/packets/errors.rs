use std::io;
use thiserror::Error;

use super::SOCKS_VERSION;

#[derive(Debug, Error)]
pub enum ClientHelloError {
    #[error("malformed client hello packet")]
    MalformedPacket,
    #[error("expected protocol version to be {}, but received {0}", SOCKS_VERSION)]
    UnexpectedProtocolVersion(u8),
    #[error("failed IO operation: {0}")]
    IoError(#[from] io::Error),
}

#[derive(Debug, Error)]
pub enum ServerHelloError {
    #[error("no authentication method is acceptable")]
    NoAcceptableAuth,
    #[error("user/pass authentication failed: {0}")]
    AuthError(#[from] UserPassAuthError),
    #[error("failed IO operation: {0}")]
    IoError(#[from] io::Error),
}

#[derive(Debug, Error)]
pub enum UserPassAuthError {
    #[error("user and password did not match")]
    FailedAuth,
    #[error("failed IO operation: {0}")]
    IoError(#[from] io::Error),
}

#[derive(Debug, Error)]
pub enum ClientRequestError {
    #[error("malformed client request packet")]
    MalformedPacket,
    #[error("expected protocol version to be {}, but received {0}", SOCKS_VERSION)]
    UnexpectedProtocolVersion(u8),
    #[error("unsupported BIND command")]
    ErrUnsupportedBindCommand,
    #[error("unsupported UDP ASSOCIATE command")]
    ErrUnsupportedUDPAssociateCommand,
    #[error("unknown request command")]
    ErrUnknownCommand,
    #[error("unknown address type")]
    ErrUnknownAddressType,
    #[error("failed IO operation: {0}")]
    IoError(#[from] io::Error),
}

#[derive(Debug, Error)]
pub enum ServerReplyError {
    #[error("failed IO operation: {0}")]
    IoError(#[from] io::Error),
}
