use std::io;

/// Errors produced by configuration parsing and proxy handshakes.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("invalid rule: {0}")]
    Rule(String),
    #[error("socks5: {0}")]
    Socks5(String),
    #[error("http connect: {0}")]
    Http(String),
    #[error("{0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
