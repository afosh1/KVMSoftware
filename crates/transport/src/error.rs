use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls config: {0}")]
    Tls(String),
    #[error("connect: {0}")]
    Connect(String),
    #[error("connection closed")]
    Closed,
    #[error("stream reset/aborted: {0}")]
    Stream(String),
    #[error("codec: {0}")]
    Codec(#[from] kvm_proto::codec::CodecError),
    #[error("peer certificate fingerprint not pinned/allowed")]
    FingerprintMismatch,
    #[error("unknown stream kind tag: {0}")]
    UnknownStreamKind(u8),
    #[error("config: {0}")]
    Config(String),
}
