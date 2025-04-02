use thiserror::Error;

#[derive(Error, Debug)]
pub enum PcaptureError {
    #[error("unhandled channel type")]
    UnhandledChannelType,
    #[error("unable to create channel: {e}")]
    UnableCreateChannel { e: String },
    #[error("unable to found interface: {i}")]
    UnableFoundInterface { i: String },
    #[error("capture the packet error: {e}")]
    CapturePacketError { e: String },
    #[error("create file error")]
    CreateFileError(#[from] std::io::Error),
    #[error("bincode read file error")]
    BincodeReadError(#[from] bincode::error::DecodeError),
    #[error("bincode write file error")]
    BincodeWriteError(#[from] bincode::error::EncodeError),
    #[error("get system time error")]
    SystemTimeError(#[from] std::time::SystemTimeError),
}
