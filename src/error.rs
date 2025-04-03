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
    #[error("std io error")]
    IOError(#[from] std::io::Error),
    #[error("get system time error")]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("unknown linktype [{linktype}]")]
    UnknownLinkType { linktype: u32 },
}
