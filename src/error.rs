use thiserror::Error;

#[repr(C)]
#[derive(Error, Debug)]
pub enum PcaptureError {
    // lib
    #[error("unhandled channel type")]
    UnhandledChannelType,
    #[error("unable to create channel: {e}")]
    UnableCreateChannel { e: String },
    #[error("std io error")]
    IOError(#[from] std::io::Error),
    #[error("get system time error")]
    SystemTimeError(#[from] std::time::SystemTimeError),

    // pcap errors
    #[error("unknown linktype [{linktype}]")]
    UnknownLinkType { linktype: u32 },

    // pcapng errors
    #[error("get cpu model info error")]
    GetSystemInfoError,
    #[error("unknown block type [{blocktype}]")]
    UnknownBlockType { blocktype: u32 },
    #[error("unsupported block type [{blockname}]")]
    UnsupportedBlockType { blockname: String },

    // filter errors
    #[error("{msg}")]
    ShouldHaveValueError { msg: String },
    #[error("parse [{parameter}] to [{target}] error: {e}")]
    ValueError {
        parameter: String,
        target: String,
        e: String,
    },
    #[error("unknown operator [{op}]")]
    UnknownOperator { op: String },

    // libpcap errors
    #[error("call libpcap get error: {msg}")]
    LibpcapError { msg: String },
    #[error("ffi nul error")]
    NulError(#[from] std::ffi::NulError),
    #[error("send stop singal failed")]
    SendError(#[from] std::sync::mpsc::SendError<bool>),
}
