use thiserror::Error;

#[repr(C)]
#[derive(Error, Debug)]
pub enum PcaptureError {
    // lib
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
    #[error("The write file descriptor does not exist")]
    FileDescriptorDoesNotExist,
    #[error("Try to unlock {name} error: {e}")]
    UnlockGlobalVariableError { name: String, e: String },
    #[error("This function can only be used in pcapng format")]
    PcapNgOnlyError,
    #[error("can not get thread status, thread id {thread_id}")]
    UnableGetThreadStatus { thread_id: u32 },

    // pcap errors
    #[error("unknown linktype [{linktype}]")]
    UnknownLinkType { linktype: u32 },

    // pcapng errors
    #[error("get cpu model info error")]
    GetSystemInfoError,
    #[error("subnetwork lib error")]
    SubnetworkError(#[from] subnetwork::SubnetworkError),
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
    #[error("lock global var {var} failed")]
    LockGlobalVarFailed { var: String },
    #[error("call libpcap get error: {msg}")]
    LibpcapError { msg: String },
    #[error("ffi nul error")]
    NulError(#[from] std::ffi::NulError),
}
