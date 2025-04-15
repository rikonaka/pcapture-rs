use thiserror::Error;

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
    #[error("The new interface [{new}] is the same as the previous one [{pre}]")]
    SameInterafceError { new: String, pre: String },
    #[error("This function can only be used in pcapng format")]
    PcapNgOnlyError,

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

    // transport
    #[error("bincode encode error")]
    BincodeEncodeError(#[from] bincode::error::EncodeError),
    #[error("bincode decode error")]
    BincodeDecodeError(#[from] bincode::error::DecodeError),

    // transport
    #[error("The received data length is incorrect ({recv_len} != {decode_len})")]
    RecvDataIncorrectError { recv_len: usize, decode_len: usize },
}
