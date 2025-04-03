// General Block Structure:
// from https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html
//                        1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 0 |                          Block Type                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 4 |                      Block Total Length                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 8 /                          Block Body                           /
//   /              variable length, padded to 32 bits               /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                      Block Total Length                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

pub struct GeneralBlock {
    /// Block Type (32 bits):
    /// A unique unsigned value that identifies the block.
    /// Values whose Most Significant Bit (MSB) is equal to 1 are reserved for local use.
    pub block_type: u32,
    /// Block Total Length (32 bits):
    /// An unsigned value giving the total size of this block, in octets.
    /// For instance, the length of a block that does not have a body is 12 octets:
    /// 4 octets for the Block Type, 4 octets for the initial Block Total Length and 4 octets for the trailing Block Total Length.
    pub block_total_length: u32,
    /// Block Body: content of the block.
    pub block_body: Vec<u8>,
    /// Block Total Length:
    /// Total size of this block, in octets.
    /// This field is duplicated to permit backward file navigation.
    pub block_total_length_2: u32,
}
