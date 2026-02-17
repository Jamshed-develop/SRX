pub const MAGIC: &[u8; 4] = b"SRX1";
pub const FORMAT_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 32;
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;
pub const FOOTER_SIZE: usize = 32;
pub const SALT_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub magic: [u8; 4],
    pub version: u8,
    pub flags: u16,
    pub header_len: u32,
    pub metadata_len: u32,
    pub chunk_index_len: u32,
    pub chunk_count: u32,
    pub reserved: [u8; 9],
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Flags: u16 {
        const ENCRYPTED = 0x01;
        const COMPRESSED = 0x02;
        const STREAMING = 0x04;
    }
}

impl Header {
    pub fn new(flags: Flags, metadata_len: u32, chunk_index_len: u32, chunk_count: u32) -> Self {
        Self {
            magic: *MAGIC,
            version: FORMAT_VERSION,
            flags: flags.bits(),
            header_len: HEADER_SIZE as u32,
            metadata_len,
            chunk_index_len,
            chunk_count,
            reserved: [0; 9],
        }
    }

    pub fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut buf)?;
        Self::from_bytes(&buf)
    }

    pub fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.to_bytes())
    }

    pub fn from_bytes(bytes: &[u8; HEADER_SIZE]) -> std::io::Result<Self> {
        if &bytes[0..4] != MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid magic bytes",
            ));
        }
        Ok(Self {
            magic: [bytes[0], bytes[1], bytes[2], bytes[3]],
            version: bytes[4],
            flags: u16::from_le_bytes([bytes[5], bytes[6]]),
            header_len: u32::from_le_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]),
            metadata_len: u32::from_le_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]),
            chunk_index_len: u32::from_le_bytes([bytes[15], bytes[16], bytes[17], bytes[18]]),
            chunk_count: u32::from_le_bytes([bytes[19], bytes[20], bytes[21], bytes[22]]),
            reserved: bytes[23..32].try_into().unwrap(),
        })
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4] = self.version;
        buf[5..7].copy_from_slice(&self.flags.to_le_bytes().as_slice());
        buf[7..11].copy_from_slice(&self.header_len.to_le_bytes().as_slice());
        buf[11..15].copy_from_slice(&self.metadata_len.to_le_bytes().as_slice());
        buf[15..19].copy_from_slice(&self.chunk_index_len.to_le_bytes().as_slice());
        buf[19..23].copy_from_slice(&self.chunk_count.to_le_bytes().as_slice());
        buf[23..32].copy_from_slice(&self.reserved);
        buf
    }

    pub fn flags(&self) -> Flags {
        Flags::from_bits_truncate(self.flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = Header::new(Flags::ENCRYPTED | Flags::COMPRESSED, 100, 200, 5);
        let bytes = header.to_bytes();
        let parsed = Header::from_bytes(&bytes).unwrap();
        assert_eq!(header.magic, parsed.magic);
        assert_eq!(header.version, parsed.version);
        assert_eq!(header.flags, parsed.flags);
        assert_eq!(header.metadata_len, parsed.metadata_len);
        assert_eq!(header.chunk_count, parsed.chunk_count);
    }

    #[test]
    fn invalid_magic_rejected() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..4].copy_from_slice(b"XXXX");
        let result = Header::from_bytes(&bytes);
        assert!(result.is_err());
    }
}