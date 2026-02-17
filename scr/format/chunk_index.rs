use std::io::{Read, Write};

use crate::format::NONCE_SIZE;
use crate::format::TAG_SIZE;

#[derive(Clone, Debug)]
pub struct ChunkIndexEntry {
    pub offset: u64,
    pub compressed_size: u32,
    pub original_size: u32,
    pub nonce: [u8; NONCE_SIZE],
    pub tag: [u8; TAG_SIZE],
}

impl ChunkIndexEntry {
    pub const SIZE: usize = 8 + 4 + 4 + NONCE_SIZE + TAG_SIZE;

    pub fn new(offset: u64, compressed_size: u32, original_size: u32, nonce: [u8; NONCE_SIZE], tag: [u8; TAG_SIZE]) -> Self {
        Self {
            offset,
            compressed_size,
            original_size,
            nonce,
            tag,
        }
    }

    pub fn read<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        reader.read_exact(&mut buf)?;
        Self::from_bytes(&buf)
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.to_bytes())
    }

    pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> std::io::Result<Self> {
        let offset = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let compressed_size = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let original_size = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[16..16 + NONCE_SIZE]);
        
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&bytes[16 + NONCE_SIZE..16 + NONCE_SIZE + TAG_SIZE]);

        Ok(Self {
            offset,
            compressed_size,
            original_size,
            nonce,
            tag,
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..8].copy_from_slice(&self.offset.to_le_bytes());
        buf[8..12].copy_from_slice(&self.compressed_size.to_le_bytes());
        buf[12..16].copy_from_slice(&self.original_size.to_le_bytes());
        buf[16..16 + NONCE_SIZE].copy_from_slice(&self.nonce);
        buf[16 + NONCE_SIZE..16 + NONCE_SIZE + TAG_SIZE].copy_from_slice(&self.tag);
        buf
    }
}

#[derive(Clone, Debug, Default)]
pub struct ChunkIndex {
    pub entries: Vec<ChunkIndexEntry>,
}

impl ChunkIndex {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn read<R: Read>(reader: &mut R, count: u32) -> std::io::Result<Self> {
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            entries.push(ChunkIndexEntry::read(reader)?);
        }
        Ok(Self { entries })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        for entry in &self.entries {
            entry.write(writer)?;
        }
        Ok(())
    }

    pub fn total_len(&self) -> u32 {
        (self.entries.len() * ChunkIndexEntry::SIZE) as u32
    }

    pub fn push(&mut self, entry: ChunkIndexEntry) {
        self.entries.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_index_entry_roundtrip() {
        let nonce = [1u8; NONCE_SIZE];
        let tag = [2u8; TAG_SIZE];
        let entry = ChunkIndexEntry::new(1024, 512, 1024, nonce, tag);
        
        let bytes = entry.to_bytes();
        let parsed = ChunkIndexEntry::from_bytes(&bytes).unwrap();
        
        assert_eq!(entry.offset, parsed.offset);
        assert_eq!(entry.compressed_size, parsed.compressed_size);
        assert_eq!(entry.original_size, parsed.original_size);
        assert_eq!(entry.nonce, parsed.nonce);
        assert_eq!(entry.tag, parsed.tag);
    }
}