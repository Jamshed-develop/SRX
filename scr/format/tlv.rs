use std::io::{Read, Write};

pub const TLV_ALIGNMENT: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tag(pub u16);

impl Tag {
    pub const COMPRESSION_ALGO: Tag = Tag(0x0001);
    pub const ENCRYPTION_ALGO: Tag = Tag(0x0002);
    pub const CHUNK_SIZE: Tag = Tag(0x0003);
    pub const ORIGINAL_SIZE: Tag = Tag(0x0004);
    pub const ORIGINAL_FILENAME: Tag = Tag(0x0005);
    pub const SALT: Tag = Tag(0x0010);
    pub const ARGON2_MEMORY: Tag = Tag(0x0011);
    pub const ARGON2_TIME: Tag = Tag(0x0012);
    pub const ARGON2_PARALLELISM: Tag = Tag(0x0013);
    pub const VENDOR: Tag = Tag(0xFFFF);
}

#[derive(Clone, Debug)]
pub struct TlvEntry {
    pub tag: Tag,
    pub value: Vec<u8>,
}

impl TlvEntry {
    pub fn new(tag: Tag, value: Vec<u8>) -> Self {
        Self { tag, value }
    }

    pub fn read<R: Read>(reader: &mut R) -> std::io::Result<Option<Self>> {
        let mut header = [0u8; 4];
        match reader.read_exact(&mut header) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }

        let tag = u16::from_le_bytes([header[0], header[1]]);
        let len = u16::from_le_bytes([header[2], header[3]]) as usize;

        if len == 0 {
            return Ok(None);
        }

        let mut value = vec![0u8; len];
        reader.read_exact(&mut value)?;

        let padding = (TLV_ALIGNMENT - (len % TLV_ALIGNMENT)) % TLV_ALIGNMENT;
        if padding > 0 {
            let mut pad = vec![0u8; padding];
            reader.read_exact(&mut pad)?;
        }

        Ok(Some(TlvEntry::new(Tag(tag), value)))
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.tag.0.to_le_bytes())?;
        writer.write_all(&(self.value.len() as u16).to_le_bytes())?;
        writer.write_all(&self.value)?;

        let padding = (TLV_ALIGNMENT - (self.value.len() % TLV_ALIGNMENT)) % TLV_ALIGNMENT;
        if padding > 0 {
            writer.write_all(&vec![0u8; padding])?;
        }

        Ok(())
    }

    pub fn as_u64(&self) -> Option<u64> {
        if self.value.len() <= 8 {
            let mut buf = [0u8; 8];
            buf[..self.value.len()].copy_from_slice(&self.value);
            Some(u64::from_le_bytes(buf))
        } else {
            None
        }
    }

    pub fn from_u64(tag: Tag, val: u64) -> Self {
        Self::new(tag, val.to_le_bytes().to_vec())
    }

    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }

    pub fn from_str(tag: Tag, s: &str) -> Self {
        Self::new(tag, s.as_bytes().to_vec())
    }
}

#[derive(Clone, Debug, Default)]
pub struct Metadata {
    pub entries: Vec<TlvEntry>,
}

impl Metadata {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn read<R: Read>(reader: &mut R, len: u32) -> std::io::Result<Self> {
        let mut buffer = vec![0u8; len as usize];
        reader.read_exact(&mut buffer)?;
        
        let mut cursor = std::io::Cursor::new(&buffer);
        let mut entries = Vec::new();

        loop {
            match TlvEntry::read(&mut cursor)? {
                Some(entry) => entries.push(entry),
                None => break,
            }
        }

        Ok(Self { entries })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<u32> {
        let mut total = 0u32;
        for entry in &self.entries {
            entry.write(writer)?;
            total += 4 + entry.value.len() as u32;
            total += ((TLV_ALIGNMENT - (entry.value.len() % TLV_ALIGNMENT)) % TLV_ALIGNMENT) as u32;
        }
        Ok(total)
    }

    pub fn get(&self, tag: Tag) -> Option<&TlvEntry> {
        self.entries.iter().find(|e| e.tag == tag)
    }

    pub fn set(&mut self, entry: TlvEntry) {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.tag == entry.tag) {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_roundtrip() {
        let entry = TlvEntry::from_u64(Tag::CHUNK_SIZE, 262144);
        let mut buf = Vec::new();
        entry.write(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let parsed = TlvEntry::read(&mut cursor).unwrap().unwrap();
        assert_eq!(entry.tag, parsed.tag);
        assert_eq!(entry.as_u64(), parsed.as_u64());
    }
}