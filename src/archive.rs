use crate::compression::{CompressionAlgo, Compressor};
use crate::crypto::{Encryptor, derive_key, generate_nonce, generate_salt};
use crate::format::{Tag, ChunkIndexEntry, ChunkIndex, Flags, Header, Metadata, TlvEntry, DEFAULT_CHUNK_SIZE, FOOTER_SIZE, HEADER_SIZE, SALT_SIZE};

use blake3::Hasher;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write, Seek};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("Compression error: {0}")]
    Compression(#[from] crate::compression::CompressionError),
    #[error("Invalid archive: {0}")]
    InvalidArchive(String),
    #[error("Integrity check failed")]
    IntegrityFailed,
}

pub struct Packer {
    compression_algo: CompressionAlgo,
    compression_level: i32,
    chunk_size: usize,
    password: String,
}

impl Packer {
    pub fn new(password: String) -> Self {
        Self {
            compression_algo: CompressionAlgo::Zstd,
            compression_level: 3,
            chunk_size: DEFAULT_CHUNK_SIZE,
            password,
        }
    }

    pub fn compression_algo(mut self, algo: CompressionAlgo) -> Self {
        self.compression_algo = algo;
        self
    }

    pub fn compression_level(mut self, level: i32) -> Self {
        self.compression_level = level;
        self
    }

    pub fn chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    pub fn pack<P: AsRef<Path>, Q: AsRef<Path>>(&self, input: P, output: Q) -> Result<(), ArchiveError> {
        let input_path = input.as_ref();
        let output_path = output.as_ref();

        let input_file = File::open(input_path)?;
        let file_size = input_file.metadata()?.len();
        let mut reader = BufReader::new(input_file);

        let output_file = File::create(output_path)?;
        let mut writer = BufWriter::new(output_file);

        let salt = generate_salt();
        let key = derive_key(&self.password, &salt)?;
        let encryptor = Encryptor::new(&key);
        let compressor = Compressor::new(self.compression_algo, self.compression_level);

        let flags = Flags::ENCRYPTED | Flags::COMPRESSED;

        let filename = input_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file");

        let mut metadata = Metadata::new();
        metadata.set(TlvEntry::from_u64(Tag::COMPRESSION_ALGO, self.compression_algo as u64));
        metadata.set(TlvEntry::from_u64(Tag::ENCRYPTION_ALGO, 1));
        metadata.set(TlvEntry::from_u64(Tag::CHUNK_SIZE, self.chunk_size as u64));
        metadata.set(TlvEntry::from_u64(Tag::ORIGINAL_SIZE, file_size));
        metadata.set(TlvEntry::from_str(Tag::ORIGINAL_FILENAME, filename));
        metadata.set(TlvEntry::new(Tag::SALT, salt.to_vec()));

        let mut metadata_buf = Vec::new();
        let metadata_len = metadata.write(&mut metadata_buf)?;

        writer.write_all(&[0u8; HEADER_SIZE])?;
        writer.write_all(&metadata_buf)?;

        let mut chunk_index = ChunkIndex::new();
        let mut global_hasher = Hasher::new();

        let mut chunk_data_offset = HEADER_SIZE as u64 + metadata_len as u64;
        let mut buffer = vec![0u8; self.chunk_size];

        let mut total_read = 0u64;
        while total_read < file_size {
            let to_read = ((file_size - total_read) as usize).min(self.chunk_size);
            let slice = &mut buffer[..to_read];
            reader.read_exact(slice)?;
            
            global_hasher.update(&buffer[..to_read]);
            
            let original_chunk = &buffer[..to_read];
            let compressed_chunk = compressor.compress(original_chunk)?;

            let nonce = generate_nonce();
            let (encrypted_chunk, tag) = encryptor.encrypt(&compressed_chunk, &nonce)?;

            let entry = ChunkIndexEntry::new(
                chunk_data_offset,
                encrypted_chunk.len() as u32,
                to_read as u32,
                nonce,
                tag,
            );

            chunk_index.push(entry);
            writer.write_all(&encrypted_chunk)?;
            chunk_data_offset += encrypted_chunk.len() as u64;
            total_read += to_read as u64;
        }

        let chunk_index_len = chunk_index.total_len();
        chunk_index.write(&mut writer)?;

        let global_hash = global_hasher.finalize();
        let mut footer = [0u8; FOOTER_SIZE];
        footer[..32].copy_from_slice(global_hash.as_bytes());
        writer.write_all(&footer)?;

        let header = Header::new(
            flags,
            metadata_len,
            chunk_index_len,
            chunk_index.entries.len() as u32,
        );

        writer.seek(std::io::SeekFrom::Start(0))?;
        header.write(&mut writer)?;
        writer.flush()?;

        Ok(())
    }
}

pub struct Unpacker {
    password: String,
}

impl Unpacker {
    pub fn new(password: String) -> Self {
        Self { password }
    }

    pub fn unpack<P: AsRef<Path>>(&self, input: P) -> Result<(), ArchiveError> {
        let input_path = input.as_ref();

        let mut file = File::open(input_path)?;
        let file_size = file.metadata()?.len();

        let header = Header::read(&mut file)?;
        if header.version != 1 {
            return Err(ArchiveError::InvalidArchive("Unsupported version".into()));
        }

        let _flags = header.flags();

        let mut metadata_bytes = vec![0u8; header.metadata_len as usize];
        file.read_exact(&mut metadata_bytes)?;

        let metadata = Metadata::read(&mut metadata_bytes.as_slice(), header.metadata_len)?;

        let filename = metadata.get(Tag::ORIGINAL_FILENAME)
            .and_then(|e| e.as_str())
            .unwrap_or("output");

        let compression_algo: CompressionAlgo = metadata.get(Tag::COMPRESSION_ALGO)
            .and_then(|e| e.as_u64())
            .map(|v| v as u8)
            .map(CompressionAlgo::from)
            .unwrap_or(CompressionAlgo::Zstd);

        let decompressor = Compressor::new(compression_algo, 0);

        let salt_entry = metadata.get(Tag::SALT)
            .ok_or_else(|| ArchiveError::InvalidArchive("Missing salt".into()))?;
        
        let salt: [u8; SALT_SIZE] = salt_entry.value.as_slice()
            .try_into()
            .map_err(|_| ArchiveError::InvalidArchive("Invalid salt".into()))?;
        
        let key = derive_key(&self.password, &salt)?;
        let decryptor = Encryptor::new(&key);

        let chunk_index_offset = file_size - FOOTER_SIZE as u64 - header.chunk_index_len as u64;
        file.seek(std::io::SeekFrom::Start(chunk_index_offset))?;

        let chunk_index = ChunkIndex::read(&mut file, header.chunk_count)?;

        let output_file = File::create(filename)?;
        let mut writer = BufWriter::new(output_file);

        let mut global_hasher = Hasher::new();

        for entry in &chunk_index.entries {
            file.seek(std::io::SeekFrom::Start(entry.offset))?;

            let mut encrypted_chunk = vec![0u8; entry.compressed_size as usize];
            file.read_exact(&mut encrypted_chunk)?;

            let compressed_chunk = decryptor.decrypt(&encrypted_chunk, &entry.nonce, &entry.tag)?;
            let original_chunk = decompressor.decompress(&compressed_chunk)?;

            global_hasher.update(&original_chunk);
            writer.write_all(&original_chunk)?;
        }

        writer.flush()?;

        file.seek(std::io::SeekFrom::Start(file_size - FOOTER_SIZE as u64))?;
        let mut expected_hash = [0u8; 32];
        file.read_exact(&mut expected_hash)?;

        let computed_hash = global_hasher.finalize();

        if computed_hash.as_bytes() != &expected_hash {
            return Err(ArchiveError::IntegrityFailed);
        }

        Ok(())
    }

    pub fn info<P: AsRef<Path>>(&self, input: P) -> Result<FileInfo, ArchiveError> {
        let input_path = input.as_ref();
        let mut file = File::open(input_path)?;

        let header = Header::read(&mut file)?;
        if header.version != 1 {
            return Err(ArchiveError::InvalidArchive("Unsupported version".into()));
        }

        let mut metadata_bytes = vec![0u8; header.metadata_len as usize];
        file.read_exact(&mut metadata_bytes)?;

        let metadata = Metadata::read(&mut metadata_bytes.as_slice(), header.metadata_len)?;

        let original_size = metadata.get(Tag::ORIGINAL_SIZE)
            .and_then(|e| e.as_u64())
            .unwrap_or(0);

        let filename = metadata.get(Tag::ORIGINAL_FILENAME)
            .and_then(|e| e.as_str())
            .unwrap_or("unknown")
            .to_string();

        let compression_algo: CompressionAlgo = metadata.get(Tag::COMPRESSION_ALGO)
            .and_then(|e| e.as_u64())
            .map(|v| v as u8)
            .map(CompressionAlgo::from)
            .unwrap_or(CompressionAlgo::Zstd);

        Ok(FileInfo {
            filename,
            original_size,
            compressed_size: file.metadata()?.len(),
            chunk_count: header.chunk_count,
            compression_algo,
            encrypted: header.flags().contains(Flags::ENCRYPTED),
        })
    }
}

pub struct FileInfo {
    pub filename: String,
    pub original_size: u64,
    pub compressed_size: u64,
    pub chunk_count: u32,
    pub compression_algo: CompressionAlgo,
    pub encrypted: bool,
}
