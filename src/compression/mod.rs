#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionAlgo {
    None = 0,
    Zstd = 1,
    Lz4 = 2,
}

impl From<u8> for CompressionAlgo {
    fn from(v: u8) -> Self {
        match v {
            0 => CompressionAlgo::None,
            1 => CompressionAlgo::Zstd,
            2 => CompressionAlgo::Lz4,
            _ => CompressionAlgo::Zstd,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CompressionError {
    #[error("Compression failed: {0}")]
    Compression(String),
    #[error("Decompression failed: {0}")]
    Decompression(String),
}

pub struct Compressor {
    algo: CompressionAlgo,
    level: i32,
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new(CompressionAlgo::Zstd, 3)
    }
}

impl Compressor {
    pub fn new(algo: CompressionAlgo, level: i32) -> Self {
        Self { algo, level }
    }

    pub fn algo(&self) -> CompressionAlgo {
        self.algo
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        match self.algo {
            CompressionAlgo::None => Ok(data.to_vec()),
            CompressionAlgo::Zstd => {
                zstd::stream::encode_all(data, self.level)
                    .map_err(|e| CompressionError::Compression(e.to_string()))
            }
            CompressionAlgo::Lz4 => {
                let compressed = lz4_flex::compress_prepend_size(data);
                Ok(compressed)
            }
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        match self.algo {
            CompressionAlgo::None => Ok(data.to_vec()),
            CompressionAlgo::Zstd => {
                zstd::stream::decode_all(data)
                    .map_err(|e| CompressionError::Decompression(e.to_string()))
            }
            CompressionAlgo::Lz4 => {
                lz4_flex::decompress_size_prepended(data)
                    .map_err(|e| CompressionError::Decompression(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zstd_roundtrip() {
        let compressor = Compressor::new(CompressionAlgo::Zstd, 3);
        let data = b"Hello, this is a test string for compression! This needs to be longer to show compression benefits. Lorem ipsum dolor sit amet.";
        
        let compressed = compressor.compress(data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        
        assert_eq!(data.as_slice(), decompressed.as_slice());
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn lz4_roundtrip() {
        let compressor = Compressor::new(CompressionAlgo::Lz4, 0);
        let data = b"Hello, this is a test string for compression!";
        
        let compressed = compressor.compress(data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn none_passes_through() {
        let compressor = Compressor::new(CompressionAlgo::None, 0);
        let data = b"Unchanged data";
        
        let compressed = compressor.compress(data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        
        assert_eq!(data.as_slice(), compressed.as_slice());
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }
}
