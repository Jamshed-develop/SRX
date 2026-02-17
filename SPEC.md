# SRX Archive Format Specification v1.0

## Overview

SRX is a modern compressed and encrypted archive format designed for:
- Security-first approach with proven cryptographic primitives
- High performance through chunk-based parallel processing
- Streaming and random access capabilities
- Extensibility without breaking backward compatibility

## File Structure

```
┌─────────────────────────┐
│      Fixed Header       │  32 bytes
├─────────────────────────┤
│   TLV Metadata Section  │  Variable
├─────────────────────────┤
│    Chunk Index Table    │  Variable
├─────────────────────────┤
│   Encrypted Data Chunks │  Variable
├─────────────────────────┤
│    Integrity Footer     │  32 bytes
└─────────────────────────┘
```

## Header (32 bytes)

| Offset | Size | Field          | Description                     |
|--------|------|----------------|---------------------------------|
| 0      | 4    | magic          | ASCII "SRX1" (0x53 0x52 0x58 0x31) |
| 4      | 1    | version        | Format version (currently 1)    |
| 5      | 2    | flags          | Feature flags (little-endian)   |
| 7      | 4    | header_len     | Header length (always 32)       |
| 11     | 4    | metadata_len   | Length of metadata section      |
| 15     | 4    | chunk_index_len| Length of chunk index table     |
| 19     | 4    | chunk_count    | Number of data chunks           |
| 23     | 9    | reserved       | Reserved for future use         |

### Flags

| Bit | Name       | Description                    |
|-----|------------|--------------------------------|
| 0   | ENCRYPTED  | Archive is encrypted           |
| 1   | COMPRESSED | Archive is compressed          |
| 2   | STREAMING  | Streaming mode (future)        |
| 3-15| Reserved   | Must be zero                   |

## Metadata Section

Metadata uses TLV (Type-Length-Value) encoding:
- Type: 2 bytes (little-endian)
- Length: 2 bytes (little-endian) 
- Value: `Length` bytes
- Padding: Up to 4-byte alignment

### Defined Types

| Type   | ID    | Description                    |
|--------|-------|--------------------------------|
| COMPRESSION_ALGO | 0x0001 | Compression algorithm (u8) |
| ENCRYPTION_ALGO  | 0x0002 | Encryption algorithm (u8)  |
| CHUNK_SIZE       | 0x0003 | Chunk size in bytes (u64)  |
| ORIGINAL_SIZE    | 0x0004 | Original file size (u64)   |
| ORIGINAL_FILENAME| 0x0005 | Original filename (string) |
| SALT             | 0x0010 | Argon2 salt (16 bytes)     |
| ARGON2_MEMORY    | 0x0011 | Argon2 memory cost (u64)   |
| ARGON2_TIME      | 0x0012 | Argon2 time cost (u64)     |
| ARGON2_PARALLELISM| 0x0013| Argon2 parallelism (u64)  |

Unknown types MUST be preserved and skipped safely.

### Compression Algorithms

| Value | Algorithm  |
|-------|------------|
| 0     | None       |
| 1     | Zstandard  |
| 2     | LZ4        |

### Encryption Algorithms

| Value | Algorithm          |
|-------|-------------------|
| 0     | None              |
| 1     | XChaCha20-Poly1305|

## Chunk Index Table

Each entry describes a data chunk:

| Offset | Size | Field          | Description              |
|--------|------|----------------|--------------------------|
| 0      | 8    | offset         | File offset of chunk data|
| 8      | 4    | compressed_size| Size after compression+encryption|
| 12     | 4    | original_size  | Original chunk size      |
| 16     | 24   | nonce          | XChaCha20 nonce          |
| 40     | 16   | tag            | Poly1305 authentication tag|

Entry size: 56 bytes

## Data Chunks

Each chunk is processed independently:

1. **Compression**: Original data → Compressed data
2. **Encryption**: Compressed data → Encrypted data + auth tag

Default chunk size: 256 KiB (262,144 bytes)

### Encryption Details

- Algorithm: XChaCha20-Poly1305
- Key derivation: Argon2id
  - Memory: 64 MiB
  - Time: 3 iterations
  - Parallelism: 4 threads
  - Output: 32 bytes
- Nonce: 24 bytes, random per chunk
- Tag: 16 bytes Poly1305

### Compression Details

- Default: Zstandard level 3
- Alternative: LZ4 for speed-critical applications

## Integrity Footer (32 bytes)

| Offset | Size | Field  | Description          |
|--------|------|--------|---------------------|
| 0      | 32   | hash   | BLAKE3 hash of original data|

The hash covers the original (decompressed, decrypted) data in chunk order.

## Security Considerations

1. **Authenticated Encryption**: Every chunk is individually authenticated with Poly1305
2. **Key Derivation**: Argon2id provides resistance against brute-force attacks
3. **Unique Nonces**: Each chunk uses a unique random nonce
4. **Integrity Verification**: BLAKE3 hash in footer verifies overall data integrity
5. **No Custom Crypto**: Only uses well-audited cryptographic primitives

## Processing Workflow

### Packing

```
1. Generate salt
2. Derive key from password using Argon2id
3. For each chunk:
   a. Read chunk data
   b. Update BLAKE3 hasher
   c. Compress
   d. Generate nonce
   e. Encrypt with XChaCha20-Poly1305
   f. Record chunk metadata
4. Write chunk index
5. Write BLAKE3 hash footer
6. Write header at file start
```

### Unpacking

```
1. Read and validate header
2. Read metadata
3. Derive key from password
4. Read chunk index
5. For each chunk:
   a. Read encrypted chunk
   b. Decrypt and verify tag
   c. Decompress
   d. Update BLAKE3 hasher
   e. Write to output
6. Verify BLAKE3 hash against footer
```

## Extensibility

The format supports future extensions through:
- Reserved fields in header
- Unknown TLV types (preserved, skipped)
- New compression/encryption algorithm IDs
- Additional flag bits

Implementations MUST:
- Preserve unknown TLV entries
- Reject unknown critical algorithms
- Ignore undefined flag bits

## Version History

- v1.0: Initial specification
  - Single file archives
  - Zstandard/LZ4 compression
  - XChaCha20-Poly1305 encryption
  - 256 KiB default chunk size