use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, Key, XNonce, aead::Aead};
use rand::{RngCore, rngs::OsRng};

use crate::format::{SALT_SIZE, NONCE_SIZE, TAG_SIZE};

const ARGON2_MEMORY_COST: u32 = 64 * 1024;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Key derivation failed")]
    KeyDerivation,
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Invalid key size")]
    InvalidKeySize,
}

pub struct Encryptor {
    cipher: XChaCha20Poly1305,
}

pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn derive_key(password: &str, salt: &[u8; SALT_SIZE]) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(
        ARGON2_MEMORY_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(32),
    ).map_err(|_| CryptoError::KeyDerivation)?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| CryptoError::KeyDerivation)?;
    
    Ok(key)
}

impl Encryptor {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        Self { cipher }
    }

    pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; NONCE_SIZE]) -> Result<(Vec<u8>, [u8; TAG_SIZE]), CryptoError> {
        let nonce = XNonce::from_slice(nonce);
        
        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        let tag_len = TAG_SIZE;
        let tag_offset = ciphertext.len() - tag_len;
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&ciphertext[tag_offset..]);
        
        let data = ciphertext[..tag_offset].to_vec();
        
        Ok((data, tag))
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; NONCE_SIZE], tag: &[u8; TAG_SIZE]) -> Result<Vec<u8>, CryptoError> {
        let nonce = XNonce::from_slice(nonce);
        
        let mut full_ciphertext = ciphertext.to_vec();
        full_ciphertext.extend_from_slice(tag);
        
        let plaintext = self.cipher
            .decrypt(nonce, full_ciphertext.as_slice())
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;
        
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let password = "test_password_123";
        let salt = generate_salt();
        let key = derive_key(password, &salt).unwrap();
        
        let encryptor = Encryptor::new(&key);
        let nonce = generate_nonce();
        
        let plaintext = b"Hello, World!";
        let (ciphertext, tag) = encryptor.encrypt(plaintext, &nonce).unwrap();
        let decrypted = encryptor.decrypt(&ciphertext, &nonce, &tag).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn wrong_password_fails() {
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let salt = generate_salt();
        
        let key = derive_key(password, &salt).unwrap();
        let encryptor = Encryptor::new(&key);
        let nonce = generate_nonce();
        
        let plaintext = b"Secret data";
        let (ciphertext, tag) = encryptor.encrypt(plaintext, &nonce).unwrap();
        
        let wrong_key = derive_key(wrong_password, &salt).unwrap();
        let wrong_encryptor = Encryptor::new(&wrong_key);
        
        let result = wrong_encryptor.decrypt(&ciphertext, &nonce, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn different_nonces_different_ciphertext() {
        let password = "test";
        let salt = generate_salt();
        let key = derive_key(password, &salt).unwrap();
        let encryptor = Encryptor::new(&key);
        
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        
        let plaintext = b"Same data";
        let (ct1, _) = encryptor.encrypt(plaintext, &nonce1).unwrap();
        let (ct2, _) = encryptor.encrypt(plaintext, &nonce2).unwrap();
        
        assert_ne!(ct1, ct2);
    }
}
