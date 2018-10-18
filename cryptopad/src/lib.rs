extern crate aes;
extern crate block_modes;
extern crate rand;
extern crate sha2;
#[cfg(test)]
#[macro_use]
extern crate hex_literal;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::InvalidKeyLength;
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, BlockModeError, BlockModeIv, Cbc};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use std::str;

type Aes256CBC = Cbc<Aes256, Pkcs7>;
#[derive(Clone, Copy, Debug)]
pub struct IV([u8; 16]);
#[derive(Clone, Copy, Debug)]
pub struct Key([u8; 32]);

#[derive(Debug)]
pub struct EncryptionError;
#[derive(Debug)]
pub struct DecryptionError;

pub fn password_to_key(password: &str) -> Key {
    let mut hasher = Sha256::new();
    hasher.input(password);
    let mut result = [0; 32];
    result.copy_from_slice(&hasher.result()[..]);
    Key(result)
}

pub fn encrypt_text(text: &str, key: Key) -> Result<(Vec<u8>, IV), EncryptionError> {
    let mut bytes: Vec<u8> = text.as_bytes().to_vec();
    let length = bytes.len();
    bytes.resize(length + 16, 0);
    let iv = generate_iv();
    let cipher = Aes256CBC::new_varkey(&key.0, &GenericArray::clone_from_slice(&iv.0))?;
    let bytes = cipher
        .encrypt_pad(&mut bytes, length)?;
    Ok((bytes.to_vec(), iv))
}

pub fn decrypt_text(cipher_text: &[u8], iv: IV, key: Key) -> Result<String, DecryptionError> {
    let cipher = Aes256CBC::new_varkey(&key.0, &GenericArray::clone_from_slice(&iv.0))?;
    let mut cipher_text = Vec::from(cipher_text);
    let bytes = cipher_text.as_mut_slice();
    let bytes = cipher.decrypt_pad(bytes)?;
    Ok(str::from_utf8(bytes).unwrap().to_owned())
}

fn generate_iv() -> IV {
    let mut rand = thread_rng();
    IV(rand.gen())
}

impl From<InvalidKeyLength> for EncryptionError {
    fn from(_: InvalidKeyLength) -> EncryptionError {
        EncryptionError
    }
}

impl From<BlockModeError> for EncryptionError {
    fn from(_: BlockModeError) -> EncryptionError {
        EncryptionError
    }
}

impl From<InvalidKeyLength> for DecryptionError {
    fn from(_: InvalidKeyLength) -> DecryptionError {
        DecryptionError
    }
}

impl From<BlockModeError> for DecryptionError {
    fn from(_: BlockModeError) -> DecryptionError {
        DecryptionError
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_key() {
        let Key(key) = password_to_key("test123");
        assert_eq!(
            key[..],
            hex!("ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae")
        );
    }

    #[test]
    fn encrypt_decrypt() {
        let key = password_to_key("test123");
        let text = "
        This is a se1cret!
        Testing
        123...";
        let (encryption, iv) = encrypt_text(&text, key).unwrap();
        let decryption = decrypt_text(&encryption, iv, key).unwrap();
        assert_eq!(text, decryption);
    }
}
