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
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::str;

type Aes256CBC = Cbc<Aes256, Pkcs7>;
#[derive(Clone, Copy, Debug)]
struct IV([u8; 16]);

impl IV {
    fn generate() -> IV {
        let mut rand = thread_rng();
        IV(rand.gen())
    }
}

#[derive(Clone, Copy, Debug)]
struct Key([u8; 32]);

impl Key {
    fn new_from_password(password: &str) -> Key {
        let mut hasher = Sha256::new();
        hasher.input(password);
        let mut result = [0; 32];
        result.copy_from_slice(&hasher.result()[..]);
        Key(result)
    }
}

#[derive(Debug)]
pub struct EncryptionError;
#[derive(Debug)]
pub struct DecryptionError;

const ENCRYPTED_TAG: u8 = 0xFF;

pub enum SaveOption {
    Plain,
    Encrypted(String),
}

pub enum CryptoFile {
    Plain(String),
    Encrypted(EncryptedFile),
}

pub struct EncryptedFile {
    iv: IV,
    cipher_text: Vec<u8>,
}

impl CryptoFile {
    pub fn new(contents: Vec<u8>) -> Result<CryptoFile, DecryptionError> {
        if contents[0] == ENCRYPTED_TAG {
            let mut iv = IV([0; 16]);
            iv.0.copy_from_slice(&contents[1..17]);
            let cipher_text = contents[17..].iter().cloned().collect();
            Ok(CryptoFile::Encrypted(EncryptedFile { iv, cipher_text }))
        } else {
            Ok(CryptoFile::Plain(String::from_utf8(contents).unwrap()))
        }
    }

    pub fn new_from_file(path: &str) -> Result<CryptoFile, DecryptionError> {
        let mut file = File::open(path).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        if contents[0] == ENCRYPTED_TAG {
            let mut iv = IV([0; 16]);
            iv.0.copy_from_slice(&contents[1..17]);
            let cipher_text = contents[17..].iter().cloned().collect();
            Ok(CryptoFile::Encrypted(EncryptedFile { iv, cipher_text }))
        } else {
            Ok(CryptoFile::Plain(String::from_utf8(contents).unwrap()))
        }
    }
}

impl EncryptedFile {
    pub fn try_decrypt(&self, password: &str) -> Result<String, DecryptionError> {
        let key = Key::new_from_password(password);
        decrypt_text(&self.cipher_text, self.iv, key)
    }
}

pub fn save_text_to_file(
    path: PathBuf,
    text: &str,
    save_options: SaveOption,
) -> Result<(), EncryptionError> {
    let mut file = File::create(path).unwrap();
    match save_options {
        SaveOption::Plain => {
            file.write(text.as_bytes()).unwrap();
        }
        SaveOption::Encrypted(password) => {
            let key = Key::new_from_password(&password);
            let (encrypted_text, iv) = encrypt_text(text, key)?;
            file.write_all(&[ENCRYPTED_TAG]).unwrap();
            file.write_all(&iv.0).unwrap();
            file.write_all(&encrypted_text).unwrap();
        }
    }
    Ok(())
}

fn encrypt_text(text: &str, key: Key) -> Result<(Vec<u8>, IV), EncryptionError> {
    let mut bytes: Vec<u8> = text.as_bytes().to_vec();
    let length = bytes.len();
    bytes.resize(length + 16, 0);
    let iv = IV::generate();
    let cipher = Aes256CBC::new_varkey(&key.0, &GenericArray::clone_from_slice(&iv.0))?;
    let bytes = cipher.encrypt_pad(&mut bytes, length)?;
    Ok((bytes.to_vec(), iv))
}

fn decrypt_text(cipher_text: &[u8], iv: IV, key: Key) -> Result<String, DecryptionError> {
    let cipher = Aes256CBC::new_varkey(&key.0, &GenericArray::clone_from_slice(&iv.0))?;
    let mut cipher_text = Vec::from(cipher_text);
    let bytes = cipher_text.as_mut_slice();
    let bytes = cipher.decrypt_pad(bytes)?;
    Ok(str::from_utf8(bytes).unwrap().to_owned())
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
        let Key(key) = Key::new_from_password("test123");
        assert_eq!(
            key[..],
            hex!("ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae")
        );
    }

    #[test]
    fn encrypt_decrypt() {
        let key = Key::new_from_password("test123");
        let text = "
        This is a se1cret!
        Testing
        123...";
        let (encryption, iv) = encrypt_text(&text, key).unwrap();
        let decryption = decrypt_text(&encryption, iv, key).unwrap();
        assert_eq!(text, decryption);
    }
}
