extern crate aes;
extern crate block_modes;
extern crate sha2;
#[cfg(test)]
#[macro_use]
extern crate hex_literal;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, BlockModeIv, Cbc};
use sha2::{Digest, Sha256};
use std::str;

type Aes256CBC = Cbc<Aes256, Pkcs7>;

pub fn password_to_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.input(password);
    let mut result = [0; 32];
    result.copy_from_slice(&hasher.result()[..]);
    result
}

pub fn encrypt_text(text: &str, key: [u8; 32]) -> Vec<u8> {
    let mut bytes: Vec<u8> = text.as_bytes().to_vec();
    let length = bytes.len();
    bytes.resize(16 * (2 + (length / 16)), 0);
    let iv = GenericArray::clone_from_slice(&[2; 16]);
    let cipher = Aes256CBC::new_varkey(&key, &iv).expect("Failed to create cipher");
    let bytes = cipher
        .encrypt_pad(&mut bytes, length)
        .expect("Failed to encrypt");
    bytes.to_vec()
}

pub fn decrypt_text(cipher_text: &[u8], key: [u8; 32]) -> String {
    let iv = GenericArray::clone_from_slice(&[2; 16]);
    let cipher = Aes256CBC::new_varkey(&key, &iv).expect("Failed to create cipher");
    let mut cipher_text = Vec::from(cipher_text);
    let bytes = cipher_text.as_mut_slice();
    let bytes = cipher.decrypt_pad(bytes).expect("Failed to decrypt");
    str::from_utf8(bytes).unwrap().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_key() {
        let key = password_to_key("test123");
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
        let encryption = encrypt_text(&text, key);
        let decryption = decrypt_text(&encryption, key);
        assert_eq!(text, decryption);
    }
}
