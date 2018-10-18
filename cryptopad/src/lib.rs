extern crate aes;
extern crate sha2;
#[cfg(test)]
#[macro_use]
extern crate hex_literal;

use sha2::{Digest, Sha256};

pub fn password_to_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.input(password);
    let mut result = [0; 32];
    result.copy_from_slice(&hasher.result()[..]);
    result
}

#[cfg(test)]
mod tests {

    use super::password_to_key;

    #[test]
    fn create_key() {
        let key = password_to_key("test123");
        assert_eq!(
            key[..],
            hex!("ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae")
        );
    }
}
