pub mod root_key;
pub use root_key::RootKey;
pub use root_key::RootKeyMetadata;
pub mod derived_key;
pub use derived_key::DerivedKey;

use chacha20poly1305::{aead::{Aead, OsRng}, AeadCore, ChaCha20Poly1305, KeyInit, Nonce, Key};
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use zeroize::Zeroize;
use crate::helpers::Helpers;

/**
 * Encryption is a struct that contains a dek and a nonce.
 * The dek is a 32 byte key used to encrypt and decrypt data.
 * The nonce is a 12 byte nonce used to encrypt and decrypt data.
 */

#[derive(Debug)]
pub struct Cipher {
    dek: Key,
    nonce: Nonce,
}

impl Serialize for Cipher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        let mut state = serializer.serialize_struct("Cipher", 2)?;
        state.serialize_field("dek", &Helpers::base64_encode(&self.dek.as_slice()))?;
        state.serialize_field("nonce", &Helpers::base64_encode(&self.nonce.as_slice()))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Cipher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            #[derive(serde::Deserialize)]
            struct CipherHelper {
                dek: String,
                nonce: String,
            }

            let helper = CipherHelper::deserialize(deserializer)?;
            let nonce_array = Nonce::from_slice(&Helpers::base64_decode(&helper.nonce).unwrap()).clone();

            if nonce_array.len() != 12 {
                return Err(serde::de::Error::custom("Invalid nonce length"));
            }

            let dek_array = Key::from_slice(&Helpers::base64_decode(&helper.dek).unwrap()).clone();

            Ok(Cipher {
                dek: dek_array,
                nonce: nonce_array,
            })
        }
}

/**
 * The dek should be zeroized on drop (clear from memory)
*/
impl Drop for Cipher {
    fn drop(&mut self) {
        self.dek.as_mut_slice().zeroize();
    }
}

/**
 * If user use the default constructor, the dek and nonce should be generated randomly
 */

impl Default for Cipher {
    fn default() -> Self {
        let mut os_rng = OsRng::default();

        Self {
            dek: ChaCha20Poly1305::generate_key(&mut os_rng),
            nonce: ChaCha20Poly1305::generate_nonce(&mut os_rng)
        }
    }
}

impl Cipher {
    pub fn new(dek: Key, nonce: Nonce) -> Self {
        Self { dek, nonce }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(&Key::from_slice(&self.dek));
        cipher.encrypt(&self.nonce, plaintext).unwrap()
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(&Key::from_slice(&self.dek));
        cipher.decrypt(&self.nonce, ciphertext).unwrap()
    }
}

#[cfg(test)]
mod cipher_tests {
    use super::*;

    #[test]
    fn test_cipher_serialize_deserialize() {
        let cipher = Cipher::default();
        let serialized = serde_json::to_string(&cipher).unwrap();

        println!("Serialized: {}", serialized);
        let deserialized: Cipher = serde_json::from_str(&serialized).unwrap();
        println!("Deserialized: {:?}", deserialized);

        assert_eq!(cipher.dek.as_slice(), deserialized.dek.as_slice());
        assert_eq!(cipher.nonce.as_slice(), deserialized.nonce.as_slice());
        assert_eq!(cipher.nonce.len(), deserialized.nonce.len());
    }

    #[test]
    fn test_cipher_encrypt_decrypt() {
        let dek = ChaCha20Poly1305::generate_key(&mut OsRng::default()).as_slice().to_vec();
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng::default());
        let cipher = Cipher::new(Key::from_slice(&dek).clone(), nonce);
        let plaintext = b"hello world";
        let ciphertext = cipher.encrypt(plaintext);
        let decrypted = cipher.decrypt(&ciphertext);

        assert_eq!(plaintext, decrypted.as_slice());
    }
}