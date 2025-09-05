pub mod cipher;
pub mod header;
pub mod helpers;
pub mod keychain;

pub use cipher::Cipher;
pub use cipher::RootKey;
pub use cipher::RootKeyMetadata;
pub use cipher::DerivedKey;
pub use helpers::Helpers;
pub use keychain::KeyChain;

#[cfg(test)]
mod lib_tests {
  use super::*;
  use chacha20poly1305::{aead::{OsRng, AeadCore}, ChaCha20Poly1305};

  #[test]
  fn test_cipher() {
    let cipher = Cipher::default();
    let plaintext = b"hello world";
    let ciphertext = cipher.encrypt(plaintext);
    let decrypted = cipher.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted.as_slice());
  }

  #[test]
  fn test_full_flow() {
    // Passphrase from user
    let passphrase = "password";

    // Root key is a 32 byte key used to encrypt and decrypt user data (randomly generated)
    let root_key = RootKey::default();

    // Key use to encrypt root key (derived from passphrase)
    let derived_key = DerivedKey::new(passphrase.to_string(), vec![0; 16], 32);

    // Encrypt root key with derived key
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng::default());

    let cipher = Cipher::new(derived_key.get_value(), nonce);

    let encrypted_root_key = cipher.encrypt(root_key.value.as_slice());

    let base64_root_key = Helpers::base64_encode(&encrypted_root_key);
    println!("Root key encrypted: {:?}", base64_root_key);

    let decrypted_root_key = cipher.decrypt(&encrypted_root_key);
    println!("Root key decrypted: {:?}", decrypted_root_key);
    assert_eq!(root_key.value.as_slice(), decrypted_root_key.as_slice());
  }
}