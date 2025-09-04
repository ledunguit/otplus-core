pub mod encryption;
pub use encryption::Encryption;
pub use encryption::RootKey;
pub use encryption::RootKeyMetadata;
pub use encryption::DerivedKey;
pub mod header;

#[cfg(test)]
mod lib_tests {
  use super::*;
  use base64::{engine::general_purpose::STANDARD, Engine};
  use chacha20poly1305::{aead::{OsRng, AeadCore}, ChaCha20Poly1305};

  #[test]
  fn test_encryption() {
    let encryption = Encryption::default();
    let plaintext = b"hello world";
    let ciphertext = encryption.encrypt(plaintext);
    let decrypted = encryption.decrypt(&ciphertext);
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

    let encryption = Encryption::new(derived_key.get_value(), nonce);

    let encrypted_root_key = encryption.encrypt(root_key.value.as_slice());

    let base64_root_key = STANDARD.encode(&encrypted_root_key);
    println!("Root key encrypted: {:?}", base64_root_key);

    let decrypted_root_key = encryption.decrypt(&encrypted_root_key);
    println!("Root key decrypted: {:?}", decrypted_root_key);
    assert_eq!(root_key.value.as_slice(), decrypted_root_key.as_slice());
  }
}