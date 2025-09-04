use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::ser::SerializeStruct;
pub mod kdf;
pub use kdf::Kdf;
pub mod wraps;
pub use wraps::Wraps;
pub use wraps::WrapsWithUserPassphrase;
pub use wraps::WrapsWithOsKeychain;
pub use crate::cipher::RootKey;
pub use crate::cipher::RootKeyMetadata;
pub use crate::cipher::DerivedKey;
pub use crate::cipher::Cipher;
use chacha20poly1305::{Key, Nonce};
use chrono::Utc;

#[derive(Debug)]
pub struct Header {
  pub version: String,
  pub kdf: Kdf,
  pub wraps: Wraps,
}

impl Header {
  pub fn new(version: String, kdf: Kdf, wraps: Wraps) -> Self {
    Self { version, kdf, wraps }
  }

  pub fn get_root_key(&self, user_passphrase: String) -> RootKey {
    let dk = DerivedKey::new(user_passphrase, self.kdf.salt.clone(), self.kdf.key_length);
    let wrapped_dek = &self.wraps.from_user_passphrase.dek_wrapped;
    let wrapped_nonce = &self.wraps.from_user_passphrase.nonce;
    
    let cipher = Cipher::new(dk.get_value(), Nonce::from_slice(&wrapped_nonce).clone());
    let decrypted_dek = cipher.decrypt(&wrapped_dek);

    RootKey { value: Key::from_slice(&decrypted_dek).to_owned(), metadata: RootKeyMetadata { created_at: Utc::now().timestamp_millis(), key_length: self.kdf.key_length } }
  }
}

impl Serialize for Header {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut state = serializer.serialize_struct("Header", 3)?;
    state.serialize_field("version", &self.version)?;
    state.serialize_field("kdf", &self.kdf)?;
    state.serialize_field("wraps", &self.wraps)?;
    state.end()
  }
}

impl<'de> Deserialize<'de> for Header {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    #[derive(Deserialize)]
    struct HeaderHelper {
      version: String,
      kdf: Kdf,
      wraps: Wraps,
    }

    let helper = HeaderHelper::deserialize(deserializer)?;
    Ok(Header::new(helper.version, helper.kdf, helper.wraps))
  }
}


#[cfg(test)]
mod header_tests {
  use super::*;
  use crate::cipher::{DerivedKey, RootKey};
  use chacha20poly1305::{aead::{Aead, AeadCore, OsRng}, ChaCha20Poly1305, Key, KeyInit};
  use crate::helpers::Helpers;

  #[test]
  fn test_header_serialize_deserialize() {
    let kdf = Kdf::default();
    let root_key = RootKey::default(); // This is a 32 byte key use for encrypting and decrypting user data
    let user_passpharase = "Test@123"; // This is the user passphrase used to derive the key (to generate the key to decrypt root_key)
    let os_keychain_raw_key = ChaCha20Poly1305::generate_key(&mut OsRng::default()); // This is a 32 byte key store in os keychain

    // Use user passphrase -> encryption key -> encrypt root_key -> encode encrypted root_key -> wrapped dek
    let dk: DerivedKey = DerivedKey::new(user_passpharase.to_string(), vec![0; 16], 32);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng::default());
    let encrypted_root_key_from_user_passphrase = ChaCha20Poly1305::new(&Key::from_slice(&dk.get_value().as_slice())).encrypt(&nonce, root_key.value.as_slice()).unwrap();
    let encrypted_root_key_from_user_passphrase_base64 = Helpers::base64_encode(&encrypted_root_key_from_user_passphrase);
    let nonce_base64 = Helpers::base64_encode(&nonce);

    // Use os keychain -> encryption key -> encrypt root_key -> encode encrypted root_key -> wrapped dek
    let encrypted_root_key_from_os_keychain = ChaCha20Poly1305::new(&Key::from_slice(&os_keychain_raw_key)).encrypt(&nonce, root_key.value.as_slice()).unwrap();
    let encrypted_root_key_from_os_keychain_base64 = Helpers::base64_encode(&encrypted_root_key_from_os_keychain);
    let nonce_base64_from_os_keychain = Helpers::base64_encode(&nonce);

    let wraps = Wraps::new(
      WrapsWithUserPassphrase::new(Helpers::base64_decode(&encrypted_root_key_from_user_passphrase_base64).unwrap(), Helpers::base64_decode(&nonce_base64).unwrap()), 
      WrapsWithOsKeychain::new(Helpers::base64_decode(&encrypted_root_key_from_os_keychain_base64).unwrap(), Helpers::base64_decode(&nonce_base64_from_os_keychain).unwrap())
    );

    let header = Header::new("1.0.0".to_string(), kdf, wraps);
    let serialized = serde_json::to_string(&header).unwrap();
    println!("Serialized: {}", serialized);

    let deserialized: Header = serde_json::from_str(&serialized).unwrap();
    println!("Deserialized: {:?}", deserialized);

    assert_eq!(header.version, deserialized.version);
    assert_eq!(header.kdf.algorithm, deserialized.kdf.algorithm);
    assert_eq!(header.kdf.salt, deserialized.kdf.salt);
    assert_eq!(header.kdf.key_length, deserialized.kdf.key_length);
    assert_eq!(header.wraps.from_user_passphrase.dek_wrapped, deserialized.wraps.from_user_passphrase.dek_wrapped);
    assert_eq!(header.wraps.from_user_passphrase.nonce, deserialized.wraps.from_user_passphrase.nonce);
    assert_eq!(header.wraps.from_os_keychain.dek_wrapped, deserialized.wraps.from_os_keychain.dek_wrapped);
    assert_eq!(header.wraps.from_os_keychain.nonce, deserialized.wraps.from_os_keychain.nonce);
  }


  #[test]
  fn test_get_root_key_from_header() {
    let json_string = r#"{"version":"1.0.0","kdf":{"algorithm":"argon2","salt":"cMCMq9U80mqBc2fu","key_length":32},"wraps":{"from_user_passphrase":{"dek_wrapped":"5tT3qfiGGIpuRM0Qu8K8ux+flfdJnThMglCn1aYU77iq6mxTiPVSWrBXHTkK+6R0","nonce":"770Ww/yxnCgiHSdZ"},"from_os_keychain":{"dek_wrapped":"9ilYJsWddv6Nm9DWO4YJ99LTjiihNHLl+WRP4PjKp1DKaERqpnGuHFysAmUaFoJO","nonce":"770Ww/yxnCgiHSdZ"}}}"#;
    let header: Header = serde_json::from_str(json_string).unwrap();

    println!("Header: {:?}", header);

    // let root_key = header.get_root_key("Test@123".to_string());
    // println!("Root key: {:?}", root_key);

    // assert_eq!(root_key.value.as_slice().len(), 32);
    // assert_eq!(root_key.metadata.key_length, 32);
  }
}