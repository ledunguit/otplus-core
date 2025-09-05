use serde::{Serialize, Deserialize, Serializer, Deserializer};
use chacha20poly1305::{aead::{AeadCore, OsRng}, ChaCha20Poly1305};
use serde::ser::SerializeStruct;
use crate::helpers::Helpers;

#[derive(Debug)]
pub struct Kdf {
  pub algorithm: String,
  pub salt: Vec<u8>,
  pub key_length: u32,
}

impl Default for Kdf {
  fn default() -> Self {
    let mut os_rng = OsRng::default();
    let salt = ChaCha20Poly1305::generate_nonce(&mut os_rng);
    
    Self { algorithm: "argon2".to_string(), salt: salt.as_slice().to_vec(), key_length: 32 }
  }
}

impl Serialize for Kdf {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut state = serializer.serialize_struct("Kdf", 3)?;
    state.serialize_field("algorithm", &self.algorithm)?;

    let salt_base64 = Helpers::base64_encode(&self.salt);
    state.serialize_field("salt", &salt_base64)?;
    state.serialize_field("key_length", &self.key_length)?;
    state.end()
  }
}

impl<'de> Deserialize<'de> for Kdf {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    #[derive(Deserialize)]
    struct KdfHelper {
      algorithm: String,
      salt: String,
      key_length: u32,
    }

    let kdf_helper = KdfHelper::deserialize(deserializer)?;

    let salt = Helpers::base64_decode(&kdf_helper.salt).unwrap_or_default();

    Ok(Self { algorithm: kdf_helper.algorithm, salt: salt, key_length: kdf_helper.key_length })
  }
}