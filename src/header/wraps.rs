use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::ser::SerializeStruct;
use crate::helpers::Helpers;

#[derive(Debug)]
pub struct WrapsWithUserPassphrase {
  pub dek_wrapped: Vec<u8>,
  pub nonce: Vec<u8>,
}

impl WrapsWithUserPassphrase {
  pub fn new(dek_wrapped: Vec<u8>, nonce: Vec<u8>) -> Self {
    Self { dek_wrapped, nonce }
  }
}

impl Serialize for WrapsWithUserPassphrase {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut state = serializer.serialize_struct("WrapsWithUserPassphrase", 2)?;
    state.serialize_field("dek_wrapped", &Helpers::base64_encode(&self.dek_wrapped))?;
    state.serialize_field("nonce", &Helpers::base64_encode(&self.nonce))?;
    state.end()
  }
}

impl<'de> Deserialize<'de> for WrapsWithUserPassphrase {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    #[derive(Deserialize)]
    struct WrapsWithUserPassphraseHelper {
      dek_wrapped: String,
      nonce: String,
    }

    let helper = WrapsWithUserPassphraseHelper::deserialize(deserializer)?;
    Ok(WrapsWithUserPassphrase::new(Helpers::base64_decode(&helper.dek_wrapped).unwrap(), Helpers::base64_decode(&helper.nonce).unwrap()))
  }
}

#[derive(Debug)]
pub struct WrapsWithOsKeychain {
  pub dek_wrapped: Vec<u8>,
  pub nonce: Vec<u8>,
}

impl WrapsWithOsKeychain {
  pub fn new(dek_wrapped: Vec<u8>, nonce: Vec<u8>) -> Self {
    Self { dek_wrapped, nonce }
  }
}

impl Serialize for WrapsWithOsKeychain {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut state = serializer.serialize_struct("WrapsWithOsKeychain", 2)?;
    state.serialize_field("dek_wrapped", &Helpers::base64_encode(&self.dek_wrapped))?;
    state.serialize_field("nonce", &Helpers::base64_encode(&self.nonce))?;
    state.end()
  }
}

impl<'de> Deserialize<'de> for WrapsWithOsKeychain {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    #[derive(Deserialize)]
    struct WrapsWithOsKeychainHelper {
      dek_wrapped: String,
      nonce: String,
    }

    let helper = WrapsWithOsKeychainHelper::deserialize(deserializer)?;
    Ok(WrapsWithOsKeychain::new(Helpers::base64_decode(&helper.dek_wrapped).unwrap(), Helpers::base64_decode(&helper.nonce).unwrap()))
  }
}

#[derive(Debug)]
pub struct Wraps {
  pub from_user_passphrase: WrapsWithUserPassphrase,
  pub from_os_keychain: WrapsWithOsKeychain,
}

impl Wraps {
  pub fn new(from_user_passphrase: WrapsWithUserPassphrase, from_os_keychain: WrapsWithOsKeychain) -> Self {
    Self { from_user_passphrase, from_os_keychain }
  }
}

impl Serialize for Wraps {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut state = serializer.serialize_struct("Wraps", 2)?;
    state.serialize_field("from_user_passphrase", &self.from_user_passphrase)?;
    state.serialize_field("from_os_keychain", &self.from_os_keychain)?;
    state.end()
  }
}

impl<'de> Deserialize<'de> for Wraps {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    #[derive(Deserialize)]
    struct WrapsHelper {
      from_user_passphrase: WrapsWithUserPassphrase,
      from_os_keychain: WrapsWithOsKeychain,
    }

    let helper = WrapsHelper::deserialize(deserializer)?;
    Ok(Wraps::new(helper.from_user_passphrase, helper.from_os_keychain))
  }
}