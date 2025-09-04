use argon2::Argon2;
use chacha20poly1305::Key;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::ser::SerializeStruct;
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Debug)]
pub struct DerivedKey {
  value: Key,
  salt: Vec<u8>,
}

impl Serialize for DerivedKey {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut state = serializer.serialize_struct("DerivedKey", 2)?;
    state.serialize_field("value", &STANDARD.encode(&self.value.as_slice()))?;
    state.serialize_field("salt", &STANDARD.encode(&self.salt))?;
    state.end()
  }
}

impl<'de> Deserialize<'de> for DerivedKey {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    use serde::de::{self, MapAccess, Visitor};
    use std::fmt;

    struct DerivedKeyVisitor;

    impl<'de> Visitor<'de> for DerivedKeyVisitor {
      type Value = DerivedKey;

      fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("struct DerivedKey")
      }

      fn visit_map<V>(self, mut map: V) -> Result<DerivedKey, V::Error>
      where
        V: MapAccess<'de>,
      {
        let mut value = None;
        let mut salt = None;
        while let Some(key) = map.next_key::<&str>()? {
          match key {
            "value" => {
              if value.is_some() {
                return Err(de::Error::duplicate_field("value"));
              }
              let value_str: String = map.next_value()?;
              let value_bytes = base64::engine::general_purpose::STANDARD
                .decode(&value_str)
                .map_err(de::Error::custom)?;
              value = Some(Key::from_slice(&value_bytes).clone());
            }
            "salt" => {
              if salt.is_some() {
                return Err(de::Error::duplicate_field("salt"));
              }
              let salt_str: String = map.next_value()?;
              let salt_bytes = base64::engine::general_purpose::STANDARD
                .decode(&salt_str)
                .map_err(de::Error::custom)?;
              salt = Some(salt_bytes);
            }
            _ => {
              let _: de::IgnoredAny = map.next_value()?;
            }
          }
        }
        let value = value.ok_or_else(|| de::Error::missing_field("value"))?;
        let salt = salt.ok_or_else(|| de::Error::missing_field("salt"))?;
        Ok(DerivedKey { value, salt })
      }
    }

    deserializer.deserialize_struct("DerivedKey", &["value", "salt"], DerivedKeyVisitor)
  }
}

impl DerivedKey {
  pub fn new(passphrase: String, salt: Vec<u8>, key_length: u32) -> Self {
    let mut output = vec![0; key_length as usize];
    Argon2::default().hash_password_into(passphrase.as_bytes(), &salt, &mut output).unwrap();

    Self { value: Key::from_slice(&output).clone(), salt }
  }

  pub fn get_value(&self) -> Key {
    self.value.clone()
  }

  pub fn get_salt(&self) -> Vec<u8> {
    self.salt.clone()
  }
}

#[cfg(test)]
mod derived_key_tests {
  use super::*;

  #[test]
  fn test_passphrase_to_derived_key() {
    let salt = Vec::from([147, 253, 247, 2, 13, 123, 249, 26, 108, 229, 69, 61]); // For testing purposes
    let derived_key = DerivedKey::new("password".to_string(), salt.clone(), 32);

    assert_eq!(derived_key.value.as_slice().len(), 32);
    assert_eq!(derived_key.salt, salt);
  }

  #[test]
  fn test_the_same_passphrase_should_produce_the_same_derived_key() {
    let salt = Vec::from([147, 253, 247, 2, 13, 123, 249, 26, 108, 229, 69, 61]); // For testing purposes
    let derived_key1 = DerivedKey::new("password".to_string(), salt.clone(), 32);
    let derived_key2 = DerivedKey::new("password".to_string(), salt.clone(), 32);
    assert_eq!(derived_key1.value, derived_key2.value);
  }

  #[test]
  fn test_the_different_passphrase_should_produce_the_different_derived_key() {
    let salt = Vec::from([147, 253, 247, 2, 13, 123, 249, 26, 108, 229, 69, 61]); // For testing purposes
    let derived_key1 = DerivedKey::new("password".to_string(), salt.clone(), 32);
    let derived_key2 = DerivedKey::new("password2".to_string(), salt.clone(), 32);
    assert_ne!(derived_key1.value, derived_key2.value);
  }

  #[test]
  fn test_derived_key_serialize_deserialize() {
    let salt = Vec::from([147, 253, 247, 2, 13, 123, 249, 26, 108, 229, 69, 61]); // For testing purposes
    let derived_key = DerivedKey::new("password".to_string(), salt.clone(), 32);
    let serialized = serde_json::to_string(&derived_key).unwrap();
    println!("Serialized: {}", serialized);
    let deserialized: DerivedKey = serde_json::from_str(&serialized).unwrap();
    println!("Deserialized: {:?}", deserialized);

    assert_eq!(derived_key.value.as_slice(), deserialized.value.as_slice());
    assert_eq!(derived_key.salt, deserialized.salt);
  }
}
