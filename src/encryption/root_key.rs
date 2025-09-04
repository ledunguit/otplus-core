use chacha20poly1305::{aead::{KeyInit, OsRng}, Key, ChaCha20Poly1305};
use zeroize::Zeroize;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de::Error;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::ser::SerializeStruct;
use chrono::Utc;

#[derive(Debug, Clone)]
pub struct RootKeyMetadata {
    pub created_at: i64,
    pub key_length: u32,
}

impl Serialize for RootKeyMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RootKeyMetadata", 2)?;
        state.serialize_field("created_at", &self.created_at)?;
        state.serialize_field("key_length", &self.key_length)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RootKeyMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RootKeyMetadataHelper {
            created_at: i64,
            key_length: u32,
        }

        let helper = RootKeyMetadataHelper::deserialize(deserializer)?;
        Ok(Self { created_at: helper.created_at, key_length: helper.key_length })
    }
}

#[derive(Debug, Clone)]
pub struct RootKey {
    pub value: Key,
    pub metadata: RootKeyMetadata,
}

impl Serialize for RootKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RootKey", 2)?;
        state.serialize_field("value", &STANDARD.encode(&self.value.as_slice()))?;
        state.serialize_field("metadata", &self.metadata)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RootKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RootKeyHelper {
            value: String,
            metadata: RootKeyMetadata,
        }

        let helper = RootKeyHelper::deserialize(deserializer)?;
        let key = STANDARD.decode(&helper.value)
            .map_err(|e| Error::custom(e.to_string()))?;
        
        if key.len() != 32 {
            return Err(Error::custom("Invalid key length"));
        }

        Ok(Self { value: Key::from_slice(&key).clone(), metadata: helper.metadata })
    }
}

impl Drop for RootKey {
    fn drop(&mut self) {
        self.value.as_mut_slice().zeroize();
    }
}

impl Default for RootKey {
    fn default() -> Self {
        let mut os_rng = OsRng::default();
        let value = ChaCha20Poly1305::generate_key(&mut os_rng);
        Self { value, metadata: RootKeyMetadata { created_at: Utc::now().timestamp_millis(), key_length: 32 } }
    }
}

#[cfg(test)]
mod data_key_tests {
    use super::*;

    #[test]
    fn test_data_key_default() {
        let dek = RootKey::default();
        assert_eq!(dek.value.as_slice().len(), 32);
        assert_eq!(dek.metadata.key_length, 32);
    }

    #[test]
    fn test_data_key_serialize_deserialize() {
        let dek = RootKey::default();
        let serialized = serde_json::to_string(&dek).unwrap();
        println!("Serialized: {}", serialized);
        let deserialized: RootKey = serde_json::from_str(&serialized).unwrap();
        println!("Deserialized: {:?}", deserialized);
    }
}