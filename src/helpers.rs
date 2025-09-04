use base64::{engine::general_purpose::STANDARD, Engine};

pub struct Helpers;

impl Helpers {
  pub fn base64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
  }

  pub fn base64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(data)
  }
}