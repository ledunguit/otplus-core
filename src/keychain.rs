use keyring::Entry;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyChainError {
  #[error("Keychain error: {0}")]
  KeyringError(#[from] keyring::Error),

  #[error("Keychain entry not found")]
  NotFound,
}

pub struct KeyChain {
  service: String,
  account: String,
}

impl KeyChain {
  pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
      Self {
          service: service.into(),
          account: account.into(),
      }
  }

  fn entry(&self) -> Result<Entry, KeyChainError> {
      Ok(Entry::new(&self.service, &self.account)?)
  }

  pub fn set_password(&self, password: &str) -> Result<(), KeyChainError> {
      self.entry()?.set_password(password)?;
      Ok(())
  }

  pub fn get_password(&self) -> Result<String, KeyChainError> {
      match self.entry()?.get_password() {
          Ok(pwd) => Ok(pwd),
          Err(keyring::Error::NoEntry) => Err(KeyChainError::NotFound),
          Err(e) => Err(KeyChainError::KeyringError(e)),
      }
  }

  pub fn delete_credential(&self) -> Result<(), KeyChainError> {
      match self.entry()?.delete_credential() {
          Ok(_) => Ok(()),
          Err(keyring::Error::NoEntry) => Err(KeyChainError::NotFound),
          Err(e) => Err(KeyChainError::KeyringError(e)),
      }
  }
}

#[cfg(test)]
mod keychain_tests {
  use super::*;

  #[ignore = "reason: this test will set the password to the keychain, so it should be ignored from CI"]
  #[test]
  fn test_keychain_set_password() {
    let keychain = KeyChain::new("com.zed.otplus-core", "zed");
    keychain.set_password("password").unwrap();
  }

  #[ignore = "reason: this test will get the password from the keychain, so it should be ignored from CI"]
  #[test]
  fn test_keychain_get_password() {
    let keychain = KeyChain::new("com.zed.otplus-core", "zed");
    let password = keychain.get_password().unwrap();
    println!("Password: {password}");
    assert_eq!(password, "password");
  }
}
