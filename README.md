# OTPlus Core

OTPlus Core is a library for creating and managing OTPlus keys for encrypting and decrypting data.

## Features

- Create root key for encrypting and decrypting data
- Create derived key from passphrase
- Create header for storing the root key and derived key

## Usage

- Create root key
```rust
use otplus_core::encryption::RootKey;

let root_key = RootKey::default();
```

- Create derived key from passphrase
```rust
use otplus_core::encryption::DerivedKey;

let derived_key = DerivedKey::new("password", vec![0; 16], 32);
```

## License

MIT

## Author

[OTPlus](https://dung.io.vn)