use std::fs;
use std::io;
use std::path::Path;

/// Validates the keystore directory and checks if it exists.
pub(crate) fn validate_keystore_directory(keystore_path: &str) -> Result<(), io::Error> {
    let path = Path::new(keystore_path);
    if !path.is_dir() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid keystore directory"));
    }
    Ok(())
}

/// Validates the key file and checks if it exists.
pub(crate) fn validate_key_file(key_path: &str) -> Result<(), io::Error> {
    let path = Path::new(key_path);
    if !path.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Key file does not exist"));
    }
    Ok(())
}
