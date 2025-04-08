use clap::{value_parser, Arg, Command}; // Import value_parser
use std::io::{self, Read};
use std::{fs, path::Path};
// Importing File

/// Entry point for the `key_management` module, adding subcommands to manage keys.
pub(crate) fn define_key_management_subcommand() -> Command {
    Command::new("keys") // Fixed semicolon placement
        .about("Manage keys for onion services")
        .subcommand(
            Command::new("list")
                .about("List keys and certificates from the keystore")
                .arg(
                    Arg::new("keystore")
                        .long("keystore")
                        .value_parser(value_parser!(String)) // Updated to use value_parser
                        .help("Path to the keystore directory")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("check")
                .about("Check integrity of keys in the keystore")
                .arg(
                    Arg::new("keystore")
                        .long("keystore")
                        .value_parser(value_parser!(String)) // Updated to use value_parser
                        .help("Path to the keystore directory")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove a specific key from the keystore")
                .arg(
                    Arg::new("keystore")
                        .long("keystore")
                        .value_parser(value_parser!(String)) // Updated to use value_parser
                        .help("Path to the keystore directory")
                        .required(true),
                )
                .arg(
                    Arg::new("key")
                        .long("key")
                        .value_parser(value_parser!(String)) // Updated to use value_parser
                        .help("Path of the key to remove")
                        .required(true),
                ),
        )
}

pub(crate) fn handle_key_management(matches: &clap::ArgMatches) {
    println!("Received matches: {:?}", matches); // Debugging output
    if let Some(matches) = matches.subcommand_matches("keys") {
        if let Some(list_matches) = matches.subcommand_matches("list") {
            if let Some(keystore_path) = list_matches.get_one::<String>("keystore") {
                list_keys(keystore_path);
            }
        } else if let Some(check_matches) = matches.subcommand_matches("check") {
            if let Some(keystore_path) = check_matches.get_one::<String>("keystore") {
                check_keys_integrity(keystore_path);
            }
        } else if let Some(remove_matches) = matches.subcommand_matches("remove") {
            if let Some(keystore_path) = remove_matches.get_one::<String>("keystore") {
                if let Some(key_path) = remove_matches.get_one::<String>("key") {
                    remove_key(keystore_path, key_path);
                }
            }
        }
    }
}

fn list_keys(keystore_path: &str) {
    println!("Listing keys from keystore at: {}", keystore_path);

    let keystore_dir = Path::new(keystore_path);
    if !keystore_dir.exists() || !keystore_dir.is_dir() {
        eprintln!("Error: Invalid keystore directory");
        return;
    }

    let entries = match fs::read_dir(keystore_dir) {
        Ok(entries) => entries,
        Err(_) => {
            eprintln!("Error: Could not read keystore directory");
            return;
        }
    };

    let mut keys_found = false;
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_file() {
            println!("Found key/certificate: {}", path.display());
            keys_found = true;
        }
    }

    if !keys_found {
        println!("No keys or certificates found in the keystore.");
    }
}

fn check_keys_integrity(keystore_path: &str) {
    println!(
        "Checking integrity of keys in keystore at: {}",
        keystore_path
    );

    let keystore_dir = Path::new(keystore_path);
    if !keystore_dir.exists() || !keystore_dir.is_dir() {
        eprintln!("Error: Invalid keystore directory");
        return;
    }

    let entries = match fs::read_dir(keystore_dir) {
        Ok(entries) => entries,
        Err(_) => {
            eprintln!("Error: Could not read keystore directory");
            return;
        }
    };

    let mut issues_found = false;
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_file() {
            // Here we can check for key file integrity
            // For example, just reading a few bytes to check file consistency
            if let Err(_) = check_file_integrity(&path) {
                eprintln!("Warning: Key file {} has integrity issues.", path.display());
                issues_found = true;
            }
        }
    }

    if !issues_found {
        println!("All keys in the keystore are intact.");
    }
}

fn check_file_integrity(path: &Path) -> io::Result<()> {
    let mut file = std::fs::File::open(path)?; // Specify the correct File import
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    // A basic check could be verifying if the file is empty or corrupt.
    if buffer.is_empty() {
        Err(io::Error::new(io::ErrorKind::InvalidData, "File is empty"))
    } else {
        Ok(())
    }
}

fn remove_key(keystore_path: &str, key_path: &str) {
    println!("Removing key at: {}", key_path);

    let keystore_dir = Path::new(keystore_path);
    if !keystore_dir.exists() || !keystore_dir.is_dir() {
        eprintln!("Error: Invalid keystore directory");
        return;
    }

    let key_file_path = Path::new(key_path);
    if !key_file_path.exists() {
        eprintln!("Error: Key file does not exist at {}", key_path);
        return;
    }

    if let Err(e) = fs::remove_file(key_file_path) {
        eprintln!("Error removing key file: {}", e);
    } else {
        println!("Key file removed successfully.");
    }
}
