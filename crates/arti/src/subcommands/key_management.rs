use clap::{value_parser, Arg, Command}; // Import value_parser
use tracing::info; // Import the info macro for logging
use tor_basic_utils::PathExt; // Import PathExt for display_lossy method
use std::io::{self, Read};
use std::{fs, path::Path}; // Re-added import for Read trait
use crate::cli::migrate_keys; // Import migrate_keys function
use crate::subcommands::validation::{validate_keystore_directory, validate_key_file}; // Import validation module
use serde_json::json; // Import json for creating JSON objects

/// Entry point for the `key_management` module, adding subcommands to manage keys.
/// This module provides functionality to list, check integrity, and remove keys from the keystore.
pub(crate) fn define_key_management_subcommand() -> Command {
    Command::new("keys") // Fixed semicolon placement
        .about("Manage keys for onion services")
        .subcommand(
            Command::new("destroy")
                .about("Remove all keys and state of an onion service")
                .arg(
                    Arg::new("keystore")
                        .long("keystore")
                        .value_parser(value_parser!(String))
                        .help("Path to the keystore directory")
                        .required(true),
                ),
        )
        .arg(Arg::new("json")
            .long("json")
            .help("Output results in JSON format")
            .required(false))
        .subcommand(Command::new("migrate")
            .about("Migrate keys from C Tor to Arti")
            .arg(Arg::new("c_tor_path")
                .long("c-tor-path")
                .value_parser(value_parser!(String))
                .help("Path to C Tor hidden service directory")
                .required(true))
            .arg(Arg::new("arti_keystore")
                .long("arti-keystore")
                .value_parser(value_parser!(String))
                .help("Path to Arti keystore directory")
                .required(true)))
        .subcommand(
            Command::new("destroy-and-recreate")
                .about("Generate new identity (set of keys) for an existing onion service")
                .arg(
                    Arg::new("keystore")
                        .long("keystore")
                        .value_parser(value_parser!(String))
                        .help("Path to the keystore directory")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("list")
                .about("List keys and certificates from the keystore")
                .arg(
                    Arg::new("keystore")
                        .long("keystore")
                        .value_parser(value_parser!(String)) // Updated to use value_parser
                        .help("Path to the keystore directory")
                        .required(true),
                )
                .arg(Arg::new("json")
                    .long("json")
                    .help("Output results in JSON format")
                    .required(false)),
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
                )
                .arg(
                    Arg::new("fix")
                        .long("fix")
                        .help("Attempt to fix detected issues")
                        .required(false),
                )
                .arg(
                    Arg::new("json")
                        .long("json")
                        .help("Output results in JSON format")
                        .required(false),
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

pub(crate) fn handle_key_management(matches: &clap::ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(migrate_matches) = matches.subcommand_matches("migrate") {
        if let Some(c_tor_path) = migrate_matches.get_one::<String>("c_tor_path") {
            if let Some(arti_keystore) = migrate_matches.get_one::<String>("arti_keystore") {
                migrate_keys(c_tor_path, arti_keystore)?;
                return Ok(());
            }
        }
        return Err("C Tor path and Arti keystore path are required.".into());
    }

    info!("Received matches: {:?}", matches);

    if let Some(matches) = matches.subcommand_matches("keys") {
        if let Some(list_matches) = matches.subcommand_matches("list") {
            if let Some(keystore_path) = list_matches.get_one::<String>("keystore") {
                let json_output = list_matches.contains_id("json");
                list_keys(keystore_path, json_output)?; 
            } else {
                return Err("No keystore path provided for list command".into());
            }
        } else if let Some(check_matches) = matches.subcommand_matches("check") {
            if let Some(keystore_path) = check_matches.get_one::<String>("keystore") {
                let fix = check_matches.contains_id("fix");
                let json_output = check_matches.contains_id("json");
                check_keys_integrity(keystore_path, fix, json_output)?; 
            } else {
                return Err("No keystore path provided for check command".into());
            }
        }
        // Handle other subcommands here...
    }

    Ok(()) // Ensure this is placed at the end to avoid premature returns
}

fn list_keys(keystore_path: &str, json_output: bool) -> Result<(), Box<dyn std::error::Error>> {
    let keystore_dir = Path::new(keystore_path);
    let mut keys = Vec::new();

    for entry in fs::read_dir(keystore_dir)? {
        let path = entry?.path();
        if path.is_file() {
            keys.push(path.display().to_string());
        }
    }

    if json_output {
        let json_result = serde_json::to_string_pretty(&keys)?;
        println!("{}", json_result);
    } else {
        for key in &keys {
            println!("{}", key);
        }
    }

    Ok(())
}

fn check_keys_integrity(keystore_path: &str, fix: bool, json_output: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    
    for entry in fs::read_dir(keystore_path)? {
        let path = entry?.path();
        let status = if path.is_file() {
            match check_keys_integrity(&path) {
                Ok(_) => "valid",
                Err(_) => "corrupted",
            }
        } else {
            "unknown"
        };

        results.push(json!({ "file": path.display().to_string(), "status": status }));
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        for res in results {
            println!("{}: {}", res["file"], res["status"]);
        }
    }

    Ok(())
}
