use anyhow::{Context, Error};
use clap::{value_parser, Arg, ArgAction, Command};
use std::fs;
use std::io; // Removed unused import of Read
use std::path::Path; // Import anyhow Error and Context

/// Builds the command-line interface for the Arti application.
///
/// # Returns
/// A `Command` instance representing the CLI.
pub fn build_cli() -> Command {
    Command::new("arti")
        .arg(
            Arg::new("fix")
                .long("fix")
                .action(ArgAction::SetFalse)
                .help("Attempt to fix detected issues"),
        )
        .arg(
            Arg::new("keystore")
                .long("keystore")
                .action(ArgAction::Set)
                .help("Path to the keystore directory")
                .required(true),
        )
        .version("0.1")
        .author("Your Name <your.email@example.com>")
        .about("Arti onion service client")
        .subcommand(
            Command::new("hss")
                .about("Manage onion service state")
                .subcommand(
                    Command::new("keys")
                        .about("Manage keys for onion services")
                        .subcommand(
                            Command::new("list")
                                .about("List keys and certificates from the keystore")
                                .arg(
                                    Arg::new("keystore")
                                        .long("keystore")
                                        .action(ArgAction::Set)
                                        .help("Path to the keystore directory")
                                        .required(true),
                                ),
                        ),
                ),
        )
}

/// Removes a key at the specified path.
///
/// # Parameters
/// - `path`: The path to the key to be removed.
///
/// # Returns
/// A `Result` indicating success or failure.
pub fn remove_key_by_path(path: &str) -> anyhow::Result<()> {
    std::fs::remove_file(path).context(format!("Failed to remove key at path: {}", path))?;
    Ok(())
}

/// Migrates a key from the specified source path to the destination path.
///
/// # Parameters
/// - `from_path`: The source path of the key to migrate.
/// - `to_path`: The destination path for the migrated key.
///
/// # Returns
/// A `Result` indicating success or failure.
pub fn migrate_keys(from_path: &str, to_path: &str) -> Result<(), crate::Error> {
    std::fs::copy(from_path, to_path).context(format!(
        "Failed to migrate key from {} to {}",
        from_path, to_path
    ))?;
    Ok(())
}

/// Formats the output data based on the use_colon flag.
/// If use_colon is true, replaces spaces with colons; otherwise, returns the data as is.
pub fn output_in_field_format(data: &str, use_colon: bool) -> String {
    if use_colon {
        data.replace(" ", ":")
    } else {
        data.to_string()
    }
}
