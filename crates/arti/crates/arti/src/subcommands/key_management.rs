use clap::{App, Arg, SubCommand};

// Define the subcommand for listing keys
pub fn define_key_management_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("key-management") // This is the main command
        .about("Manage Onion Service Keys")   // Description of what this command does
        .subcommand(
            SubCommand::with_name("list-keys") // Subcommand to list keys
                .about("List all Onion Service keys") // Description of the subcommand
        )
}
