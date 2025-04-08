//! A minimal client for connecting to the tor network
//!
//! See the [crate-level documentation](::arti).

// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->
use clap::Command; // Import value_parser
use tracing::info; // Import logging macro from tracing
use tracing_subscriber; // Import tracing_subscriber for setting up logging

mod key_management; // Ensure the module is declared
mod subcommands; // Assuming you have a module named subcommands

fn main() {
    // Initialize the logger
    env_logger::init(); // Initialize the logger
    tracing_subscriber::fmt::init(); // Initialize the tracing subscriber

    // Define the main CLI application
    let matches = Command::new("Arti")
        .version("1.0")
        .author("The Tor Project")
        .about("A Rust implementation of Tor")
        .subcommand(key_management::define_key_management_subcommand()) // Register the key-management subcommand
        .get_matches();

    // Handle the subcommands here
    if let Some(matches) = matches.subcommand_matches("keys") {
        key_management::handle_key_management(matches); // Call the key management handler
    } else {
        eprintln!("Error: Unrecognized subcommand");
    }
}
