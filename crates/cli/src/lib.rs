//! pwk: command line client for Passwork 7. The binary is a thin wrapper around
//! [`main`]; the modules are public so they can be tested and reused by the commands.

pub mod cli;
pub mod commands;
pub mod config;
pub mod dotenv;
pub mod fsutil;
pub mod output;
pub mod prompt;
pub mod reference;
pub mod run;
pub mod session;

use std::process::ExitCode;

use clap::Parser as _;

/// Parses the command line, runs the command and maps errors to exit codes:
/// 0 success, 1 error (printed as `pwk: …`), 2 usage error (by clap).
pub fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    match commands::dispatch(cli) {
        Ok(code) => code,
        Err(error) => {
            output::print_error(&error);
            ExitCode::FAILURE
        }
    }
}
