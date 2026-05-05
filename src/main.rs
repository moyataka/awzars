//! awzars: Modern Rust-based Azure AD to AWS credential federation

use awzars::cli::{Args, Command};
use awzars::error::AwzarsError;
use clap::Parser;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    install_panic_hook();
    let args = Args::parse();

    // Apply --config-dir / AWZARS_CONFIG_DIR before anything else touches
    // config_dir(), so the override is honored consistently.
    if let Some(ref dir) = args.config_dir {
        if let Err(e) = awzars::config::set_config_dir_override(dir) {
            eprintln!("Error: {}", e);
            return ExitCode::from(2);
        }
    }

    // Setup logging
    let log_level = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)),
        )
        .init();

    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::from(error_to_exit_code(&e))
        }
    }
}

async fn run(args: Args) -> awzars::error::Result<()> {
    match &args.command {
        Command::Login { .. } => awzars::cli::commands::login::execute(&args).await,
        Command::Configure { .. } => awzars::cli::commands::configure::execute(&args).await,
        Command::ListRoles { .. } => awzars::cli::commands::list_roles::execute(&args).await,
        Command::CredentialProcess { .. } => {
            awzars::cli::commands::credential_process::execute(&args).await
        }
        Command::ClearCache { yes } => {
            if !*yes {
                let prompt = format!(
                    "Clear cached credentials for profile '{}'? Next AWS call will require browser re-auth.",
                    args.profile
                );
                let confirmed = dialoguer::Confirm::new()
                    .with_prompt(&prompt)
                    .default(false)
                    .interact()
                    .map_err(|e| AwzarsError::Dialog(e.to_string()))?;
                if !confirmed {
                    println!("Aborted.");
                    return Ok(());
                }
            }
            awzars::storage::cache::clear_profile_cache(&args.profile)?;
            let keyring = awzars::storage::keyring::KeyringStorage::new(&args.profile)?;
            keyring.delete_credentials()?;
            println!(
                "Cache and keyring credentials cleared for profile '{}'",
                args.profile
            );
            Ok(())
        }
        Command::DeleteProfile { yes } => {
            awzars::cli::commands::delete_profile::run(&args.profile, *yes)
        }
        Command::Tui => awzars::cli::commands::tui::execute(&args).await,
        Command::SetPassword { remove } => {
            awzars::cli::commands::set_password::run(&args.profile, *remove)
        }
        Command::Unlock {
            allow_ai,
            ttl_hours,
            allow_long_ttl,
        } => awzars::cli::commands::unlock::run(
            &args.profile,
            *allow_ai,
            *ttl_hours,
            *allow_long_ttl,
        ),
        Command::Lock => awzars::cli::commands::lock::run(&args.profile),
    }
}

/// Install a panic hook that restores terminal state and wipes in-process
/// key material before the default handler prints the panic and aborts.
///
/// `panic = "abort"` (release profile) skips Drop, so Zeroize impls do not
/// run during a panic. The hook wires up best-effort cleanup so a TUI panic
/// does not leave the user's shell in raw mode and does not leave cookie
/// keys in heap memory longer than necessary.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableMouseCapture,
            crossterm::cursor::Show,
        );
        awzars::browser::cookie_crypto::cleanup_keys();
        default_hook(info);
    }));
}

fn error_to_exit_code(e: &AwzarsError) -> u8 {
    match e {
        AwzarsError::Config(_) => 2,
        AwzarsError::AzureAuth(_) => 3,
        AwzarsError::Saml(_) => 3,
        AwzarsError::AwsSts(_) => 5,
        AwzarsError::Browser(_) => 4,
        AwzarsError::Storage(_) => 5,
        AwzarsError::Network(_) => 4,
        AwzarsError::ProfileNotFound(_) => 2,
        AwzarsError::NoRolesAvailable => 3,
        AwzarsError::CredentialExpired => 5,
        AwzarsError::Tui(_) => 6,
        AwzarsError::UserQuit => 0,
        AwzarsError::Cache(_) => 5,
        AwzarsError::Keyring(_) => 5,
        AwzarsError::Dialog(_) => 6,
        AwzarsError::Io(_) => 1,
        AwzarsError::Json(_) => 1,
        AwzarsError::Toml(_) => 1,
        AwzarsError::Http(_) => 4,
        AwzarsError::LockedProfile { .. } => 7,
        AwzarsError::AiContextBlocked { .. } => 8,
        AwzarsError::LockVerificationFailed => 9,
        AwzarsError::LockRequiresTty => 10,
    }
}
