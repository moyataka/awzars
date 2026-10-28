//! TUI config manager command

use crate::cli::args::Args;
use crate::config::Config;
use crate::error::{AwzarsError, Result};
use crate::tui::manager::ConfigManager;

pub async fn execute(_args: &Args) -> Result<()> {
    let config = load_config()?;

    match ConfigManager::new(config) {
        Ok(manager) => match manager.run() {
            Ok(()) => Ok(()),
            Err(AwzarsError::UserQuit) => Ok(()),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    }
}

/// Load the config the TUI edits. A missing file gives an empty config, but a
/// file that exists and fails to load is an error: the TUI saves the whole
/// config back, so starting from an empty one would overwrite the file.
fn load_config() -> Result<Config> {
    Config::load()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_config_fails_on_unreadable_file_and_allows_missing_file() {
        const TEST_DIRECTORY: &str = "AWZARS_TUI_LOAD_CONFIG_TEST";
        let Ok(directory) = std::env::var(TEST_DIRECTORY) else {
            let directory = tempfile::tempdir().unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cli::commands::tui::tests::load_config_fails_on_unreadable_file_and_allows_missing_file",
                ])
                .env(TEST_DIRECTORY, directory.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        };
        crate::config::set_config_dir_override(&directory).unwrap();
        let path = crate::config::config_file().unwrap();

        // No file yet: the TUI opens with an empty config.
        assert!(load_config().unwrap().profiles.is_empty());

        // A file that exists but is not valid TOML must not be replaced by an
        // empty config, and the file itself stays as it was.
        let broken = "[profiles.dev]\nrole_arn = \"unterminated\n";
        std::fs::write(&path, broken).unwrap();
        assert!(matches!(load_config(), Err(AwzarsError::Toml(_))));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), broken);
    }
}
