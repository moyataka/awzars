//! TUI config manager command

use crate::cli::args::Args;
use crate::config::Config;
use crate::error::{AwzarsError, Result};
use crate::tui::manager::ConfigManager;

pub async fn execute(_args: &Args) -> Result<()> {
    let config = Config::load().unwrap_or_default();

    match ConfigManager::new(config) {
        Ok(manager) => match manager.run() {
            Ok(()) => Ok(()),
            Err(AwzarsError::UserQuit) => Ok(()),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    }
}
