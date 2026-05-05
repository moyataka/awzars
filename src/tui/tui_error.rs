//! Helpers for wrapping TUI/crossterm/io errors into `AwzarsError::Tui`.

use crate::error::{AwzarsError, Result};

/// Convert any displayable error into `AwzarsError::Tui` via its `Display`
/// representation.
///
/// Used for crossterm/ratatui errors that don't carry domain meaning beyond
/// "the TUI subsystem failed". Their concrete error types are not part of
/// our public API surface, so stringifying is fine.
pub trait TuiResultExt<T> {
    fn tui(self) -> Result<T>;
}

impl<T, E: std::fmt::Display> TuiResultExt<T> for std::result::Result<T, E> {
    fn tui(self) -> Result<T> {
        self.map_err(|e| AwzarsError::Tui(e.to_string()))
    }
}
