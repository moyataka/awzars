//! Completions command: print a shell completion script.
//!
//! The script is generated from the clap definition, so it never reads the
//! configuration, the keychain or the unlock state.

use crate::cli::Args;
use crate::error::Result;
use clap::CommandFactory;
use clap_complete::{Generator, Shell};
use std::io::Write;

/// Write the completion script for `shell` to stdout.
pub fn execute(shell: Shell) -> Result<()> {
    write_script(shell, &mut std::io::stdout().lock())
}

/// Write the completion script for `shell` to `out`. A closed pipe (for
/// example `awzars completions fish | head`) is not an error.
fn write_script(shell: Shell, out: &mut dyn Write) -> Result<()> {
    let mut command = Args::command();
    command.set_bin_name("awzars");
    command.build();
    // The generators panic on some write errors (the fish one even inside
    // `try_generate`), and release builds abort on panic. Writing to memory
    // cannot fail, so generate the whole script first and write it here.
    let mut script = Vec::new();
    shell.try_generate(&command, &mut script)?;
    match out.write_all(&script).and_then(|()| out.flush()) {
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        result => Ok(result?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Command;
    use clap::{Parser, ValueEnum};

    #[test]
    fn every_shell_script_names_every_subcommand() {
        let command = Args::command();
        let subcommands: Vec<&str> = command
            .get_subcommands()
            .filter(|subcommand| !subcommand.is_hide_set())
            .map(|subcommand| subcommand.get_name())
            .collect();
        assert!(subcommands.contains(&"completions"));
        for shell in Shell::value_variants() {
            let mut script = Vec::new();
            write_script(*shell, &mut script).unwrap();
            let script = String::from_utf8(script).unwrap();
            assert!(script.contains("awzars"), "{shell}");
            for subcommand in &subcommands {
                assert!(script.contains(subcommand), "{shell}: {subcommand}");
            }
        }
    }

    struct FailingWriter(std::io::ErrorKind);

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(self.0.into())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(self.0.into())
        }
    }

    #[test]
    fn a_closed_pipe_is_not_an_error_but_other_write_errors_are() {
        for shell in Shell::value_variants() {
            let mut closed = FailingWriter(std::io::ErrorKind::BrokenPipe);
            assert!(write_script(*shell, &mut closed).is_ok(), "{shell}");

            let mut full = FailingWriter(std::io::ErrorKind::StorageFull);
            assert!(
                matches!(
                    write_script(*shell, &mut full),
                    Err(crate::error::AwzarsError::Io(_))
                ),
                "{shell}"
            );
        }
    }

    #[test]
    fn completions_takes_one_known_shell() {
        let args = Args::try_parse_from(["awzars", "completions", "fish"]).unwrap();
        assert!(matches!(
            args.command,
            Command::Completions { shell: Shell::Fish }
        ));
        assert_eq!(
            Args::try_parse_from(["awzars", "completions", "tcsh"])
                .unwrap_err()
                .kind(),
            clap::error::ErrorKind::InvalidValue
        );
        assert_eq!(
            Args::try_parse_from(["awzars", "completions"])
                .unwrap_err()
                .kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }
}
