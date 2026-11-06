use crate::error::{AwzarsError, Result};
use nix::sys::select::{select, FdSet, FD_SETSIZE};
use nix::sys::termios::{self, FlushArg, LocalFlags, SetArg, Termios};
use nix::sys::time::{TimeVal, TimeValLike};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use zeroize::Zeroizing;

struct TerminalEchoGuard {
    terminal: File,
    original: Termios,
}

impl Drop for TerminalEchoGuard {
    fn drop(&mut self) {
        // TCSAFLUSH can wait indefinitely for unread terminal output on macOS.
        let _ = termios::tcflush(&self.terminal, FlushArg::TCIFLUSH);
        let _ = termios::tcsetattr(&self.terminal, SetArg::TCSANOW, &self.original);
    }
}

pub(super) fn read(prompt: &str) -> Result<Zeroizing<String>> {
    let _interruption = crate::util::interrupt::protect_cleanup()?;
    let terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|error| AwzarsError::Dialog(format!("cannot open /dev/tty: {error}")))?;
    read_from_terminal(terminal, prompt)
}

fn read_from_terminal(terminal: File, prompt: &str) -> Result<Zeroizing<String>> {
    if terminal.as_raw_fd() as usize >= FD_SETSIZE {
        return Err(AwzarsError::Dialog(
            "Too many open files to wait for terminal password input".into(),
        ));
    }
    let original = termios::tcgetattr(&terminal)
        .map_err(|error| AwzarsError::Dialog(format!("tcgetattr: {error}")))?;
    let guard = TerminalEchoGuard { terminal, original };
    let mut quiet = guard.original.clone();
    quiet
        .local_flags
        .remove(LocalFlags::ECHO | LocalFlags::ECHOE | LocalFlags::ECHOK);
    quiet
        .local_flags
        .insert(LocalFlags::ECHONL | LocalFlags::ICANON | LocalFlags::ISIG);
    termios::tcsetattr(&guard.terminal, SetArg::TCSANOW, &quiet)
        .map_err(|error| AwzarsError::Dialog(format!("tcsetattr: {error}")))?;
    let mut terminal = &guard.terminal;
    write!(terminal, "{prompt}: ")?;
    terminal.flush()?;
    let mut password = Zeroizing::new(Vec::new());
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        crate::util::interrupt::check()?;
        // macOS does not support poll reliably for terminal descriptors.
        let mut descriptors = FdSet::new();
        descriptors.insert(terminal.as_fd());
        let mut timeout = TimeVal::milliseconds(100);
        match select(None, Some(&mut descriptors), None, None, Some(&mut timeout)) {
            Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(AwzarsError::Dialog(format!("select /dev/tty: {error}"))),
            Ok(_) => {}
        }
        match terminal.read(byte.as_mut()) {
            Ok(0) => {
                return Err(AwzarsError::Dialog(
                    "Password input ended before Enter".into(),
                ))
            }
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => password.push(byte[0]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
        if password.len() > 8192 {
            return Err(AwzarsError::Dialog("Password input is too long".into()));
        }
    }
    if password.last() == Some(&b'\r') {
        password.pop();
    }
    std::str::from_utf8(&password)
        .map(|password| Zeroizing::new(password.to_owned()))
        .map_err(|_| AwzarsError::Dialog("Password is not valid UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    #[test]
    fn terminal_echo_is_restored_after_password_or_signal() {
        const CHILD: &str = "AWZARS_PASSWORD_TERMINAL_TEST";
        if let Ok(mode) = std::env::var(CHILD) {
            let _interruption = crate::util::interrupt::protect_cleanup().unwrap();
            let terminal = File::from(std::io::stdin().as_fd().try_clone_to_owned().unwrap());
            let result = read_from_terminal(terminal, "Test password");
            if mode == "password" {
                assert_eq!(result.unwrap().as_str(), "test-password");
            } else {
                assert!(matches!(result, Err(AwzarsError::Interrupted(_))));
            }
            return;
        }
        for mode in ["password", "interrupt", "terminate"] {
            let terminal = nix::pty::openpty(None, None).unwrap();
            // Leave output unread: restoring echo must not wait for it to drain.
            let mut master = File::from(terminal.master);
            let slave = File::from(terminal.slave);
            let original = termios::tcgetattr(&slave).unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "auth::password_prompt::tests::terminal_echo_is_restored_after_password_or_signal"])
                .env(CHILD, mode).stdin(Stdio::from(slave.try_clone().unwrap()))
                .stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while termios::tcgetattr(&slave)
                .unwrap()
                .local_flags
                .contains(LocalFlags::ECHO)
            {
                if Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("password prompt did not become ready in {mode} mode");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            match mode {
                "password" => master.write_all(b"test-password\n").unwrap(),
                "interrupt" => kill(Pid::from_raw(child.id() as i32), Signal::SIGINT).unwrap(),
                _ => kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM).unwrap(),
            }
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("password prompt did not stop in {mode} mode");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert!(status.success(), "child failed in {mode} mode: {status}");
            assert_eq!(
                termios::tcgetattr(&slave).unwrap().local_flags,
                original.local_flags
            );
        }
    }
}
