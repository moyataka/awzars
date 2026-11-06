use crate::error::{AwzarsError, Result};
use once_cell::sync::OnceCell;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

struct SignalState {
    signal: Arc<AtomicUsize>,
    use_default_handler: Arc<AtomicBool>,
    active_guards: Mutex<usize>,
}

static SIGNAL: OnceCell<SignalState> = OnceCell::new();

pub struct InterruptionGuard(&'static SignalState);

impl Drop for InterruptionGuard {
    fn drop(&mut self) {
        let mut active = self
            .0
            .active_guards
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *active -= 1;
        if *active == 0 {
            self.0.use_default_handler.store(true, Ordering::SeqCst);
        }
    }
}

pub fn protect_cleanup() -> std::io::Result<InterruptionGuard> {
    let state = SIGNAL.get_or_try_init(|| {
        let signal = Arc::new(AtomicUsize::new(0));
        let use_default_handler = Arc::new(AtomicBool::new(true));
        let mut registrations = Vec::new();
        let register = (|| {
            for number in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
                registrations.push(signal_hook::flag::register_conditional_default(
                    number,
                    use_default_handler.clone(),
                )?);
                registrations.push(signal_hook::flag::register_usize(
                    number,
                    signal.clone(),
                    number as usize,
                )?);
            }
            Ok::<_, std::io::Error>(())
        })();
        if let Err(error) = register {
            for registration in registrations {
                signal_hook::low_level::unregister(registration);
            }
            return Err(error);
        }
        Ok(SignalState {
            signal,
            use_default_handler,
            active_guards: Mutex::new(0),
        })
    })?;
    let mut active = state
        .active_guards
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *active += 1;
    state.use_default_handler.store(false, Ordering::SeqCst);
    Ok(InterruptionGuard(state))
}

pub fn check() -> Result<()> {
    match SIGNAL
        .get()
        .map(|state| state.signal.load(Ordering::SeqCst))
        .unwrap_or(0)
    {
        0 => Ok(()),
        signal => Err(AwzarsError::Interrupted(signal as u8)),
    }
}

pub async fn wait() -> AwzarsError {
    loop {
        if let Err(error) = check() {
            return error;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

pub async fn until_interrupted<T>(
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! {
        biased;
        error = wait() => Err(error),
        result = operation => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn cleanup_guards_restore_normal_signal_delivery() {
        const CHILD: &str = "AWZARS_INTERRUPT_GUARD_TEST";
        if std::env::var_os(CHILD).is_some() {
            let outer = protect_cleanup().unwrap();
            let inner = protect_cleanup().unwrap();
            drop(inner);
            nix::sys::signal::raise(nix::sys::signal::Signal::SIGTERM).unwrap();
            assert!(matches!(check(), Err(AwzarsError::Interrupted(15))));
            drop(outer);
            nix::sys::signal::raise(nix::sys::signal::Signal::SIGTERM).unwrap();
            panic!("normal signal handling was not restored");
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "util::interrupt::tests::cleanup_guards_restore_normal_signal_delivery",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_eq!(
            output.status.signal(),
            Some(nix::sys::signal::Signal::SIGTERM as i32),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
