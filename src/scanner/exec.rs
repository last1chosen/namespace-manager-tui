//! # Execution Module
//!
//! Provides type-safe wrappers for command execution within network namespaces.
//! Enforces timeouts, environment isolation, and utilizes the `ValidatedBin` typestate.

use crate::scanner::security::ValidatedBin;
use crate::scanner::{NsError, NsResult, POLL_INTERVAL};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// RAII guard that guarantees child process reaping on drop.
/// This prevents zombie processes even in the face of panics or early returns.
struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    /// Disarms the guard and returns ownership of the child.
    /// This should only be called when we successfully get the output.
    fn disarm(mut self) -> Child {
        self.0.take().expect("ChildGuard already disarmed")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            // 1. Terminate the process if it's still running
            let _ = child.kill();

            // 2. CRITICAL: Block until the process is reaped to prevent zombies.
            // We retry on EINTR to handle signal interruptions (like window resizing).
            loop {
                match child.wait() {
                    Ok(_) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        }
    }
}

/// Extension trait for `std::process::Command` to provide checked output with
/// custom timeout logic and guaranteed process reaping via RAII.
pub trait CommandExt {
    fn output_checked(&mut self, timeout: Duration) -> NsResult<Output>;
}

impl CommandExt for Command {
    fn output_checked(&mut self, timeout: Duration) -> NsResult<Output> {
        let child = self.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        let mut guard = ChildGuard::new(child);

        let start = Instant::now();

        loop {
            // Safety: guard.0 is always Some until disarm() is called
            let child = guard.0.as_mut().unwrap();

            match child.try_wait() {
                Ok(Some(_status)) => {
                    // Process exited - disarm guard and drain the pipes
                    let child = guard.disarm();
                    return Ok(child.wait_with_output()?);
                }
                Ok(None) => {
                    if start.elapsed() > timeout {
                        // Drop(guard) handles kill + wait
                        return Err(NsError::Timeout(
                            "Command execution timed out and process reaped".into(),
                        ));
                    }
                    thread::sleep(POLL_INTERVAL);
                }
                Err(e) => {
                    // Drop(guard) handles cleanup on OS errors
                    return Err(e.into());
                }
            }
        }
    }
}

/// Type-safe network inspection commands.
/// This ensures only known-safe flag combinations are ever sent to the kernel.
#[derive(Debug, Clone, Copy)]
pub enum NetworkCommand {
    ShowAddresses,
    ShowRoutes,
    ShowSockets,
    ShowFirewall,
}
impl NetworkCommand {
    /// Converts command to validated, compile-time constant arguments.
    fn to_args(&self) -> &'static [&'static str] {
        match self {
            Self::ShowAddresses => &["-j", "-s", "addr", "show"],
            Self::ShowRoutes => &["-j", "route", "show"],
            Self::ShowSockets => &["-lntuH"],
            Self::ShowFirewall => &["list", "ruleset"],
        }
    }
}

/// A specialized executor for running commands inside a target namespace.
pub struct NamespaceExecutor<'a> {
    pub nsenter: &'a ValidatedBin,
    pub target_ns_path: &'a str,
}

impl<'a> NamespaceExecutor<'a> {
    /// Constructs a new executor.
    pub fn new(nsenter: &'a ValidatedBin, target_ns_path: &'a str) -> Self {
        Self {
            nsenter,
            target_ns_path,
        }
    }

    /// Executes a type-safe network command inside the target namespace.
    ///
    /// This is the **preferred API** as it prevents command injection by design.
    pub fn execute(
        &self,
        bin: &ValidatedBin,
        command: NetworkCommand,
        timeout: Duration,
    ) -> NsResult<Output> {
        let mut cmd = Command::new(self.nsenter.as_path());

        // SECURITY: Environment Scrubbing
        // Prevents LD_PRELOAD and library hijacking attacks.
        cmd.env_clear();

        // Build: nsenter --net=/path/to/ns -- [bin] [compile-time args]
        cmd.arg(format!("--net={}", self.target_ns_path));
        cmd.arg("--");
        cmd.arg(bin.as_path());

        for arg in command.to_args() {
            cmd.arg(arg);
        }

        cmd.output_checked(timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_command_args() {
        assert_eq!(
            NetworkCommand::ShowAddresses.to_args(),
            &["-j", "-s", "addr", "show"]
        );
    }
}
