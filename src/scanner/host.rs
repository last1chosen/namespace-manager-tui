use crate::scanner::exec::CommandExt;
use crate::scanner::security::WORLD_WRITABLE;
use crate::scanner::{NsError, NsResult};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::{fs::read_to_string, io};
use tracing::error;

/// SEALED TRAIT PATTERN:
/// Ensures only types in this crate can implement 'Host', preventing
/// third-party bypasses of your security logic.
mod private {
    pub trait Sealed {}
}

pub struct HostMetadata {
    pub inode: u64,
    pub size: u64,
}

pub trait Host: private::Sealed + Send + Sync {
    // Filesystem abstractions
    fn metadata(&self, path: &Path) -> io::Result<HostMetadata>;
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>>;
    fn read_to_string(&self, path: &Path) -> io::Result<String>;
    fn read_bytes(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn read_link(&self, path: &Path) -> io::Result<PathBuf>;

    // Security-Critical abstractions
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf>;
    fn exists(&self, path: &Path) -> bool;

    // Command execution
    fn execute(&self, cmd: &Path, args: &[String]) -> NsResult<Output>;
    fn verify_binary_security(&self, path: &Path) -> NsResult<()>;
}

// --- PRODUCTION IMPLEMENTATION ---

pub struct LinuxHost {
    /// Private field ensures this struct can only be created via LinuxHost::new()
    _private: (),
}

impl private::Sealed for LinuxHost {}

impl LinuxHost {
    /// THE SECURITY GATEKEEPER:
    /// This is where the initial "Secure Boot" of your scanner happens.
    pub fn new() -> NsResult<Self> {
        if !check_is_root() {
            return Err(crate::scanner::NsError::InsufficientPrivileges(
                "Root required for network namespace inspection".into(),
            ));
        }
        Ok(Self { _private: () })
    }
}

fn check_is_root() -> bool {
    if let Ok(status) = read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    return parts[1] == "0" || parts[2] == "0";
                }
            }
        }
    }
    false
}

impl Host for LinuxHost {
    fn metadata(&self, path: &Path) -> io::Result<HostMetadata> {
        let meta = std::fs::metadata(path)?;
        Ok(HostMetadata {
            inode: meta.ino(),
            size: meta.len(),
        })
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        std::fs::read_dir(path)?
            .map(|res| res.map(|e| e.path()))
            .collect()
    }

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn read_bytes(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }
    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::read_link(path)
    }

    /// Used to resolve magic symlinks in /proc and verify binary paths
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::canonicalize(path)
    }

    /// Used by BinaryRegistry to find tools in TRUSTED_PATHS
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn execute(&self, cmd: &Path, args: &[String]) -> NsResult<Output> {
        use crate::scanner::DEFAULT_CMD_TIMEOUT;
        use std::process::Command;

        let mut command = Command::new(cmd);
        command.args(args);

        // Enforce the hardened timeout logic
        command.output_checked(DEFAULT_CMD_TIMEOUT)
    }

    fn verify_binary_security(&self, path: &Path) -> NsResult<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        // We still use std::fs here because this IS the Linux-specific
        // implementation where we expect a real filesystem.
        let meta = std::fs::metadata(path).map_err(|e| NsError::IoWithPath {
            source: e,
            path: path.to_path_buf(),
        })?;

        // EXACT MATCH of your original logic:
        // 1. Must be owned by root (UID 0)
        // 2. Must NOT be world-writable (WORLD_WRITABLE / 0o002)
        if meta.uid() != 0 || (meta.permissions().mode() & WORLD_WRITABLE) != 0 {
            error!(
                "SECURITY ALERT: Binary {} has insecure permissions!",
                path.display()
            );
            return Err(NsError::InsecureBinary(format!(
                "Security check failed for {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
pub struct MockHost {
    pub mock_inode: u64,
}

#[cfg(test)]
impl private::Sealed for MockHost {}

#[cfg(test)]
impl Host for MockHost {
    fn metadata(&self, _: &Path) -> io::Result<HostMetadata> {
        Ok(HostMetadata {
            inode: self.mock_inode,
            size: 0, // Namespaces are always 0
        })
    }
    fn read_dir(&self, _: &Path) -> io::Result<Vec<PathBuf>> {
        Ok(vec![])
    }

    fn read_to_string(&self, _: &Path) -> io::Result<String> {
        Ok("".into())
    }
    fn read_bytes(&self, _: &Path) -> io::Result<Vec<u8>> {
        Ok(vec![])
    }
    fn read_link(&self, _path: &Path) -> io::Result<PathBuf> {
        Ok(PathBuf::from(format!("net:[{}]", self.mock_inode)))
    }
    fn canonicalize(&self, p: &Path) -> io::Result<PathBuf> {
        Ok(p.to_path_buf())
    }
    fn exists(&self, _: &Path) -> bool {
        true
    }
    fn execute(&self, _: &Path, _: &[String]) -> NsResult<Output> {
        Ok(Output {
            status: Default::default(),
            stdout: vec![],
            stderr: vec![],
        })
    }
    fn verify_binary_security(&self, _path: &Path) -> NsResult<()> {
        // By default, mocks are secure.
        // You could add a 'should_fail_security' flag to MockHost to test the error path!
        Ok(())
    }
}
