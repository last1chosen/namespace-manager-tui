//! # Security Module
//!
//! Handles binary hardening, path validation, and the trusted execution registry.
//! This module uses the Typestate pattern to ensure only verified binaries can be executed.

use crate::scanner::{NsError, NsResult, host::Host};
// can remove OnceCell crate once #109737 <https://github.com/rust-lang/rust/issues/109737> is resolved (then can use std::sync::OnceLock)
use once_cell::sync::OnceCell;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, error};

/// A marker for a path that has been canonicalized, checked for root ownership,
/// and verified to not be world-writable.
#[derive(Debug, Clone)]
pub struct ValidatedBin(Arc<Path>);

impl ValidatedBin {
    /// Access the underlying path. We provide this as a method rather than
    /// public field to maintain the Typestate guarantee.
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// The trusted paths we allow binaries to be sourced from.
pub const TRUSTED_PATHS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"];
pub const WORLD_WRITABLE: u32 = 0o002;

/// Centralized registry for all binaries used by the scanner.
pub struct BinaryRegistry {
    pub nsenter: ValidatedBin,
    pub ip: ValidatedBin,
    pub ss: ValidatedBin,
    pub nft: ValidatedBin,
    pub docker: Option<ValidatedBin>,
}

static REGISTRY: OnceCell<Arc<BinaryRegistry>> = OnceCell::new();

impl BinaryRegistry {
    /// Initialize the global registry using the host's filesystem view.
    pub fn initialize(host: &impl Host) -> NsResult<Arc<BinaryRegistry>> {
        REGISTRY
            .get_or_try_init(|| -> NsResult<Arc<BinaryRegistry>> {
                debug!("Initializing secure binary registry (locked)...");

                let new_registry = BinaryRegistry {
                    nsenter: find_and_harden_bin("nsenter", host)?,
                    ip: find_and_harden_bin("ip", host)?,
                    ss: find_and_harden_bin("ss", host)?,
                    nft: find_and_harden_bin("nft", host)?,
                    docker: find_and_harden_bin("docker", host).ok(),
                };

                Ok(Arc::new(new_registry))
            })
            .map(Arc::clone)
    }
}

/// Core hardening logic: verifies binary ownership and permissions.
fn find_and_harden_bin(name: &str, host: &impl Host) -> NsResult<ValidatedBin> {
    for dir in TRUSTED_PATHS {
        let path = PathBuf::from(dir).join(name);

        if host.exists(&path) {
            // 1. Resolve symlinks to absolute physical path
            let real_path = host.canonicalize(&path).map_err(|e| NsError::IoWithPath {
                source: e,
                path: path.clone(),
            })?;

            // 2. Perform UID and Permission checks
            host.verify_binary_security(&real_path)?;

            debug!("Binary hardened and validated: {:?}", real_path);
            return Ok(ValidatedBin(real_path.into()));
        }
    }

    error!("Critical binary missing from trusted paths: {}", name);
    Err(NsError::MissingBinary(name.to_string()))
}

/// A principled namespace validator that uses kernel identity ("DNA matching")
/// to prevent TOCTOU and correctly handle virtual filesystem objects.
pub fn validate_ns_path(path: &str, host: &impl Host) -> NsResult<PathBuf> {
    //     // 1. Lexical pre-filter (Keep as is)
    //     if !path
    //         .chars()
    //         .all(|c| c.is_alphanumeric() || "/._-".contains(c))
    //     {
    //         return Err(NsError::InvalidPath("Illegal characters in path".into()));
    //     }

    let path_obj = Path::new(path);

    // 2. Metadata Check (Source of Truth)
    let meta = host.metadata(path_obj).map_err(|e| NsError::IoWithPath {
        source: e,
        path: path.into(),
    })?;

    // 3. Attempt to read the kernel handle string
    match host.read_link(path_obj) {
        Ok(link) => {
            let link_str = link.to_string_lossy();

            // --- UPDATED UNIVERSAL CHECK ---
            // We check for the characteristic ':[inode]' pattern used by the kernel
            // for ALL namespace types (net, mnt, pid, etc.)
            if !link_str.contains(":[") || !link_str.ends_with(']') {
                return Err(NsError::InvalidPath(
                    "Path is not a recognized kernel namespace handle".into(),
                ));
            }

            let inode_from_link = crate::scanner::utilities::parse_ns_inode(&link_str)
                .ok_or_else(|| NsError::InvalidPath("Malformed namespace handle text".into()))?;

            // DNA Match (Anti-TOCTOU)
            if inode_from_link != meta.inode {
                return Err(NsError::InsecureBinary(
                    "Namespace identity mismatch (TOCTOU)".into(),
                ));
            }
        }
        Err(_) => {
            // 4. BIND-MOUNT FALLBACK (Important for Kubernetes/Docker)
            // K8s often bind-mounts namespaces into specific pods.
            // These won't have link text, so we rely on the 0-size + Inode check.
            if meta.size != 0 {
                return Err(NsError::InvalidPath(
                    "Resource reports invalid data size".into(),
                ));
            }
            debug!(
                "Trusting bind-mounted namespace at {} (Inode: {})",
                path, meta.inode
            );
        }
    }
    // 5. Canonicalization (Keep your existing logic)
    if !path.starts_with("/proc/") {
        let canon = host
            .canonicalize(path_obj)
            .map_err(|e| NsError::IoWithPath {
                source: e,
                path: path.into(),
            })?;
        return Ok(canon);
    }

    Ok(path_obj.to_path_buf())
}

// use std::fs::File;
// use std::os::unix::fs::MetadataExt;
// use std::os::unix::io::AsRawFd;

// pub struct ValidatedHandle {
//     pub path: PathBuf,
//     pub file: File,
//     pub inode: u64,
// }

// pub fn validate_ns_path(path: &str) -> NsResult<ValidatedHandle> {
//     // 1. Lexical check (defense in depth)
//     if !path
//         .chars()
//         .all(|c| c.is_alphanumeric() || "/._-".contains(c))
//     {
//         return Err(NsError::InvalidPath("Illegal characters".into()));
//     }

//     // 2. OPEN THE HANDLE (The point of no return)
//     // By opening first, we lock the kernel onto the resource.
//     let file = File::open(path).map_err(|e| NsError::IoWithPath {
//         source: e,
//         path: path.into(),
//     })?;
//     let fd = file.as_raw_fd();

//     // 3. FSTAT the FD (Not the path!)
//     // This ensures we are getting metadata for the EXACT file we just opened.
//     let meta = file.metadata().map_err(|e| NsError::IoWithPath {
//         source: e,
//         path: path.into(),
//     })?;
//     let stat_inode = meta.ino();

//     // 4. DNA Check via /proc/self/fd (Cross-reference)
//     // We read the "link" of our own file descriptor to see what the kernel says it is.
//     let fd_path = format!("/proc/self/fd/{}", fd);
//     let link = std::fs::read_link(&fd_path)
//         .map_err(|_| NsError::InvalidPath("Kernel handle verification failed".into()))?;
//     let link_str = link.to_string_lossy();

//     // 5. Atomic DNA Match
//     if link_str.contains(":[") {
//         let inode_from_link = crate::scanner::utilities::parse_ns_inode(&link_str)
//             .ok_or_else(|| NsError::InvalidPath("Malformed kernel handle".into()))?;

//         if inode_from_link != stat_inode {
//             return Err(NsError::InsecureBinary(
//                 "Namespace identity mismatch (TOCTOU)".into(),
//             ));
//         }
//     } else {
//         // Fallback for bind-mounts: verify 0-size via the open FD
//         if meta.len() != 0 {
//             return Err(NsError::InvalidPath("Invalid resource size".into()));
//         }
//     }

//     Ok(ValidatedHandle {
//         path: PathBuf::from(path),
//         file,
//         inode: stat_inode,
//     })
// }
