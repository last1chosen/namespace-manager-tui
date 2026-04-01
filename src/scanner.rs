//! # Scanner Module (The Facade)
//!
//! This is the primary entry point for the namespace management engine.
//! It orchestrates discovery, security, and inspection.

pub mod discovery;
pub mod error;
pub mod exec;
pub mod host;
pub mod inspector;
pub mod security;
pub mod structs;
pub mod utilities;

pub use error::{NsError, NsResult};
pub use host::{Host, LinuxHost};

use crate::models::{NamespaceDetail, NetworkNamespace, PeerInfo};
use crate::scanner::discovery::{
    collect_host_namespace, collect_named_namespaces, scan_proc_for_namespaces,
};
use crate::scanner::inspector::Inspector;
use crate::scanner::security::{BinaryRegistry, validate_ns_path};
use crate::scanner::utilities::get_network_id;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};

// Constants re-exported for module-wide access
pub const DEFAULT_CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
pub const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);
pub const MAX_PROC_SCAN_DEPTH: usize = 5000;
pub const DOCKER_ID_LEN: usize = 12;

/// Newtype wrappers for safety
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Inode(pub u64);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pid(pub u32);

/// The Orchestrator Service.
/// This is the struct the TUI interacts with.
pub struct NamespaceService<H: Host = LinuxHost> {
    bins: Arc<BinaryRegistry>,
    host: H,
}

impl NamespaceService<LinuxHost> {
    /// Factory method for production.
    pub fn new() -> NsResult<Self> {
        let host = LinuxHost::new()?;
        Self::with_host(host)
    }
}

impl<H: Host> NamespaceService<H> {
    pub fn with_host(host: H) -> NsResult<Self> {
        let bins = BinaryRegistry::initialize(&host)?;
        info!("Scanner Service initialized with hardened binary registry.");
        Ok(Self { bins, host })
    }

    /// High-level API to scan the system and return all discovered namespaces.
    pub fn gather_all_namespaces(&self) -> NsResult<Vec<NetworkNamespace>> {
        debug!("Starting system-wide namespace discovery...");
        let mut ns_map: HashMap<Inode, NetworkNamespace> = HashMap::new();

        // 1. Get docker names (if docker is available)
        let docker_names = self.get_docker_names();

        // 2. Execute discovery strategies
        collect_host_namespace(&mut ns_map, &self.host)?;
        collect_named_namespaces(&mut ns_map, &self.host)?;
        scan_proc_for_namespaces(&mut ns_map, &docker_names, &self.host)?;

        // 3. Quick-scan for basic metrics (Interface count and IPs)
        let inspector = Inspector::new(&self.bins, &self.host);
        let mut result: Vec<NetworkNamespace> = ns_map.into_values().collect();

        // Finalize metadata for the TUI list view
        for ns in result.iter_mut() {
            match inspector.fetch_details(&ns.ns_path, Inode(ns.inode)) {
                Ok((details, _)) => {
                    ns.num_interfaces = details.interfaces.len();
                    ns.ip_prefixes = details
                        .interfaces
                        .iter()
                        .filter(|i| i.ip != "N/A")
                        .map(|i| i.ip.clone())
                        .collect();
                }
                Err(e) => {
                    warn!(
                        "Security or access error for namespace {} ({}): {}. Skipping metadata.",
                        ns.name, ns.ns_path, e
                    );
                }
            }
        }

        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    /// Fetches the deep-dive details for the currently selected namespace.
    pub fn fetch_details(
        &self,
        ns_path: &str,
        target_inode: Inode,
    ) -> NsResult<(NamespaceDetail, Vec<String>)> {
        validate_ns_path(ns_path, &self.host)?;
        let inspector = Inspector::new(&self.bins, &self.host);
        inspector.fetch_details(ns_path, target_inode)
    }

    /// Logic for resolving cross-namespace peers (Subnet detection).
    pub fn resolve_peers(
        &self,
        current_ips: &[String],
        all_ns: &[NetworkNamespace],
        target_inode: Inode,
    ) -> Vec<PeerInfo> {
        let mut peers = Vec::new();
        let mut seen_inodes = HashSet::new();

        let my_networks: Vec<String> = current_ips
            .iter()
            .filter_map(|cidr| match get_network_id(cidr) {
                Ok(net) => Some(net),
                Err(e) => {
                    warn!("Invalid CIDR in current namespace '{}': {}", cidr, e);
                    None
                }
            })
            .collect();

        for other_ns in all_ns {
            if other_ns.inode == target_inode.0 || seen_inodes.contains(&other_ns.inode) {
                continue;
            }
            for other_cidr in &other_ns.ip_prefixes {
                if let Ok(other_net) = get_network_id(other_cidr) {
                    if my_networks.contains(&other_net) {
                        peers.push(PeerInfo {
                            name: other_ns.name.clone(),
                            _ip: other_cidr.clone(),
                            _inode: other_ns.inode,
                        });
                        seen_inodes.insert(other_ns.inode);
                        break; // Found a matching network for this namespace
                    }
                } else {
                    debug!(
                        "Skipping malformed CIDR '{}' in namespace {}",
                        other_cidr, other_ns.name
                    );
                }
            }
        }
        peers
    }

    /// Private helper to resolve container IDs to human-readable names.
    fn get_docker_names(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        let Some(ref docker_bin) = self.bins.docker else {
            return map;
        };

        let args = ["ps".into(), "--format".into(), "{{.ID}}|{{.Names}}".into()];
        if let Ok(out) = self.host.execute(docker_bin.as_path(), &args) {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if let Some((id, name)) = line.split_once('|') {
                    map.insert(id.into(), name.into());
                }
            }
        }
        map
    }
}
