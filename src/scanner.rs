//! # Scanner Module
//!
//! This module provides the core engine for discovering and inspecting Linux network namespaces.
//! It uses a "Service Pattern" to manage binary verification and secure system inspection.

mod error;
mod structs;
mod utilities;

pub use error::{NsError, NsResult};

use crate::models::{
    FirewallInfo, InterfaceInfo, ListeningPort, NamespaceDetail, NamespaceType, NetworkNamespace,
    PeerInfo, ProcessInfo, RouteInfo,
};
use crate::scanner::structs::{IpAddrJson, IpRouteJson};
use crate::scanner::utilities::collect_host;
use std::collections::HashSet;
use std::{
    collections::HashMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Arc, OnceLock},
    thread,
    time::{Duration, Instant},
};
use tracing::{debug, error, info, warn};
use utilities::{
    collect_named, detect_type, get_container_id_from_pid, get_network_id, redact_env_var,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Inode(pub u64);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pid(pub u32);

const WORLD_WRITABLE: u32 = 0o002;
const DOCKER_ID_LEN: usize = 12;
const DEFAULT_CMD_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PROC_SCAN_DEPTH: usize = 5000;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const TRUSTED_PATHS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"];

trait CommandExt {
    fn output_checked(&mut self, timeout: Duration) -> NsResult<Output>;
}

impl CommandExt for Command {
    fn output_checked(&mut self, timeout: Duration) -> NsResult<Output> {
        let mut child = self.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    return Ok(child.wait_with_output()?);
                }
                Ok(None) => {
                    if start.elapsed() > timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(NsError::Timeout("Command execution exceeded limit".into()));
                    }
                    thread::sleep(POLL_INTERVAL);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

pub struct BinaryRegistry {
    pub nsenter: PathBuf,
    pub ip: PathBuf,
    pub ss: PathBuf,
    pub nft: PathBuf,
    pub docker: Option<PathBuf>,
}

static REGISTRY: OnceLock<Arc<BinaryRegistry>> = OnceLock::new();

impl BinaryRegistry {
    pub fn get() -> NsResult<Arc<BinaryRegistry>> {
        if let Some(registry) = REGISTRY.get() {
            return Ok(Arc::clone(registry));
        }

        info!("Initializing Binary Registry...");
        let new_registry = Arc::new(BinaryRegistry {
            nsenter: find_and_harden_bin("nsenter")?,
            ip: find_and_harden_bin("ip")?,
            ss: find_and_harden_bin("ss")?,
            nft: find_and_harden_bin("nft")?,
            docker: find_and_harden_bin("docker").ok(),
        });

        let _ = REGISTRY.set(Arc::clone(&new_registry));

        Ok(new_registry)
    }
}

fn find_and_harden_bin(name: &str) -> NsResult<PathBuf> {
    for dir in TRUSTED_PATHS {
        let path = PathBuf::from(dir).join(name);
        if path.exists() {
            let real_path = fs::canonicalize(&path)?;
            let meta = fs::metadata(&real_path)?;

            if meta.uid() != 0 || (meta.permissions().mode() & WORLD_WRITABLE) != 0 {
                return Err(NsError::InsecureBinary(format!(
                    "Security check failed for {}",
                    name
                )));
            }
            debug!("Binary verified: {:?}", real_path);
            return Ok(real_path);
        }
    }
    Err(NsError::MissingBinary(name.to_string()))
}

fn check_is_root() -> bool {
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
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

fn validate_ns_path(path: &str) -> NsResult<()> {
    let p = Path::new(path);
    if !path
        .chars()
        .all(|c| c.is_alphanumeric() || "/._-".contains(c))
    {
        return Err(NsError::InvalidPath(
            "Path contains illegal characters".into(),
        ));
    }
    let l_meta = fs::symlink_metadata(p)
        .map_err(|_| NsError::InvalidPath(format!("Path {} not accessible", path)))?;

    if l_meta.file_type().is_symlink() && !path.starts_with("/proc/") {
        return Err(NsError::InsecureBinary(
            "Untrusted symbolic link detected".into(),
        ));
    }
    Ok(())
}

// --- The Service Layer ---

pub struct NamespaceService {
    bins: Arc<BinaryRegistry>,
}

impl NamespaceService {
    pub fn new() -> NsResult<Self> {
        if !check_is_root() {
            return Err(NsError::InsufficientPrivileges("Root required".into()));
        }
        Ok(Self {
            bins: BinaryRegistry::get()?,
        })
    }

    pub fn gather_all_namespaces(&self) -> NsResult<Vec<NetworkNamespace>> {
        debug!("Scanning system for namespaces...");
        let mut ns_map: HashMap<Inode, NetworkNamespace> = HashMap::new();
        let docker_names = self.get_docker_names();

        collect_host(&mut ns_map)?;
        collect_named(&mut ns_map)?;
        self.scan_processes(&mut ns_map, &docker_names)?;

        for ns in ns_map.values_mut() {
            ns.num_interfaces = self.count_ifaces(&ns.ns_path);
            ns.ip_prefixes = self.get_namespace_ips(&ns.ns_path);
        }

        let mut result: Vec<NetworkNamespace> = ns_map.into_values().collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

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
            .filter_map(|cidr| get_network_id(cidr))
            .collect();

        if my_networks.is_empty() {
            return peers;
        }

        for other_ns in all_ns {
            // Skip self
            if other_ns.inode == target_inode.0 {
                continue;
            }

            if seen_inodes.contains(&other_ns.inode) {
                continue;
            }

            for other_cidr in &other_ns.ip_prefixes {
                if let Some(other_net) = get_network_id(other_cidr) {
                    if my_networks.contains(&other_net) {
                        peers.push(PeerInfo {
                            name: other_ns.name.clone(),
                            _ip: other_cidr.clone(),
                            _inode: other_ns.inode,
                        });
                        seen_inodes.insert(other_ns.inode);
                        break;
                    }
                }
            }
        }
        peers
    }

    fn get_namespace_ips(&self, ns_path: &str) -> Vec<String> {
        let mut ips = Vec::new();

        if let Ok(output) = Command::new(&self.bins.nsenter)
            .arg(format!("--net={}", ns_path))
            .arg("--")
            .arg(&self.bins.ip)
            .args(&["-j", "addr", "show"])
            .output_checked(DEFAULT_CMD_TIMEOUT)
        {
            if let Ok(json) = serde_json::from_slice::<Vec<IpAddrJson>>(&output.stdout) {
                for iface in json {
                    if iface.ifname == "lo" {
                        continue;
                    }

                    // Note: Currently only supports IPv4 peer detection
                    for addr in iface.addr_info {
                        ips.push(format!("{}/{}", addr.local, addr.prefixlen));
                    }
                }
            }
        }
        ips
    }

    fn ns_exec(&self, ns_path: &str, bin: &PathBuf, args: &[&str]) -> NsResult<Output> {
        Command::new(&self.bins.nsenter)
            .arg(format!("--net={}", ns_path))
            .arg("--")
            .arg(bin)
            .args(args)
            .output_checked(DEFAULT_CMD_TIMEOUT)
    }

    pub fn fetch_details(
        &self,
        ns_path: &str,
        target_inode: Inode,
    ) -> NsResult<(NamespaceDetail, Vec<String>)> {
        validate_ns_path(ns_path)?;

        let mut details = NamespaceDetail::default();
        let mut warnings = Vec::new();

        // 1. Interfaces
        match self.ns_exec(ns_path, &self.bins.ip, &["-j", "-s", "addr", "show"]) {
            Ok(output) => {
                // --- USAGE OF ParseError ---
                let json: Vec<IpAddrJson> = serde_json::from_slice(&output.stdout)
                    .map_err(|e| NsError::ParseError(format!("IP JSON Parse Fail: {e}")))?;

                for iface in json {
                    let (rx, tx) = iface
                        .stats64
                        .map(|s| (s.rx.bytes, s.tx.bytes))
                        .unwrap_or((0, 0));
                    details.interfaces.push(InterfaceInfo {
                        name: iface.ifname,
                        state: iface.operstate.to_uppercase(),
                        mtu: iface.mtu,
                        ip: iface
                            .addr_info
                            .first()
                            .map(|a| format!("{}/{}", a.local, a.prefixlen))
                            .unwrap_or_else(|| "N/A".into()),
                        rx_bytes: rx,
                        tx_bytes: tx,
                    });
                }
            }
            Err(e) => warnings.push(format!("Interface scan failed: {}", e)),
        }

        // 2. Routes
        match self.ns_exec(ns_path, &self.bins.ip, &["-j", "route", "show"]) {
            Ok(output) => {
                // --- USAGE OF ParseError ---
                match serde_json::from_slice::<Vec<IpRouteJson>>(&output.stdout) {
                    Ok(routes) => {
                        for r in routes {
                            details.routes.push(RouteInfo {
                                dst: r.dst,
                                gateway: r.gateway.unwrap_or_else(|| "0.0.0.0".into()),
                                dev: r.dev.unwrap_or_default(),
                            });
                        }
                    }
                    Err(e) => warnings.push(format!("Route JSON Parse Fail: {}", e)),
                }
            }
            Err(e) => warnings.push(format!("Route scan failed: {}", e)),
        }

        // 3. Listening Ports
        match self.ns_exec(ns_path, &self.bins.ss, &["-lntuH"]) {
            Ok(output) => {
                let out_str = String::from_utf8_lossy(&output.stdout);
                for line in out_str.lines() {
                    let cols: Vec<&str> = line.split_whitespace().collect();
                    if cols.len() >= 5 {
                        let local = cols[4];
                        if let Some(idx) = local.rfind(':') {
                            details.ports.push(ListeningPort {
                                proto: cols[0].to_string(),
                                addr: local[..idx].to_string(),
                                port: local[idx + 1..].to_string(),
                            });
                        }
                    }
                }
            }
            Err(e) => warnings.push(format!("Port scan failed: {}", e)),
        }

        // 4. Firewall
        match self.ns_exec(ns_path, &self.bins.nft, &["list", "ruleset"]) {
            Ok(output) => {
                let out_str = String::from_utf8_lossy(&output.stdout);
                let chains = out_str
                    .lines()
                    .filter(|l| l.trim().starts_with("chain "))
                    .count();
                let rules = out_str
                    .lines()
                    .filter(|l| l.contains("accept") || l.contains("drop"))
                    .count();
                details.firewall = FirewallInfo {
                    chains: chains,
                    rules: rules,
                };
            }
            Err(e) => warnings.push(format!("Firewall scan failed: {}", e)),
        }

        // 5. Processes
        self.scan_details_processes(&mut details, target_inode)?;

        Ok((details, warnings))
    }

    fn scan_processes(
        &self,
        map: &mut HashMap<Inode, NetworkNamespace>,
        docker_names: &HashMap<String, String>,
    ) -> NsResult<()> {
        let entries = fs::read_dir("/proc")?;
        for entry in entries.flatten().take(MAX_PROC_SCAN_DEPTH) {
            let pid_s = entry.file_name().to_string_lossy().into_owned();
            if let Ok(pid_val) = pid_s.parse::<u32>() {
                let ns_l = format!("/proc/{}/ns/net", pid_val);
                if let Ok(meta) = fs::metadata(&ns_l) {
                    let inode = Inode(meta.ino());
                    let comm = fs::read_to_string(format!("/proc/{}/comm", pid_val))
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    if !comm.is_empty() {
                        let ns_entry = map.entry(inode).or_insert_with(|| NetworkNamespace {
                            name: format!("{}-{}", comm, pid_val),
                            ns_type: detect_type(&comm),
                            inode: inode.0,
                            ns_path: ns_l.clone(),
                            num_interfaces: 0,
                            process_names: vec![],
                            primary_pid: Some(pid_val),
                            ip_prefixes: vec![],
                        });
                        ns_entry.process_names.push(comm.clone());
                        if let Some(cid) = get_container_id_from_pid(Pid(pid_val)) {
                            if let Some(real_name) = docker_names.get(&cid) {
                                ns_entry.name = real_name.clone();
                                ns_entry.ns_type = NamespaceType::Container;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Scans the entire /proc filesystem to find all processes associated with a specific
    /// network namespace inode. It populates detailed process info including command lines
    /// and environment variables.
    fn scan_details_processes(
        &self,
        details: &mut NamespaceDetail,
        target_inode: Inode,
    ) -> NsResult<()> {
        debug!("Performing deep process scan for Inode: {}", target_inode.0);

        let entries = fs::read_dir("/proc").map_err(|e| {
            error!("Failed to read /proc directory: {}", e);
            NsError::IoWithPath {
                source: e,
                path: PathBuf::from("/proc"),
            }
        })?;

        for entry in entries.flatten().take(MAX_PROC_SCAN_DEPTH) {
            let pid_s = entry.file_name().to_string_lossy().into_owned();

            // Only process directories that are valid PIDs (numeric)
            if let Ok(pid_val) = pid_s.parse::<u32>() {
                let proc_root = Path::new("/proc").join(&pid_s);
                let ns_path = proc_root.join("ns/net");

                // Check if the process's network namespace matches our target inode
                // Note: We use metadata() which follows the magic symlink in /proc
                if let Ok(meta) = fs::metadata(&ns_path) {
                    if meta.ino() == target_inode.0 {
                        // 1. Get process name (comm)
                        let name = fs::read_to_string(proc_root.join("comm"))
                            .unwrap_or_else(|_| "unknown".to_string())
                            .trim()
                            .to_string();

                        // 2. Get full command line
                        // /proc/[pid]/cmdline uses null-bytes as separators
                        let cmdline_raw = fs::read(proc_root.join("cmdline")).unwrap_or_default();
                        let cmdline = String::from_utf8_lossy(&cmdline_raw)
                            .replace('\0', " ")
                            .trim()
                            .to_string();

                        // 3. Get Environment Variables
                        // /proc/[pid]/environ also uses null-bytes as separators
                        let env_raw = fs::read(proc_root.join("environ")).unwrap_or_default();
                        let env_vars: Vec<String> = env_raw
                            .split(|&b| b == 0)
                            .filter(|s| !s.is_empty())
                            .map(|s| redact_env_var(&String::from_utf8_lossy(s)))
                            .collect();

                        debug!(
                            "Found process in namespace: [{}] {} (Env: {})",
                            pid_val,
                            name,
                            env_vars.len()
                        );

                        details.processes.push(ProcessInfo {
                            pid: pid_val,
                            name,
                            cmdline,
                            env_vars,
                        });
                    }
                }
            }
        }

        details.processes.sort_by_key(|p| p.pid);

        if details.processes.is_empty() {
            warn!(
                "No processes found for Inode {}. This can happen if the namespace is stale.",
                target_inode.0
            );
        }

        Ok(())
    }

    fn count_ifaces(&self, ns_path: &str) -> usize {
        Command::new(&self.bins.nsenter)
            .arg(format!("--net={}", ns_path))
            .arg("--")
            .arg(&self.bins.ip)
            .args(["-o", "link"])
            .output_checked(DEFAULT_CMD_TIMEOUT)
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
            .unwrap_or(0)
    }

    fn get_docker_names(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Some(ref d) = self.bins.docker {
            if let Ok(out) = Command::new(d)
                .args(["ps", "--format", "{{.ID}}|{{.Names}}"])
                .output_checked(DEFAULT_CMD_TIMEOUT)
            {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    if let Some((id, name)) = line.split_once('|') {
                        map.insert(id.into(), name.into());
                    }
                }
            }
        }
        map
    }
}
