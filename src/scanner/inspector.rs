//! # Inspector Module
//!
//! Performs deep inspection of network namespaces to extract interfaces,
//! routes, listening ports, firewall rules, and process details.

use crate::models::{
    FirewallInfo, InterfaceInfo, ListeningPort, NamespaceDetail, ProcessInfo, RouteInfo,
};
use crate::scanner::exec::{NamespaceExecutor, NetworkCommand};
use crate::scanner::host::Host;
use crate::scanner::security::BinaryRegistry;
use crate::scanner::structs::{IpAddrJson, IpRouteJson};
use crate::scanner::utilities::redact_env_var;
use crate::scanner::{DEFAULT_CMD_TIMEOUT, Inode, MAX_PROC_SCAN_DEPTH, NsError, NsResult};

use std::path::Path;
use tracing::warn;

//TODO - these consts should be configurable via flags when launching the app
const MAX_PROCESSES_PER_NS: usize = 1_000; // do not show more than 1000 namespaces.
const MAX_ENV_VARS_PER_PROC: usize = 100; // do not show more than 100 variables. 
const MAX_ENV_VAL_LEN: usize = 128;

pub struct Inspector<'a, H: Host> {
    bins: &'a BinaryRegistry,
    host: &'a H,
}

impl<'a, H: Host> Inspector<'a, H> {
    pub fn new(bins: &'a BinaryRegistry, host: &'a H) -> Self {
        Self { bins, host }
    }

    /// Fetches full details for a specific namespace.
    pub fn fetch_details(
        &self,
        ns_path: &str,
        target_inode: Inode,
    ) -> NsResult<(NamespaceDetail, Vec<String>)> {
        let mut details = NamespaceDetail::default();
        let mut warnings = Vec::new();
        let executor = NamespaceExecutor::new(&self.bins.nsenter, ns_path);

        // 1. Interfaces (via ip -j addr)
        if let Err(e) = self.inspect_interfaces(&executor, &mut details) {
            warnings.push(format!("Interface scan failed: {e}"));
        }

        // 2. Routes (via ip -j route)
        if let Err(e) = self.inspect_routes(&executor, &mut details) {
            warnings.push(format!("Route scan failed: {e}"));
        }

        // 3. Listening Ports (via ss -lntuH)
        if let Err(e) = self.inspect_ports(&executor, &mut details) {
            warnings.push(format!("Port scan failed: {e}"));
        }

        // 4. Firewall (via nft list ruleset)
        if let Err(e) = self.inspect_firewall(&executor, &mut details) {
            warnings.push(format!("Firewall scan failed: {e}"));
        }

        // 5. Active Processes (Host-side scan of /proc)
        if let Err(e) = self.inspect_processes(target_inode, &mut details) {
            warnings.push(format!("Process detail scan failed: {e}"));
        }

        Ok((details, warnings))
    }

    fn inspect_interfaces(
        &self,
        exec: &NamespaceExecutor,
        details: &mut NamespaceDetail,
    ) -> NsResult<()> {
        let output = exec.execute(
            &self.bins.ip,
            NetworkCommand::ShowAddresses,
            DEFAULT_CMD_TIMEOUT,
        )?;
        let json: Vec<IpAddrJson> = serde_json::from_slice(&output.stdout)
            .map_err(|e| NsError::ParseError(format!("IP JSON parse failure: {e}")))?;

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
        Ok(())
    }

    fn inspect_routes(
        &self,
        exec: &NamespaceExecutor,
        details: &mut NamespaceDetail,
    ) -> NsResult<()> {
        let output = exec.execute(
            &self.bins.ip,
            NetworkCommand::ShowRoutes,
            DEFAULT_CMD_TIMEOUT,
        )?;
        let routes: Vec<IpRouteJson> = serde_json::from_slice(&output.stdout).unwrap_or_default();

        for r in routes {
            details.routes.push(RouteInfo {
                dst: r.dst,
                gateway: r.gateway.unwrap_or_else(|| "0.0.0.0".into()),
                dev: r.dev.unwrap_or_default(),
            });
        }
        Ok(())
    }

    fn inspect_ports(
        &self,
        exec: &NamespaceExecutor,
        details: &mut NamespaceDetail,
    ) -> NsResult<()> {
        let output = exec.execute(
            &self.bins.ss,
            NetworkCommand::ShowSockets,
            DEFAULT_CMD_TIMEOUT,
        )?;
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
        Ok(())
    }

    fn inspect_firewall(
        &self,
        exec: &NamespaceExecutor,
        details: &mut NamespaceDetail,
    ) -> NsResult<()> {
        let output = exec.execute(
            &self.bins.nft,
            NetworkCommand::ShowFirewall,
            DEFAULT_CMD_TIMEOUT,
        )?;
        let out_str = String::from_utf8_lossy(&output.stdout);

        let chains = out_str
            .lines()
            .filter(|l| l.trim().starts_with("chain "))
            .count();
        let rules = out_str
            .lines()
            .filter(|l| l.contains("accept") || l.contains("drop"))
            .count();

        details.firewall = FirewallInfo { chains, rules };
        Ok(())
    }

    fn inspect_processes(
        &self,
        target_inode: Inode,
        details: &mut NamespaceDetail,
    ) -> NsResult<()> {
        let entries = self.host.read_dir(Path::new("/proc"))?;

        for entry_path in entries.iter().take(MAX_PROC_SCAN_DEPTH) {
            if details.processes.len() >= MAX_PROCESSES_PER_NS {
                warn!("Namespace process limit reached; skipping remainder.");
                break;
            }
            let pid_s = entry_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            let Ok(pid_val) = pid_s.parse::<u32>() else {
                continue;
            };

            let ns_path = entry_path.join("ns/net");
            if let Ok(inode_val) = self.host.metadata(&ns_path) {
                if inode_val.inode == target_inode.0 {
                    let name = self
                        .host
                        .read_to_string(&entry_path.join("comm"))
                        .unwrap_or_else(|_| "unknown".into())
                        .trim()
                        .to_string();

                    let cmdline_raw = self
                        .host
                        .read_bytes(&entry_path.join("cmdline"))
                        .unwrap_or_default();
                    let cmdline = String::from_utf8_lossy(&cmdline_raw)
                        .replace('\0', " ")
                        .trim()
                        .to_string();

                    let env_raw = self
                        .host
                        .read_bytes(&entry_path.join("environ"))
                        .unwrap_or_default();
                    let env_vars = env_raw
                        .split(|&b| b == 0)
                        .filter(|s| !s.is_empty())
                        .take(MAX_ENV_VARS_PER_PROC)
                        .map(|s| {
                            let decoded = String::from_utf8_lossy(s);
                            let redacted = redact_env_var(&decoded);

                            // LIMIT 2: Length Truncation
                            if redacted.len() > MAX_ENV_VAL_LEN {
                                format!("{}...", &redacted[..MAX_ENV_VAL_LEN])
                            } else {
                                redacted
                            }
                        })
                        .collect();

                    details.processes.push(ProcessInfo {
                        pid: pid_val,
                        name,
                        cmdline,
                        env_vars,
                    });
                }
            }
        }
        details.processes.sort_by_key(|p| p.pid);
        Ok(())
    }
}
