use serde::Deserialize;
use std::{
    collections::HashMap,
    fs, io,
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Stdio},
};

use crate::models::{
    FirewallInfo, InterfaceInfo, ListeningPort, NamespaceDetail, NamespaceType, NetworkNamespace,
    ProcessInfo, RouteInfo,
};

#[derive(Deserialize, Debug)]
struct IpAddrJson {
    ifname: String,
    operstate: String,
    mtu: u64,
    addr_info: Vec<IpAddrInfoJson>,
    stats64: Option<IpStatsJson>,
}
#[derive(Deserialize, Debug)]
struct IpAddrInfoJson {
    local: String,
    prefixlen: u32,
    family: String,
}
#[derive(Deserialize, Debug)]
struct IpStatsJson {
    rx: IpStatsInner,
    tx: IpStatsInner,
}
#[derive(Deserialize, Debug)]
struct IpStatsInner {
    bytes: u64,
}
#[derive(Deserialize, Debug)]
struct IpRouteJson {
    dst: String,
    gateway: Option<String>,
    dev: Option<String>,
}

pub fn gather_namespaces() -> io::Result<Vec<NetworkNamespace>> {
    let mut ns_map: HashMap<u64, NetworkNamespace> = HashMap::new();
    let docker_names = get_docker_names();

    collect_host(&mut ns_map)?;
    collect_named(&mut ns_map)?;
    collect_docker(&mut ns_map)?;
    scan_processes(&mut ns_map, &docker_names)?;

    let mut result: Vec<NetworkNamespace> = ns_map.into_values().collect();
    for ns in &mut result {
        ns.finalize();
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}

pub fn fetch_details(ns_path: &str, target_inode: u64) -> NamespaceDetail {
    let mut details = NamespaceDetail::default();

    if let Ok(output) = Command::new("nsenter")
        .arg(format!("--net={}", ns_path))
        .arg("--")
        .args(&["ip", "-j", "-s", "addr", "show"])
        .stderr(Stdio::null())
        .output()
    {
        if let Ok(json) = serde_json::from_slice::<Vec<IpAddrJson>>(&output.stdout) {
            for iface in json {
                let mut ip_str = String::new();
                for addr in iface.addr_info {
                    if addr.family == "inet" {
                        ip_str = format!("{}/{}", addr.local, addr.prefixlen);
                        break;
                    }
                }
                let (rx, tx) = if let Some(stats) = iface.stats64 {
                    (stats.rx.bytes, stats.tx.bytes)
                } else {
                    (0, 0)
                };
                details.interfaces.push(InterfaceInfo {
                    name: iface.ifname,
                    state: iface.operstate.to_uppercase(),
                    mtu: iface.mtu,
                    ip: if ip_str.is_empty() {
                        "N/A".to_string()
                    } else {
                        ip_str
                    },
                    rx_bytes: rx,
                    tx_bytes: tx,
                });
            }
        }
    }

    if let Ok(output) = Command::new("nsenter")
        .arg(format!("--net={}", ns_path))
        .arg("--")
        .args(&["ip", "-j", "route", "show"])
        .stderr(Stdio::null())
        .output()
    {
        if let Ok(json) = serde_json::from_slice::<Vec<IpRouteJson>>(&output.stdout) {
            for route in json {
                details.routes.push(RouteInfo {
                    dst: route.dst,
                    gateway: route.gateway.unwrap_or_else(|| "0.0.0.0".to_string()),
                    dev: route.dev.unwrap_or_default(),
                });
            }
        }
    }

    if let Ok(output) = Command::new("nsenter")
        .arg(format!("--net={}", ns_path))
        .arg("--")
        .args(&["ss", "-lntuH"])
        .stderr(Stdio::null())
        .output()
    {
        let out_str = String::from_utf8_lossy(&output.stdout);
        for line in out_str.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 5 {
                let proto = cols[0].to_string();
                let local = cols[4];
                if let Some(idx) = local.rfind(':') {
                    details.ports.push(ListeningPort {
                        proto,
                        addr: local[..idx].to_string(),
                        port: local[idx + 1..].to_string(),
                    });
                }
            }
        }
    }

    if let Ok(output) = Command::new("nsenter")
        .arg(format!("--net={}", ns_path))
        .arg("--")
        .args(&["nft", "list", "ruleset"])
        .stderr(Stdio::null())
        .output()
    {
        let s = String::from_utf8_lossy(&output.stdout);
        let mut chains = 0;
        let mut rules = 0;
        for line in s.lines() {
            let l = line.trim();
            if l.starts_with("chain ") {
                chains += 1;
            }
            if l.contains(" counter ") || l.contains(" accept") || l.contains(" drop") {
                rules += 1;
            }
        }
        details.firewall = FirewallInfo { chains, rules };
    }

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(pid) = entry
                .file_name()
                .into_string()
                .unwrap_or_default()
                .parse::<u32>()
            {
                if let Ok(meta) = fs::metadata(format!("/proc/{}/ns/net", pid)) {
                    if meta.ino() == target_inode {
                        let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
                            .unwrap_or_default()
                            .trim()
                            .to_string();

                        let raw_cmdline =
                            fs::read(format!("/proc/{}/cmdline", pid)).unwrap_or_default();

                        let cmdline = String::from_utf8(raw_cmdline)
                            .unwrap_or_default()
                            .replace('\0', " ")
                            .trim()
                            .to_string();

                        let raw_env =
                            fs::read(format!("/proc/{}/environ", pid)).unwrap_or_default();
                        let env_string = String::from_utf8(raw_env).unwrap_or_default();

                        let env_vars: Vec<String> = env_string
                            .split('\0')
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect();

                        if !comm.is_empty() {
                            details.processes.push(ProcessInfo {
                                pid,
                                name: comm,
                                cmdline: cmdline,
                                env_vars,
                            });
                        }
                    }
                }
            }
        }
    }
    details.processes.sort_by_key(|p| p.pid);

    details
}

fn collect_host(map: &mut HashMap<u64, NetworkNamespace>) -> io::Result<()> {
    if let Ok(meta) = fs::metadata("/proc/1/ns/net") {
        let inode = meta.ino();
        map.insert(
            inode,
            NetworkNamespace {
                name: "Default (Host)".to_string(),
                ns_type: NamespaceType::Regular,
                inode,
                ns_path: "/proc/1/ns/net".to_string(),
                num_interfaces: count_ifaces("/proc/1/ns/net"),
                process_names: Vec::new(),
                primary_pid: Some(1),

                ip_prefixes: get_namespace_ips("/proc/1/ns/net"),
            },
        );
    }
    Ok(())
}

fn collect_named(map: &mut HashMap<u64, NetworkNamespace>) -> io::Result<()> {
    let path = Path::new("/var/run/netns");
    if !path.exists() {
        return Ok(());
    }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let name = entry.file_name().into_string().unwrap_or_default();
            let ns_path = format!("/var/run/netns/{}", name);
            if let Ok(meta) = fs::metadata(&ns_path) {
                map.entry(meta.ino()).or_insert_with(|| NetworkNamespace {
                    name: name.clone(),
                    ns_type: detect_type(&name),
                    inode: meta.ino(),
                    ns_path: ns_path.clone(),
                    num_interfaces: count_ifaces(&ns_path),
                    process_names: Vec::new(),
                    primary_pid: None,

                    ip_prefixes: get_namespace_ips(&ns_path),
                });
            }
        }
    }
    Ok(())
}

fn collect_docker(map: &mut HashMap<u64, NetworkNamespace>) -> io::Result<()> {
    let path = Path::new("/var/run/docker/netns");
    if !path.exists() {
        return Ok(());
    }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let fname = entry.file_name().into_string().unwrap_or_default();
            let ns_path = format!("/var/run/docker/netns/{}", fname);
            let display_name = format!("docker-sb-{}", &fname[..8.min(fname.len())]);
            if let Ok(meta) = fs::metadata(&ns_path) {
                map.entry(meta.ino()).or_insert_with(|| NetworkNamespace {
                    name: display_name,
                    ns_type: NamespaceType::Container,
                    inode: meta.ino(),
                    ns_path: ns_path.clone(),
                    num_interfaces: count_ifaces(&ns_path),
                    process_names: Vec::new(),
                    primary_pid: None,

                    ip_prefixes: get_namespace_ips(&ns_path),
                });
            }
        }
    }
    Ok(())
}

fn scan_processes(
    map: &mut HashMap<u64, NetworkNamespace>,
    docker_names: &HashMap<String, String>,
) -> io::Result<()> {
    let entries = fs::read_dir("/proc")?;
    for entry in entries.flatten() {
        if let Ok(pid) = entry
            .file_name()
            .into_string()
            .unwrap_or_default()
            .parse::<u32>()
        {
            let ns_path = format!("/proc/{}/ns/net", pid);
            if let Ok(meta) = fs::metadata(&ns_path) {
                let inode = meta.ino();
                let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                if comm.is_empty() {
                    continue;
                }

                let ns_entry = map.entry(inode).or_insert_with(|| NetworkNamespace {
                    name: format!("{}-{}", comm, pid),
                    ns_type: detect_type(&comm),
                    inode,
                    ns_path: ns_path.clone(),
                    num_interfaces: count_ifaces(&ns_path),
                    process_names: vec![],
                    primary_pid: Some(pid),

                    ip_prefixes: get_namespace_ips(&ns_path),
                });

                ns_entry.add_process(comm);
                if ns_entry.primary_pid.is_none() || pid < ns_entry.primary_pid.unwrap() {
                    ns_entry.primary_pid = Some(pid);
                }

                if let Some(cid) = get_container_id_from_pid(pid) {
                    let real_name = docker_names
                        .get(&cid)
                        .cloned()
                        .unwrap_or(format!("docker-{}", cid));

                    if ns_entry.ns_type == NamespaceType::Regular
                        || ns_entry.name.contains("docker-sb")
                    {
                        ns_entry.name = real_name;
                        ns_entry.ns_type = NamespaceType::Container;
                    } else if !ns_entry.name.contains(&real_name) {
                        ns_entry.name.push_str(&format!(", {}", real_name));
                    }
                }
            }
        }
    }
    Ok(())
}

fn detect_type(name: &str) -> NamespaceType {
    let l = name.to_lowercase();
    if l.contains("docker") || l.contains("container") {
        NamespaceType::Container
    } else if l.contains("vpn") || l.contains("tun") || l.contains("wireguard") {
        NamespaceType::Vpn
    } else {
        NamespaceType::Regular
    }
}

fn count_ifaces(ns_path: &str) -> usize {
    if ns_path.contains("/proc/1/") {
        return fs::read_dir("/sys/class/net")
            .map(|i| i.count())
            .unwrap_or(0);
    }
    if let Ok(o) = Command::new("nsenter")
        .arg(format!("--net={}", ns_path))
        .arg("--")
        .args(&["ip", "-o", "link"])
        .output()
    {
        String::from_utf8_lossy(&o.stdout).lines().count()
    } else {
        0
    }
}

fn get_docker_names() -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(out) = Command::new("docker")
        .args(&["ps", "--format", "{{.ID}}|{{.Names}}"])
        .output()
    {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some((id, name)) = line.split_once('|') {
                map.insert(id.to_string(), name.to_string());
            }
        }
    }
    map
}

fn get_container_id_from_pid(pid: u32) -> Option<String> {
    let content = fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;
    for line in content.lines() {
        if let Some(idx) = line.rfind("docker-") {
            let s = &line[idx + 7..];

            if let Some(end) = s.find(".scope") {
                return Some(s[..12.min(end)].to_string());
            }

            return Some(s[..12.min(s.len())].to_string());
        }

        if let Some(idx) = line.rfind("/docker/") {
            let s = &line[idx + 8..];
            return Some(s[..12.min(s.len())].to_string());
        }

        if let Some(idx) = line.rfind("docker/") {
            let s = &line[idx + 7..];
            return Some(s[..12.min(s.len())].to_string());
        }
    }
    None
}

fn get_namespace_ips(ns_path: &str) -> Vec<String> {
    let mut ips = Vec::new();

    if let Ok(output) = Command::new("nsenter")
        .arg(format!("--net={}", ns_path))
        .arg("--")
        .args(&["ip", "-j", "addr", "show"])
        .stderr(Stdio::null())
        .output()
    {
        if let Ok(json) = serde_json::from_slice::<Vec<IpAddrJson>>(&output.stdout) {
            for iface in json {
                if iface.ifname == "lo" {
                    continue;
                }

                for addr in iface.addr_info {
                    if addr.family == "inet" {
                        ips.push(format!("{}/{}", addr.local, addr.prefixlen));
                    }
                }
            }
        }
    }
    ips
}
