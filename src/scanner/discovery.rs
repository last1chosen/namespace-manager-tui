//! # Discovery Module
//!
//! Orchestrates the identification of network namespaces across the system
//! using multiple discovery strategies and the security validator.

use std::collections::HashMap;
use std::path::Path;

use tracing::debug;

use crate::models::{NamespaceType, NetworkNamespace};
use crate::scanner::host::Host;
use crate::scanner::security::validate_ns_path; // <--- Import the security guard
use crate::scanner::utilities::detect_type;
use crate::scanner::{DOCKER_ID_LEN, Inode, MAX_PROC_SCAN_DEPTH, NsResult, Pid};

/// Strategy 1: Identify the Host System (PID 1) namespace.
pub(super) fn collect_host_namespace(
    map: &mut HashMap<Inode, NetworkNamespace>,
    host: &impl Host,
) -> NsResult<()> {
    let path_str = "/proc/1/ns/net";

    // We validate PID 1 for consistency, though it's the most "trusted" path.
    if let Ok(validated_path) = validate_ns_path(path_str, host) {
        if let Ok(meta) = host.metadata(&validated_path) {
            let inode = Inode(meta.inode);
            map.entry(inode).or_insert_with(|| NetworkNamespace {
                name: "Host System".into(),
                ns_type: NamespaceType::Regular,
                inode: inode.0,
                ns_path: validated_path.to_string_lossy().into(),
                num_interfaces: 0,
                process_names: vec![],
                primary_pid: Some(1),
                ip_prefixes: vec![],
            });
        }
    }

    Ok(())
}

/// Strategy 2: Scan for named/persistent namespaces (e.g., ip netns add).
///
/// HIGH RISK ZONE: This scans standard directories like /run/netns which are
/// backed by physical filesystems, making them vulnerable to symlink attacks.
pub(super) fn collect_named_namespaces(
    map: &mut HashMap<Inode, NetworkNamespace>,
    host: &impl Host,
) -> NsResult<()> {
    let search_paths = ["/run/netns", "/var/run/netns", "/run/podman/netns"];

    for base in search_paths {
        let base_path = Path::new(base);
        let Ok(entries) = host.read_dir(base_path) else {
            // Silently skip if directory doesn't exist (common for podman)
            continue;
        };

        for entry_path in entries {
            let path_str = entry_path.to_string_lossy();

            // 1. SECURITY GATE: DNA Validate the path first.
            // This prevents the scanner from following a symlink to /etc/shadow
            // or processing a regular file created by a malicious user.
            let validated_path = match validate_ns_path(&path_str, host) {
                Ok(p) => p,
                Err(e) => {
                    debug!("Skipping invalid namespace handle at {}: {}", path_str, e);
                    continue;
                }
            };

            // 2. METADATA: Now that the path is vetted as a real NS handle,
            // fetch the Inode from the kernel.
            if let Ok(meta) = host.metadata(&validated_path) {
                let inode = Inode(meta.inode);

                // Extract the name (e.g., "vpn-net") from the filename
                let name = entry_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                // 3. MAP CHECK: Only add if we haven't found this namespace elsewhere
                map.entry(inode).or_insert_with(|| NetworkNamespace {
                    name,
                    ns_type: NamespaceType::Regular,
                    inode: inode.0,
                    // Use the canonicalized path from our security check
                    ns_path: validated_path.to_string_lossy().into(),
                    num_interfaces: 0,
                    process_names: vec![],
                    primary_pid: None,
                    ip_prefixes: vec![],
                });
            }
        }
    }
    Ok(())
}
/// Strategy 3: Walk /proc to find namespaces owned by active processes.
///
/// SECURITY PATTERN: Validate -> Metadata -> Map.
/// We only trust the Inode once the kernel verifies the path is a real namespace handle.
pub(super) fn scan_proc_for_namespaces(
    map: &mut HashMap<Inode, NetworkNamespace>,
    docker_names: &HashMap<String, String>,
    host: &impl Host,
) -> NsResult<()> {
    // 1. Get all entries in /proc
    let entries = host.read_dir(Path::new("/proc"))?;

    for entry_path in entries.iter().take(MAX_PROC_SCAN_DEPTH) {
        // Extract PID from directory name
        let Some(pid_s) = entry_path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(pid_val) = pid_s.parse::<u32>() else {
            continue;
        };

        let ns_link = entry_path.join("ns/net");
        let ns_path_str = ns_link.to_string_lossy();

        // 2. SECURITY GATE: DNA Validate the path first
        // We do this BEFORE metadata to ensure we aren't chasing a symlink attack
        // or a regular file masquerading as a namespace.
        let validated_path = match validate_ns_path(&ns_path_str, host) {
            Ok(p) => p,
            Err(_) => continue, // If the handle is fake or invalid, skip this PID
        };

        // 3. METADATA: Now that the path is vetted, get the actual Inode from the kernel
        let Ok(meta) = host.metadata(&validated_path) else {
            continue;
        };
        let inode = Inode(meta.inode);

        // 4. MAP CHECK: If we've already processed this namespace, just update the process list
        let comm = host
            .read_to_string(&entry_path.join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();

        if comm.is_empty() {
            continue;
        }

        let ns_entry = map.entry(inode).or_insert_with(|| NetworkNamespace {
            name: format!("{}-{}", comm, pid_val),
            ns_type: detect_type(&comm),
            inode: inode.0,
            // We store the validated path to ensure fetch_details uses the vetted handle
            ns_path: validated_path.to_string_lossy().into(),
            num_interfaces: 0,
            process_names: vec![],
            primary_pid: Some(pid_val),
            ip_prefixes: vec![],
        });

        // Add this process to the list of participants in this namespace
        ns_entry.process_names.push(comm.clone());

        // 5. CONTAINER RESOLUTION: Check if this PID belongs to a Docker/Containerd container
        if let Some(cid) = get_container_id_from_cgroups(Pid(pid_val), host) {
            if let Some(real_name) = docker_names.get(&cid) {
                // If we found a container name, prioritize it as the namespace name
                ns_entry.name = real_name.clone();
                ns_entry.ns_type = NamespaceType::Container;
            }
        }
    }

    Ok(())
}
/// Helper: Extracts container IDs from proc cgroup entries.
fn get_container_id_from_cgroups(pid: Pid, host: &impl Host) -> Option<String> {
    let cgroup_path = Path::new("/proc").join(pid.0.to_string()).join("cgroup");
    let content = host.read_to_string(&cgroup_path).ok()?;

    for line in content.lines() {
        if line.contains("docker") || line.contains("containerd") {
            let id = line.split('/').last()?;
            let clean_id = id
                .strip_prefix("docker-")
                .and_then(|s| s.strip_suffix(".scope"))
                .unwrap_or(id);

            if clean_id.len() >= DOCKER_ID_LEN {
                return Some(clean_id[..DOCKER_ID_LEN].to_string());
            }
        }
    }
    None
}
