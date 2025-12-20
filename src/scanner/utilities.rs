use std::{collections::HashMap, fs, os::unix::fs::MetadataExt};

use crate::{
    models::{NamespaceType, NetworkNamespace},
    scanner::{DOCKER_ID_LEN, Inode, NsResult, Pid},
};

pub(super) fn get_network_id(cidr: &str) -> Option<String> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let prefix: u32 = prefix_str.parse().ok()?;

    // Parse IP string into u8 array
    let mut octets = [0u8; 4];
    for (i, s) in ip_str.split('.').enumerate() {
        if i >= 4 {
            return None;
        }
        octets[i] = s.parse().ok()?;
    }

    let ip_u32 = u32::from_be_bytes(octets);

    // Calculate mask safely
    // If prefix is 0, mask should be 0. If 32, mask should be all 1s.
    let mask = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix)
    };

    let network = ip_u32 & mask;
    let n = network.to_be_bytes();

    Some(format!("{}.{}.{}.{}/{}", n[0], n[1], n[2], n[3], prefix))
}

pub(super) fn redact_env_var(kv: &str) -> String {
    if let Some((key, _)) = kv.split_once('=') {
        let sensitive = [
            "KEY", "PASS", "SECRET", "TOKEN", "AUTH", "CRED", "PRIVATE", "CERT", "AWS",
        ];
        if sensitive
            .iter()
            .any(|&word| key.to_uppercase().contains(word))
        {
            return format!("{}=********", key);
        }
    }
    kv.to_string()
}

pub(super) fn detect_type(name: &str) -> NamespaceType {
    let l = name.to_lowercase();
    if l.contains("docker") || l.contains("container") || l.contains("k8s") {
        NamespaceType::Container
    } else if l.contains("vpn") || l.contains("wg") {
        NamespaceType::Vpn
    } else {
        NamespaceType::Regular
    }
}

pub(super) fn collect_host(map: &mut HashMap<Inode, NetworkNamespace>) -> NsResult<()> {
    let path = "/proc/1/ns/net";
    if let Ok(meta) = fs::metadata(path) {
        let inode = Inode(meta.ino());
        map.insert(
            inode,
            NetworkNamespace {
                name: "Host System".into(),
                ns_type: NamespaceType::Regular,
                inode: inode.0,
                ns_path: path.into(),
                num_interfaces: 0,
                process_names: vec![],
                primary_pid: Some(1),
                ip_prefixes: vec![],
            },
        );
    }
    Ok(())
}

pub(super) fn collect_named(map: &mut HashMap<Inode, NetworkNamespace>) -> NsResult<()> {
    for base in ["/run/netns", "/var/run/netns", "/run/podman/netns"] {
        if let Ok(entries) = fs::read_dir(base) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let path = format!("{}/{}", base, name);
                if let Ok(meta) = fs::metadata(&path) {
                    map.entry(Inode(meta.ino()))
                        .or_insert_with(|| NetworkNamespace {
                            name,
                            ns_type: NamespaceType::Regular,
                            inode: meta.ino(),
                            ns_path: path,
                            num_interfaces: 0,
                            process_names: vec![],
                            primary_pid: None,
                            ip_prefixes: vec![],
                        });
                }
            }
        }
    }
    Ok(())
}

pub(super) fn get_container_id_from_pid(pid: Pid) -> Option<String> {
    let content = fs::read_to_string(format!("/proc/{}/cgroup", pid.0)).ok()?;
    for line in content.lines() {
        if line.contains("docker") || line.contains("containerd") {
            if let Some(id) = line.split('/').last() {
                let clean_id = id
                    .strip_prefix("docker-")
                    .and_then(|s| s.strip_suffix(".scope"))
                    .unwrap_or(id);
                if clean_id.len() >= DOCKER_ID_LEN {
                    return Some(clean_id[..DOCKER_ID_LEN].to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[test]
    fn test_get_network_id_sub_octet_boundaries() {
        let net_a = get_network_id("192.168.1.10/25");
        let net_b = get_network_id("192.168.1.130/25");

        assert_eq!(net_a, Some("192.168.1.0/25".to_string()));
        assert_eq!(net_b, Some("192.168.1.128/25".to_string()));

        assert_ne!(net_a, net_b);
    }

    #[test]
    fn test_get_network_id_edge_cases() {
        assert_eq!(
            get_network_id("10.0.0.1/32"),
            Some("10.0.0.1/32".to_string())
        );

        assert_eq!(get_network_id("1.2.3.4/0"), Some("0.0.0.0/0".to_string()));

        assert_eq!(
            get_network_id("10.254.1.1/8"),
            Some("10.0.0.0/8".to_string())
        );
    }

    #[test]
    fn test_get_network_id_complex_masks() {
        assert_eq!(
            get_network_id("192.168.1.7/29"),
            Some("192.168.1.0/29".to_string())
        );
        assert_eq!(
            get_network_id("192.168.1.9/29"),
            Some("192.168.1.8/29".to_string())
        );
    }

    #[rstest]
    #[case::system("system=foo", "system=foo")]
    #[case::auth_token("auth_token=bar", "auth_token=********")]
    #[case::key("key=123", "key=********")]
    #[case::aws_secret_token("aws_secret_token=foobar", "aws_secret_token=********")]
    #[case::random_value("random_value=something", "random_value=something")]
    #[case::private_auth("private_AUTH=hidden", "private_AUTH=********")]
    fn test_redact_env_var(#[case] kv: &str, #[case] expected: String) {
        let redaction_output = redact_env_var(kv);
        assert_eq!(redaction_output, expected)
    }

    #[rstest]
    #[case::docker("docker-12345", NamespaceType::Container)]
    #[case::vpn("vpn-123", NamespaceType::Vpn)]
    #[case::random("something-random", NamespaceType::Regular)]
    #[case::container("12container345", NamespaceType::Container)]
    fn test_detect_type(#[case] name: &str, #[case] expected: NamespaceType) {
        let detected_type = detect_type(name);
        assert_eq!(detected_type, expected);
    }
}
