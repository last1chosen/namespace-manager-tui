// use std::path::Path;
// use std::{collections::HashMap, os::fd::AsRawFd};

// use tracing::debug;

// use crate::{
//     models::{NamespaceType, NetworkNamespace},
//     scanner::{DOCKER_ID_LEN, Inode, NsError, NsResult, Pid, error, host::Host},
// };

// /// COLLECT HOST:
// /// Refactored to use the Host abstraction.
// /// We can now test this by mocking a failure on /proc/1/ns/net.
// pub(super) fn collect_host(
//     map: &mut HashMap<Inode, NetworkNamespace>,
//     _host: &impl Host,
// ) -> NsResult<()> {
//     let path = Path::new("/proc/1/ns/net");

//     // Use the verification function to get the validated Inode and file handle
//     if let Ok((inode_val, _ns_file)) = verify_and_lock_ns(path) {
//         let inode = Inode(inode_val);
//         map.insert(
//             inode,
//             NetworkNamespace {
//                 name: "Host System".into(),
//                 ns_type: NamespaceType::Regular,
//                 inode: inode.0,
//                 ns_path: path.to_string_lossy().into(),
//                 num_interfaces: 0,
//                 process_names: vec![],
//                 primary_pid: Some(1),
//                 ip_prefixes: vec![],
//             },
//         );
//     }

//     Ok(())
// }
// /// COLLECT NAMED:
// /// Scans standard Linux locations for persistent (bind-mounted) namespaces.
// pub(super) fn collect_named(
//     map: &mut HashMap<Inode, NetworkNamespace>,
//     host: &impl Host,
// ) -> NsResult<()> {
//     let search_paths = ["/run/netns", "/var/run/netns", "/run/podman/netns"];

//     for base in search_paths {
//         let base_path = Path::new(base);
//         // host.read_dir() allows us to "fake" these directories in tests
//         if let Ok(entries) = host.read_dir(base_path) {
//             for entry_path in entries {
//                 if let Some(name) = entry_path.file_name().and_then(|n| n.to_str()) {
//                     if let Ok(inode_val) = host.metadata(&entry_path) {
//                         map.entry(Inode(inode_val))
//                             .or_insert_with(|| NetworkNamespace {
//                                 name: name.to_string(),
//                                 ns_type: NamespaceType::Regular,
//                                 inode: inode_val,
//                                 ns_path: entry_path.to_string_lossy().into(),
//                                 num_interfaces: 0,
//                                 process_names: vec![],
//                                 primary_pid: None,
//                                 ip_prefixes: vec![],
//                             });
//                     }
//                 }
//             }
//         }
//     }
//     Ok(())
// }

// /// Helper to extract Docker Container IDs from cgroups.
// /// Now uses the host.read_to_string abstraction.
// pub(super) fn get_container_id_from_pid(pid: Pid, host: &impl Host) -> Option<String> {
//     let cgroup_path = Path::new("/proc").join(pid.0.to_string()).join("cgroup");

//     let content = host.read_to_string(&cgroup_path).ok()?;
//     for line in content.lines() {
//         if line.contains("docker") || line.contains("containerd") {
//             if let Some(id) = line.split('/').last() {
//                 let clean_id = id
//                     .strip_prefix("docker-")
//                     .and_then(|s| s.strip_suffix(".scope"))
//                     .unwrap_or(id);

//                 if clean_id.len() >= DOCKER_ID_LEN {
//                     return Some(clean_id[..DOCKER_ID_LEN].to_string());
//                 }
//             }
//         }
//     }
//     None
// }

// // --- PURE LOGIC FUNCTIONS ---
// // These don't need the Host because they don't have side effects.
// // They stay global and easy to unit test as they were.

// pub(super) fn get_network_id(cidr: &str) -> Option<String> {
//     let (ip_str, prefix_str) = cidr.split_once('/')?;
//     let prefix: u32 = prefix_str.parse().ok()?;

//     let mut octets = [0u8; 4];
//     for (i, s) in ip_str.split('.').enumerate() {
//         if i >= 4 {
//             return None;
//         }
//         octets[i] = s.parse().ok()?;
//     }

//     let ip_u32 = u32::from_be_bytes(octets);
//     let mask = if prefix == 0 {
//         0u32
//     } else {
//         u32::MAX << (32 - prefix)
//     };
//     let n = (ip_u32 & mask).to_be_bytes();

//     Some(format!("{}.{}.{}.{}/{}", n[0], n[1], n[2], n[3], prefix))
// }

// use std::fs::{self, File};
// use std::os::unix::fs::MetadataExt;

// pub fn verify_and_lock_ns(path: &Path) -> NsResult<(u64, File)> {
//     // 1. PIN the resource
//     let file = File::open(path)?;
//     let meta = file.metadata().map_err(|e| {
//         debug!("Failed to open potential NS link {:?}: {}", path, e);
//         NsError::IoWithPath {
//             source: e,
//             path: path.to_path_buf(),
//         }
//     })?;

//     if meta.len() != 0 {
//         return Err(NsError::InsecureBinary(format!(
//             "Namespace target {:?} has invalid size",
//             path
//         )));
//     }

//     // 2. VERIFY identity via the handle (the "trick") (using /proc/self/fd to avoid TOCTOU)
//     let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
//     let target = fs::read_link(fd_path)?;

//     // 3. DNA CROSS-CHECK
//     let inode_val = parse_ns_inode(&target.to_string_lossy())?;
//     if meta.ino() != inode_val {
//         error!(
//             "INODE MISMATCH: Link text says {}, but kernel fstat says {}",
//             inode_val,
//             meta.ino()
//         );
//         return Err(NsError::InsecureBinary("Handle identity mismatch".into()));
//     }

//     Ok((inode_val, file))
// }

//! # Utilities Module
//!
//! Provides side-effect-free logic for data transformation, network
//! calculations, and security redaction.

use crate::models::NamespaceType;
use crate::scanner::{NsError, NsResult};
use std::net::Ipv4Addr;

/// Extracts a network identifier from a CIDR string.
/// Example: "192.168.1.50/24" -> "192.168.1.0/24"

pub(super) fn get_network_id(cidr: &str) -> NsResult<String> {
    // 1. Split and validate structure
    let (ip_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| NsError::ParseError(format!("Malformed CIDR: {}", cidr)))?;

    // 2. Parse Prefix (0-32)
    let prefix: u32 = prefix_str
        .parse()
        .map_err(|_| NsError::ParseError(format!("Invalid prefix: {}", prefix_str)))?;

    if prefix > 32 {
        return Err(NsError::ParseError(format!(
            "Prefix out of bounds (0-32): {}",
            prefix
        )));
    }

    // 3. Parse IP using Standard Library (handles octet validation 0-255)
    let ip: Ipv4Addr = ip_str
        .parse()
        .map_err(|e| NsError::ParseError(format!("Invalid IP '{}': {}", ip_str, e)))?;

    let ip_u32 = u32::from(ip);

    // 4. Safe Mask Calculation
    let mask = if prefix == 0 {
        0u32
    } else {
        // Use checked_shl if you want to be extremely pedantic,
        // but prefix <= 32 check above makes this safe.
        u32::MAX.checked_shl(32 - prefix).unwrap_or(0)
    };

    let network_u32 = ip_u32 & mask;
    let network_ip = Ipv4Addr::from(network_u32);

    Ok(format!("{}/{}", network_ip, prefix))
}

/// Redacts sensitive information from environment variable strings.
/// Prevents leaking secrets into the TUI display.
pub(super) fn redact_env_var(kv: &str) -> String {
    let Some((key, _)) = kv.split_once('=') else {
        return kv.to_string();
    };

    const SENSITIVE_KEYWORDS: &[&str] = &[
        "KEY", "PASS", "SECRET", "TOKEN", "AUTH", "CRED", "PRIVATE", "CERT", "AWS", "API",
    ];

    let upper_key = key.to_uppercase();
    if SENSITIVE_KEYWORDS
        .iter()
        .any(|&word| upper_key.contains(word))
    {
        return format!("{}=********", key);
    }

    kv.to_string()
}

/// Heuristic-based detection of namespace purpose based on the
/// primary process name or container metadata.
pub(super) fn detect_type(name: &str) -> NamespaceType {
    let l = name.to_lowercase();
    if l.contains("docker") || l.contains("container") || l.contains("k8s") || l.contains("pod") {
        NamespaceType::Container
    } else if l.contains("vpn") || l.contains("wg") || l.contains("tun") {
        NamespaceType::Vpn
    } else {
        NamespaceType::Regular
    }
}

/// Helper to parse Inode strings like "net:[4026531905]"
pub(super) fn parse_ns_inode(s: &str) -> Option<u64> {
    let start = s.find('[')?;
    let end = s.find(']')?;
    s.get(start + 1..end)?.parse::<u64>().ok()
}

// fn parse_ns_inode(s: &str) -> NsResult<u64> {
//     // Expects "net:[12345]"
//     let start = s
//         .find('[')
//         .ok_or_else(|| NsError::InvalidPath("Malformed NS string".into()))?;
//     let end = s
//         .find(']')
//         .ok_or_else(|| NsError::InvalidPath("Malformed NS string".into()))?;
//     s[start + 1..end]
//         .parse::<u64>()
//         .map_err(|_| NsError::InvalidPath("Invalid Inode".into()))
// }

mod tests {

    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::edge("10.0.0.1/32", "10.0.0.1/32")]
    #[case::edge("1.2.3.4/0", "0.0.0.0/0")]
    #[case::edge("10.254.1.1/8", "10.0.0.0/8")]
    #[case::edge("10.0.0.1/32", "10.0.0.1/32")]
    #[case::complex("192.168.1.7/29", "192.168.1.0/29")]
    #[case::complex("192.168.1.9/29", "192.168.1.8/29")]
    #[case::complex("192.168.1.9/29", "192.168.1.8/29")]
    fn test_get_network_id(#[case] cidr: &str, #[case] expected: String) {
        use crate::scanner::get_network_id;

        let network_id = get_network_id(cidr).expect("did not parse");
        assert_eq!(network_id, expected)
    }

    #[test]
    fn test_get_network_id_sub_octet_boundaries() {
        let net_a = get_network_id("192.168.1.10/25").expect("Should parse");
        let net_b = get_network_id("192.168.1.130/25").expect("Should parse");

        assert_eq!(net_a, "192.168.1.0/25".to_string());
        assert_eq!(net_b, "192.168.1.128/25".to_string());

        assert_ne!(net_a, net_b);
    }

    #[rstest]
    #[case::no_slash("192.168.1.1", "Malformed CIDR")]
    #[case::bad_prefix("192.168.1.1/xx", "Invalid prefix")]
    #[case::too_high("192.168.1.1/33", "out of bounds")]
    #[case::bad_ip("256.256.256.256/24", "Invalid IP")]
    fn test_get_network_id_validation_failures(#[case] input: &str, #[case] expected_msg: &str) {
        use crate::scanner::get_network_id;

        let result = get_network_id(input);

        match result {
            Err(NsError::ParseError(msg)) => {
                assert!(
                    msg.contains(expected_msg),
                    "Error message '{}' did not contain '{}'",
                    msg,
                    expected_msg
                );
            }
            Err(_) => {}
            Ok(_) => panic!("Input '{}' should have failed but passed", input),
        }
    }

    #[rstest]
    #[case::system("system=foo", "system=foo")]
    #[case::auth_token("auth_token=bar", "auth_token=********")]
    #[case::key("key=123", "key=********")]
    #[case::aws_secret_token("aws_secret_token=foobar", "aws_secret_token=********")]
    #[case::random_value("random_value=something", "random_value=something")]
    #[case::private_auth("private_AUTH=hidden", "private_AUTH=********")]
    fn test_redact_env_var(#[case] kv: &str, #[case] expected: String) {
        use crate::scanner::utilities::redact_env_var;

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

    #[rstest]
    #[case::return_net_inode("net:[12343]", Some(12343_u64))]
    #[case::no_open_bracket("nothing_here]", None)]
    #[case::no_closing_bracket("[_no_end_bracket", None)]
    #[case::return_user_inode("user:[123]", Some(123))]
    fn test_parse_ns_inode(#[case] s: &str, #[case] expected: Option<u64>) {
        let namespace_inode = parse_ns_inode(s);
        assert_eq!(namespace_inode, expected)
    }
}
