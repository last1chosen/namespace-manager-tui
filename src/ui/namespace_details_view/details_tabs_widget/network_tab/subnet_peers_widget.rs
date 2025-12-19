use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::models::NetworkNamespace;

pub fn make_subnet_peers<'a>(
    selected_network_namespace: &'a NetworkNamespace,
    all_network_namespaces: &'a [NetworkNamespace],
) -> Paragraph<'a> {
    let namespace_ip_prefixes = &selected_network_namespace.ip_prefixes;
    let namespace_inode = selected_network_namespace.inode;
    let my_networks: Vec<String> = namespace_ip_prefixes
        .iter()
        .filter_map(|cidr| get_network_id(cidr))
        .collect();

    let mut peer_names = Vec::new();
    if !my_networks.is_empty() {
        for ns in all_network_namespaces {
            if ns.inode == namespace_inode {
                continue;
            }

            for other_cidr in &ns.ip_prefixes {
                if let Some(other_net) = get_network_id(other_cidr) {
                    if my_networks.contains(&other_net) {
                        peer_names.push(ns.name.clone());
                        break;
                    }
                }
            }
        }
    }

    let peers_title = format!("Subnet Peers ({})", peer_names.len());
    let peers_text = if peer_names.is_empty() {
        if my_networks.is_empty() {
            "No IP address assigned.".to_string()
        } else {
            "No peers found in same subnet.".to_string()
        }
    } else {
        peer_names.join(", ")
    };

    Paragraph::new(peers_text)
        .block(Block::default().borders(Borders::ALL).title(peers_title))
        .wrap(Wrap { trim: true })
}

fn get_network_id(cidr: &str) -> Option<String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip = parts[0];
    let prefix: usize = parts[1].parse().ok()?;

    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 {
        return None;
    }

    let relevant_octets = (prefix as f32 / 8.0).ceil() as usize;
    let count = relevant_octets.clamp(1, 4);

    Some(octets[0..count].join("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};

    use crate::models::NetworkNamespace;

    fn create_ns(inode: u64, name: &str, ip_prefixes: Vec<&str>) -> NetworkNamespace {
        NetworkNamespace {
            inode,
            name: name.to_string(),
            ip_prefixes: ip_prefixes.iter().map(|s| s.to_string()).collect(),

            ns_type: crate::models::NamespaceType::Container,
            ns_path: String::new(),
            primary_pid: None,
            num_interfaces: 5,
            process_names: vec![],
        }
    }

    #[test]
    fn test_make_subnet_peers_with_matches() {
        let selected = create_ns(1, "current_ns", vec!["192.168.1.10/24"]);

        let all_namespaces = vec![
            create_ns(1, "current_ns", vec!["192.168.1.10/24"]),
            create_ns(2, "peer_1", vec!["192.168.1.20/24"]),
            create_ns(3, "peer_2", vec!["10.0.0.5/8"]),
            create_ns(4, "peer_3", vec!["192.168.1.50/24"]),
        ];

        let widget = make_subnet_peers(&selected, &all_namespaces);

        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 5));
        Widget::render(widget, *buf.area(), &mut buf);

        let expected = Buffer::with_lines(vec![
            "┌Subnet Peers (2)──────────────────────────────────────────────────────────────┐",
            "│peer_1, peer_3                                                                │",
            "│                                                                              │",
            "│                                                                              │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
        ]);

        assert_eq!(buf, expected);
    }

    #[test]
    fn test_make_subnet_peers_no_matches() {
        let selected = create_ns(1, "current_ns", vec!["10.0.0.1/8"]);

        let all_namespaces = vec![
            create_ns(1, "current_ns", vec!["10.0.0.1/8"]),
            create_ns(2, "other_ns", vec!["192.168.1.1/24"]),
        ];

        let widget = make_subnet_peers(&selected, &all_namespaces);

        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 5));
        Widget::render(widget, *buf.area(), &mut buf);

        let expected = Buffer::with_lines(vec![
            "┌Subnet Peers (0)──────────────────────────────────────────────────────────────┐",
            "│No peers found in same subnet.                                                │",
            "│                                                                              │",
            "│                                                                              │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
        ]);

        assert_eq!(buf, expected);
    }

    #[test]
    fn test_make_subnet_peers_no_ip_assigned() {
        let selected = create_ns(1, "current_ns", vec![]);

        let all_namespaces = vec![
            create_ns(1, "current_ns", vec![]),
            create_ns(2, "peer_1", vec!["192.168.1.1/24"]),
        ];

        let widget = make_subnet_peers(&selected, &all_namespaces);

        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 5));
        Widget::render(widget, *buf.area(), &mut buf);

        let expected = Buffer::with_lines(vec![
            "┌Subnet Peers (0)──────────────────────────────────────────────────────────────┐",
            "│No IP address assigned.                                                       │",
            "│                                                                              │",
            "│                                                                              │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
        ]);

        assert_eq!(buf, expected);
    }

    #[test]
    fn test_get_network_id_standard_prefixes() {
        assert_eq!(
            get_network_id("192.168.1.10/24"),
            Some("192.168.1".to_string())
        );

        assert_eq!(get_network_id("172.16.0.5/16"), Some("172.16".to_string()));
        assert_eq!(get_network_id("10.5.2.1/8"), Some("10".to_string()));

        assert_eq!(get_network_id("8.8.8.8/32"), Some("8.8.8.8".to_string()));
    }

    #[test]
    fn test_get_network_id_boundary_prefixes() {
        assert_eq!(get_network_id("10.200.5.1/9"), Some("10.200".to_string()));
        assert_eq!(
            get_network_id("192.168.50.5/23"),
            Some("192.168.50".to_string())
        );

        assert_eq!(get_network_id("128.0.0.1/1"), Some("128".to_string()));
    }

    #[test]
    fn test_get_network_id_invalid_inputs() {
        assert_eq!(get_network_id("192.168.1.1"), None);
        assert_eq!(get_network_id("192.168.1.1/abc"), None);
        assert_eq!(get_network_id("192.168/24"), None);
        assert_eq!(get_network_id("192.168.1.1.5/24"), None);
        assert_eq!(get_network_id(""), None);
    }
}
