use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::models::NamespaceDetail;

pub fn make_subnet_peers<'a>(info: &NamespaceDetail) -> Paragraph<'a> {
    let peers = &info.peers;

    let peers_title = format!("Subnet Peers ({})", peers.len());
    let peers_text = if peers.is_empty() {
        if info.interfaces.iter().all(|i| i.ip == "N/A") {
            "No IP address assigned.".to_string()
        } else {
            "No peers found in same subnet.".to_string()
        }
    } else {
        peers
            .iter()
            .map(|p| p.name.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };

    Paragraph::new(peers_text)
        .block(Block::default().borders(Borders::ALL).title(peers_title))
        .wrap(Wrap { trim: true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{InterfaceInfo, PeerInfo};
    use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};

    fn create_mock_details(peers: Vec<(&str, &str)>, has_ips: bool) -> NamespaceDetail {
        let mut details = NamespaceDetail::default();

        if has_ips {
            details.interfaces.push(InterfaceInfo {
                name: "eth0".into(),
                ip: "192.168.1.10/24".into(),
                ..Default::default()
            });
        }

        for (name, ip) in peers {
            details.peers.push(PeerInfo {
                name: name.to_string(),
                _ip: ip.to_string(),
                _inode: 12345,
            });
        }

        details
    }

    #[test]
    fn test_make_subnet_peers_with_matches() {
        let info = create_mock_details(
            vec![("peer_1", "192.168.1.20"), ("peer_3", "192.168.1.50")],
            true,
        );

        let widget = make_subnet_peers(&info);

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
        let info = create_mock_details(vec![], true);

        let widget = make_subnet_peers(&info);

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
        // No interfaces with IPs, and no peers
        let info = create_mock_details(vec![], false);

        let widget = make_subnet_peers(&info);

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
}
