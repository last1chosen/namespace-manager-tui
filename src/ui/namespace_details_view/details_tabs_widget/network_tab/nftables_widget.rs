use ratatui::widgets::{Block, Borders, Paragraph};

use crate::models::FirewallInfo;

pub fn make_nftables_widget(firewall: &FirewallInfo) -> Paragraph<'_> {
    let fw_text = format!(
        "Chains: {}   |   Rules: {}",
        firewall.chains, firewall.rules
    );
    Paragraph::new(fw_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title("NFTables Configuration"),
    )
}

#[cfg(test)]
mod tests {
    use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};

    use super::*;

    #[test]
    fn test_make_nftables_widget() {
        let firewall_data = FirewallInfo {
            chains: 10,
            rules: 5,
        };

        let nftable = make_nftables_widget(&firewall_data);

        let mut buf = Buffer::empty(Rect::new(0, 0, 30, 4));
        Widget::render(nftable, *buf.area(), &mut buf);

        let expected = Buffer::with_lines(vec![
            "┌NFTables Configuration──────┐",
            "│Chains: 10   |   Rules: 5   │",
            "│                            │",
            "└────────────────────────────┘",
        ]);

        assert_eq!(buf, expected);
    }
}
