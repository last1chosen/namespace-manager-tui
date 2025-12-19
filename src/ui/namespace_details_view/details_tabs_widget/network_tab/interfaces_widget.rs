use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table},
};

use crate::models::{DetailSection, InterfaceInfo};

pub fn make_interfaces_widget(
    interfaces: &[InterfaceInfo],
    focused_state: DetailSection,
) -> Table<'_> {
    let iface_title = format!("Network Interfaces ({})", interfaces.len());
    let iface_rows = interfaces.iter().map(|i| {
        let state_color = if i.state == "UP" || i.state == "UNKNOWN" {
            Color::Green
        } else {
            Color::Red
        };
        Row::new(vec![
            Cell::from(i.name.as_str()).style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from(i.ip.as_str()),
            Cell::from(i.state.as_str()).style(Style::default().fg(state_color)),
            Cell::from(i.mtu.to_string()).style(Style::default().fg(state_color)),
            Cell::from(format!("RX: {:.1} MB", i.rx_bytes as f64 / 1_000_000.0)),
            Cell::from(format!("TX: {:.1} MB", i.tx_bytes as f64 / 1_000_000.0)),
        ])
    });

    let is_focused = focused_state == DetailSection::Interfaces;
    let (border_color, highlight_style) = if is_focused {
        (Color::Magenta, Style::default().bg(Color::DarkGray))
    } else {
        (Color::default(), Style::default())
    };

    Table::new(
        iface_rows,
        [
            Constraint::Percentage(15),
            Constraint::Percentage(30),
            Constraint::Percentage(10),
            Constraint::Percentage(10),
            Constraint::Percentage(17),
            Constraint::Percentage(18),
        ],
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(iface_title)
            .border_style(Style::default().fg(border_color)),
    )
    .header(
        Row::new(vec!["Name", "IP", "State", "MTU", "RX", "TX"])
            .style(Style::default().fg(Color::Yellow)),
    )
    .row_highlight_style(highlight_style)
}

#[cfg(test)]
mod tests {
    use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};

    use super::*;

    #[test]
    fn test_make_interfaces_widget_not_focused() {
        let interfaces = vec![
            InterfaceInfo {
                name: "interface_1".to_string(),
                ip: "ip_1".to_string(),
                state: "UP".to_string(),
                mtu: 12345,
                rx_bytes: 100,
                tx_bytes: 65000,
            },
            InterfaceInfo {
                name: "interface_2".to_string(),
                ip: "ip_2".to_string(),
                state: "DOWN".to_string(),
                mtu: 54321,
                rx_bytes: 1000,
                tx_bytes: 65000,
            },
        ];

        let nftable = make_interfaces_widget(&interfaces, DetailSection::Ports);

        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 5));
        Widget::render(nftable, *buf.area(), &mut buf);

        let mut expected = Buffer::with_lines(vec![
            "┌Network Interfaces (2)────────────────────────────────────────────────────────┐",
            "│Name         IP                 State    MTU      RX            TX            │",
            "│interface_1  ip_1               UP       12345    RX: 0.0 MB    TX: 0.1 MB    │",
            "│interface_2  ip_2               DOWN     54321    RX: 0.0 MB    TX: 0.1 MB    │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
        ]);
        expected.set_style(Rect::new(1, 1, 78, 1), Style::default().fg(Color::Yellow));
        expected.set_style(
            Rect::new(1, 2, 12, 1),
            Style::default().add_modifier(Modifier::BOLD),
        );
        expected.set_style(Rect::new(33, 2, 8, 1), Style::default().fg(Color::Green));
        expected.set_style(Rect::new(42, 2, 8, 1), Style::default().fg(Color::Green));
        expected.set_style(
            Rect::new(1, 3, 12, 1),
            Style::default().add_modifier(Modifier::BOLD),
        );
        expected.set_style(Rect::new(33, 3, 8, 1), Style::default().fg(Color::Red));
        expected.set_style(Rect::new(42, 3, 8, 1), Style::default().fg(Color::Red));

        assert_eq!(buf, expected);
    }
}
