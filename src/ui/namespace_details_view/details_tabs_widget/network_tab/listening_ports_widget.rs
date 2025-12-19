use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Cell, Row, Table},
};

use crate::models::{DetailSection, ListeningPort};

pub fn make_listening_ports_widget(
    listening_ports: &[ListeningPort],
    focused_state: DetailSection,
) -> Table<'_> {
    let mut rows = Vec::with_capacity(listening_ports.len());
    let mut has_global = false;
    let mut has_specific = false;

    for p in listening_ports {
        let (addr_display, style) = match p.addr.as_str() {
            "0.0.0.0" | "::" | "*" => {
                has_global = true;
                (
                    format!("{} (All Interfaces)", p.addr),
                    Style::default().fg(Color::Green),
                )
            }
            addr if addr.starts_with("127.") || addr == "::1" => (
                format!("{} (Loopback Only)", p.addr),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            _ => {
                has_specific = true;
                (p.addr.clone(), Style::default().fg(Color::Cyan))
            }
        };

        rows.push(Row::new(vec![
            Cell::from(p.proto.as_str()),
            Cell::from(addr_display).style(style),
            Cell::from(p.port.as_str()).style(Style::default().fg(Color::Green)),
        ]));
    }

    let (status_text, status_color) = if has_global {
        ("Global Access", Color::Green)
    } else if has_specific {
        ("Specific Interface", Color::Cyan)
    } else if !rows.is_empty() {
        ("Local Only", Color::Yellow)
    } else {
        ("No Open Ports", Color::DarkGray)
    };

    let port_title = Span::styled(
        format!(
            "Listening Ports ({}) - {}",
            listening_ports.len(),
            status_text
        ),
        Style::default()
            .fg(status_color)
            .add_modifier(Modifier::BOLD),
    );

    let is_focused = focused_state == DetailSection::Ports;
    let (border_color, highlight_style) = if is_focused {
        (Color::Magenta, Style::default().bg(Color::DarkGray))
    } else {
        (Color::default(), Style::default())
    };

    Table::new(
        rows,
        [
            Constraint::Percentage(20),
            Constraint::Percentage(60),
            Constraint::Percentage(20),
        ],
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(port_title)
            .border_style(Style::default().fg(border_color)),
    )
    .header(Row::new(vec!["Proto", "Address", "Port"]).style(Style::default().fg(Color::Yellow)))
    .row_highlight_style(highlight_style)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{
        buffer::Buffer,
        layout::Rect,
        style::{Color, Modifier, Style},
        widgets::Widget,
    };

    fn create_port(proto: &str, addr: &str, port: &str) -> ListeningPort {
        ListeningPort {
            proto: proto.to_string(),
            addr: addr.to_string(),
            port: port.to_string(),
        }
    }

    #[test]
    fn test_make_listening_ports_widget_specific_interface_not_focused() {
        let ports = vec![create_port("tcp", "192.168.1.5", "22")];
        let widget = make_listening_ports_widget(&ports, DetailSection::Interfaces);

        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 5));
        Widget::render(widget, *buf.area(), &mut buf);

        let mut expected = Buffer::with_lines(vec![
            "┌Listening Ports (1) - Specific Interface──────────────────────────────────────┐",
            "│Proto            Address                                      Port            │",
            "│tcp              192.168.1.5                                  22              │",
            "│                                                                              │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
        ]);
        expected.set_style(
            Rect::new(1, 0, 40, 1),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
        expected.set_style(Rect::new(1, 1, 78, 1), Style::default().fg(Color::Yellow));
        expected.set_style(Rect::new(18, 2, 44, 1), Style::default().fg(Color::Cyan));
        expected.set_style(Rect::new(63, 2, 16, 1), Style::default().fg(Color::Green));

        assert_eq!(buf, expected);
    }

    #[test]
    fn test_make_listening_ports_widget_global_access_not_focused() {
        let ports = vec![create_port("tcp", "0.0.0.0", "80")];
        let widget = make_listening_ports_widget(&ports, DetailSection::Interfaces);

        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 5));
        Widget::render(widget, *buf.area(), &mut buf);

        let mut expected = Buffer::with_lines(vec![
            "┌Listening Ports (1) - Global Access───────────────────────────────────────────┐",
            "│Proto            Address                                      Port            │",
            "│tcp              0.0.0.0 (All Interfaces)                     80              │",
            "│                                                                              │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
        ]);

        expected.set_style(
            Rect::new(1, 0, 35, 1),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        );
        expected.set_style(Rect::new(1, 1, 78, 1), Style::default().fg(Color::Yellow));
        expected.set_style(Rect::new(18, 2, 44, 1), Style::default().fg(Color::Green));
        expected.set_style(Rect::new(63, 2, 16, 1), Style::default().fg(Color::Green));

        assert_eq!(buf, expected);
    }

    #[test]
    fn test_make_listening_ports_widget_local_only_not_focused() {
        let ports = vec![create_port("udp", "127.0.0.1", "53")];
        let widget = make_listening_ports_widget(&ports, DetailSection::Interfaces);

        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 5));
        Widget::render(widget, *buf.area(), &mut buf);

        let mut expected = Buffer::with_lines(vec![
            "┌Listening Ports (1) - Local Only──────────────────────────────────────────────┐",
            "│Proto            Address                                      Port            │",
            "│udp              127.0.0.1 (Loopback Only)                    53              │",
            "│                                                                              │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
        ]);

        expected.set_style(
            Rect::new(1, 0, 32, 1),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
        expected.set_style(Rect::new(1, 1, 78, 1), Style::default().fg(Color::Yellow));
        expected.set_style(
            Rect::new(18, 2, 44, 1),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
        expected.set_style(Rect::new(63, 2, 16, 1), Style::default().fg(Color::Green));

        assert_eq!(buf, expected);
    }

    #[test]
    fn test_make_listening_ports_widget_empty_not_focused() {
        let ports = vec![];
        let widget = make_listening_ports_widget(&ports, DetailSection::Interfaces);

        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 5));
        Widget::render(widget, *buf.area(), &mut buf);

        let mut expected = Buffer::with_lines(vec![
            "┌Listening Ports (0) - No Open Ports───────────────────────────────────────────┐",
            "│Proto            Address                                      Port            │",
            "│                                                                              │",
            "│                                                                              │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
        ]);

        expected.set_style(
            Rect::new(1, 0, 35, 1),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );
        expected.set_style(Rect::new(1, 1, 78, 1), Style::default().fg(Color::Yellow));

        assert_eq!(buf, expected);
    }
}
