use ratatui::{
    layout::Alignment,
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Paragraph},
};

use crate::models::NetworkNamespace;

pub fn make_header_widget(network_namespace: &NetworkNamespace) -> Paragraph<'_> {
    let name = &network_namespace.name;
    let ns_type = &network_namespace.ns_type;
    let primary_pid = network_namespace.primary_pid;

    let type_str = format!("{:?}", ns_type);
    let pid_display = if let Some(p) = primary_pid {
        p.to_string()
    } else {
        "None".to_string()
    };
    let header_text = format!(" {} (PID: {}) Type: {}", name, pid_display, type_str);
    let header = Block::default()
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Blue).fg(Color::White));

    Paragraph::new(Span::styled(
        header_text,
        Style::default().add_modifier(Modifier::BOLD),
    ))
    .block(header)
    .alignment(Alignment::Left)
}

#[cfg(test)]
mod tests {
    use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};

    use super::*;
    use crate::{
        models::NamespaceType, ui::namespace_details_view::header_widget::make_header_widget,
    };

    #[test]
    fn test_make_headers_widget() {
        let network_namespace = NetworkNamespace {
            name: "test-ns".to_string(),
            ns_type: NamespaceType::Container,
            process_names: vec!["nginx".to_string()],
            num_interfaces: 2,
            inode: 6454,
            ns_path: "path/one".to_string(),
            primary_pid: Some(123),
            ip_prefixes: vec!["ip_1".to_string(), "ip_2".to_string()],
        };
        let nftable = make_header_widget(&network_namespace);

        let mut buf = Buffer::empty(Rect::new(0, 0, 50, 4));
        Widget::render(nftable, *buf.area(), &mut buf);

        let mut expected = Buffer::with_lines(vec![
            "┌────────────────────────────────────────────────┐",
            "│ test-ns (PID: 123) Type: Container             │",
            "│                                                │",
            "└────────────────────────────────────────────────┘",
        ]);
        expected.set_style(
            Rect::new(0, 0, 50, 4),
            Style::default().fg(Color::White).bg(Color::Blue),
        );
        expected.set_style(
            Rect::new(1, 1, 35, 1),
            Style::default()
                .fg(Color::White)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        );
        expected.set_style(
            Rect::new(36, 1, 2, 0),
            Style::default().fg(Color::White).bg(Color::Blue),
        );

        assert_eq!(buf, expected);
    }
}
