use ratatui::{
    layout::Constraint,
    style::{Color, Style},
    widgets::{Block, Borders, Cell, Row, Table},
};

use crate::models::{DetailSection, RouteInfo};

pub fn make_routing_table_widget(routes: &[RouteInfo], focused_state: DetailSection) -> Table<'_> {
    let route_title = format!("Routing Table ({})", routes.len());
    let route_rows = routes.iter().map(|r| {
        Row::new(vec![
            Cell::from(r.dst.as_str()),
            Cell::from(r.gateway.as_str()),
            Cell::from(r.dev.as_str()),
        ])
    });

    let is_focused = focused_state == DetailSection::Routes;

    let (border_color, highlight_style) = if is_focused {
        (Color::Magenta, Style::default().bg(Color::DarkGray))
    } else {
        (Color::default(), Style::default())
    };

    Table::new(
        route_rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(40),
            Constraint::Percentage(20),
        ],
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(route_title)
            .border_style(Style::default().fg(border_color)),
    )
    .header(Row::new(vec!["Dest", "Gateway", "Dev"]).style(Style::default().fg(Color::Yellow)))
    .row_highlight_style(highlight_style)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};

    #[test]
    fn test_make_listening_ports_widget_specific_interface_not_focused() {
        let routes = vec![
            RouteInfo {
                dst: "default".to_string(),
                gateway: "172.16.1.1".to_string(),
                dev: "eth0".to_string(),
            },
            RouteInfo {
                dst: "172.16.0.0/22 ".to_string(),
                gateway: "0.0.0.0".to_string(),
                dev: "eth0".to_string(),
            },
        ];

        let widget = make_routing_table_widget(&routes, DetailSection::Interfaces);

        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 5));
        Widget::render(widget, *buf.area(), &mut buf);

        let mut expected = Buffer::with_lines(vec![
            "┌Routing Table (2)─────────────────────────────────────────────────────────────┐",
            "│Dest                           Gateway                        Dev             │",
            "│default                        172.16.1.1                     eth0            │",
            "│172.16.0.0/22                  0.0.0.0                        eth0            │",
            "└──────────────────────────────────────────────────────────────────────────────┘",
        ]);
        expected.set_style(Rect::new(1, 1, 78, 1), Style::default().fg(Color::Yellow));

        assert_eq!(buf, expected);
    }
}
