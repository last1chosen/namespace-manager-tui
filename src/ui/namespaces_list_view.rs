use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table},
};

use super::helpers::{footer_bar, proc_display_cell};
use crate::app::App;
use crate::models::{NamespaceType, NetworkNamespace};

pub fn render_list(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(f.area());

    let table = build_namespace_table(&app.namespaces);
    f.render_stateful_widget(table, chunks[0], &mut app.table_state);

    let footer = footer_bar(" ↑/↓: Navigate | Enter: Details | r: Refresh | q: Quit ");
    f.render_widget(footer, chunks[1]);
}

fn build_namespace_table<'a>(namespaces: &[NetworkNamespace]) -> Table<'a> {
    let header_cells = ["Name", "Main Processes", "Interfaces"].iter().map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows = namespaces.iter().map(|ns| {
        let (symbol, color) = match ns.ns_type {
            NamespaceType::Container => ("◆", Color::Green),
            NamespaceType::Vpn => ("▲", Color::Magenta),
            NamespaceType::Regular => ("●", Color::Blue),
        };
        let name_str = format!("{} {}", symbol, ns.name);
        let proc_str = if ns.process_names.len() > 3 {
            format!(
                "{}, {}, ... (+{})",
                ns.process_names[0],
                ns.process_names[1],
                ns.process_names.len() - 2
            )
        } else {
            ns.process_names.join(", ")
        };
        Row::new(vec![
            Cell::from(name_str).style(Style::default().fg(color)),
            Cell::from(proc_display_cell(proc_str)),
            Cell::from(ns.num_interfaces.to_string()),
        ])
        .height(1)
    });

    Table::new(
        rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(40),
            Constraint::Percentage(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Network Namespaces"),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(">> ")
}

#[cfg(test)]
mod tests {
    use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};

    use super::*;
    use crate::{app::ViewState, models::DetailState};
    #[test]
    fn namespace_table_display_correctly() {
        let app = App {
            namespaces: vec![NetworkNamespace {
                name: "test-ns".to_string(),
                ns_type: NamespaceType::Container,
                process_names: vec!["nginx".to_string()],
                num_interfaces: 2,
                inode: 6454,
                ns_path: "path/one".to_string(),
                primary_pid: Some(123),
                ip_prefixes: vec!["ip_1".to_string(), "ip_2".to_string()],
            }],
            table_state: Default::default(),
            view_state: ViewState::List,
            exit: false,
            detail_state: DetailState::default(),
            is_loading: false,
        };

        let table = build_namespace_table(&app.namespaces);

        let mut buf = Buffer::empty(Rect::new(0, 0, 50, 5));
        Widget::render(table, *buf.area(), &mut buf);

        let mut expected = Buffer::with_lines(vec![
            "┌Network Namespaces──────────────────────────────┐",
            "│Name               Main Processes     Interfaces│",
            "│                                                │",
            "│◆ test-ns          nginx              2         │",
            "└────────────────────────────────────────────────┘",
        ]);
        expected.set_style(
            Rect::new(1, 1, 18, 1),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
        expected.set_style(
            Rect::new(20, 1, 18, 1),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
        expected.set_style(
            Rect::new(39, 1, 10, 1),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
        expected.set_style(Rect::new(1, 3, 18, 1), Style::default().fg(Color::Green));

        assert_eq!(buf, expected);
    }
}
