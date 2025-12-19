mod details_tabs_widget;
mod header_widget;
mod processes_widget;

use super::helpers::footer_bar;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
};

use crate::models::{DetailState, DetailTab, NamespaceDetail, NetworkNamespace, ProcessInfo};
use details_tabs_widget::{
    internals_tab::render_internals_tab, make_details_tabs, network_tab::render_network_tab,
};

use header_widget::make_header_widget;
use processes_widget::make_processes_widget;

pub fn render_detail(
    f: &mut Frame,
    detail_state: &mut DetailState,
    namespaces: &[NetworkNamespace],
    selected_index: usize,
    info: &NamespaceDetail,
) {
    let current_ns = &namespaces[selected_index];

    let filtered_processes: Vec<&ProcessInfo> = info
        .processes
        .iter()
        .filter(|p| {
            if detail_state.filter_input.is_empty() {
                true
            } else {
                p.name
                    .to_lowercase()
                    .contains(&detail_state.filter_input.to_lowercase())
            }
        })
        .collect();

    let selected_list_idx = detail_state.processes.selected();
    let selected_process = selected_list_idx
        .and_then(|i| filtered_processes.get(i))
        .copied(); // Turns &&ProcessInfo into &ProcessInfo

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.area());

    f.render_widget(make_header_widget(current_ns), main_chunks[0]);

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
        .split(main_chunks[1]);

    let processes_list = make_processes_widget(&filtered_processes, detail_state.focus);
    f.render_stateful_widget(processes_list, body_chunks[0], &mut detail_state.processes);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(body_chunks[1]);

    let tabs = make_details_tabs(&detail_state.active_tab);
    f.render_widget(tabs, right_chunks[0]);

    match detail_state.active_tab {
        DetailTab::Network => {
            render_network_tab(
                f,
                detail_state,
                info,
                namespaces,
                current_ns,
                right_chunks[1],
            );
        }
        DetailTab::Internals => {
            render_internals_tab(
                f,
                detail_state,
                selected_process,
                filtered_processes.len(),
                right_chunks[1],
            );
        }
    }

    let footer_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(25), Constraint::Min(10)])
        .split(main_chunks[2]);

    let filter_text = if detail_state.filter_input.is_empty() {
        "Filter Processes...".to_string()
    } else {
        detail_state.filter_input.clone()
    };

    let (filter_color, filter_title) = if detail_state.is_typing_filter {
        (Color::Red, " TYPING ")
    } else if !detail_state.filter_input.is_empty() {
        (Color::Green, " Active Filter ")
    } else {
        (Color::DarkGray, " / to Filter ")
    };

    let filter_widget = Paragraph::new(filter_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(filter_color))
                .title(filter_title),
        )
        .style(if detail_state.is_typing_filter {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        });

    f.render_widget(filter_widget, footer_chunks[0]);
    f.render_widget(
        footer_bar(" ◄/►: Switch Tab | Tab: Change Focus | /: Filter | Esc: Back "),
        footer_chunks[1],
    );
}
