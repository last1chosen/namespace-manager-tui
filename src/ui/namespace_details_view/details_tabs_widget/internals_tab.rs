mod empty_state;
mod env_vars_widget;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use empty_state::make_empty_internals_state;
use env_vars_widget::make_env_vars_widget;

use crate::models::{DetailState, ProcessInfo};

pub fn render_internals_tab(
    f: &mut Frame,
    state: &mut DetailState,
    selected_process: Option<&ProcessInfo>,
    process_count: usize,
    area: Rect,
) {
    if let Some(proc) = selected_process {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Min(0)])
            .split(area);

        let cmd_text = if proc.cmdline.is_empty() {
            format!("{}", proc.name)
        } else {
            proc.cmdline.clone()
        };

        let cmd_widget = Paragraph::new(cmd_text)
            .block(
                Block::default()
                    .title(" Full Command Line ")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(cmd_widget, chunks[0]);

        let env_widget = make_env_vars_widget(&proc.env_vars, state.focus);

        f.render_stateful_widget(env_widget, chunks[1], &mut state.env_vars);
    } else {
        let empty_internal_state = make_empty_internals_state(process_count);
        f.render_widget(empty_internal_state, area);
    }
}
