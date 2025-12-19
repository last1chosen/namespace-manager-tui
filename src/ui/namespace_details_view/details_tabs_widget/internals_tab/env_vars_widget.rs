use crate::models::DetailSection;
use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Row, Table},
};

pub fn make_env_vars_widget(env_vars: &[String], current_focus: DetailSection) -> Table<'_> {
    let rows: Vec<Row> = env_vars
        .iter()
        .map(|var| {
            let parts: Vec<&str> = var.splitn(2, '=').collect();
            let key = parts.get(0).unwrap_or(&"");
            let val = parts.get(1).unwrap_or(&"");

            Row::new(vec![key.to_string(), val.to_string()])
                .style(Style::default().fg(Color::White))
        })
        .collect();

    let border_style = if current_focus == DetailSection::EnvVars {
        Style::default().fg(Color::Magenta)
    } else {
        Style::default()
    };

    Table::new(
        rows,
        [Constraint::Percentage(30), Constraint::Percentage(70)],
    )
    .header(
        Row::new(vec!["Key", "Value"]).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .title(format!(" Environment Variables ({}) ", env_vars.len()))
            .borders(Borders::ALL)
            .border_style(border_style),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray))
}
