use ratatui::{
    layout::Alignment,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub fn make_empty_internals_state(process_count: usize) -> Paragraph<'static> {
    let (title, instruction) = if process_count == 0 {
        (
            "NO RUNNING PROCESSES",
            "This namespace appears to be active but has no processes.",
        )
    } else {
        (
            "NO PROCESS SELECTED",
            "Select a process from the sidebar to inspect details.",
        )
    };

    Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            title,
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from(instruction),
    ])
    .block(Block::default().borders(Borders::ALL))
    .alignment(Alignment::Center)
    .wrap(Wrap { trim: true })
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

    #[test]
    fn render_no_running_processes() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 60, 7));

        let empty_internal_state = make_empty_internals_state(0);
        Widget::render(empty_internal_state, *buf.area(), &mut buf);

        let mut expected = Buffer::with_lines(vec![
            "┌──────────────────────────────────────────────────────────┐",
            "│                                                          │",
            "│                   NO RUNNING PROCESSES                   │",
            "│                                                          │",
            "│ This namespace appears to be active but has no processes.│",
            "│                                                          │",
            "└──────────────────────────────────────────────────────────┘",
        ]);

        let title_style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);

        expected.set_style(Rect::new(20, 2, 20, 1), title_style);

        assert_eq!(buf, expected);
    }

    #[test]
    fn render_no_process_selected() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 60, 7));
        let empty_internal_state = make_empty_internals_state(5);
        Widget::render(empty_internal_state, *buf.area(), &mut buf);

        let mut expected = Buffer::with_lines(vec![
            "┌──────────────────────────────────────────────────────────┐",
            "│                                                          │",
            "│                    NO PROCESS SELECTED                   │",
            "│                                                          │",
            "│   Select a process from the sidebar to inspect details.  │",
            "│                                                          │",
            "└──────────────────────────────────────────────────────────┘",
        ]);

        let title_style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);

        expected.set_style(Rect::new(21, 2, 19, 1), title_style);

        assert_eq!(buf, expected);
    }

    #[test]
    fn test_render_no_process_selected_with_wrap() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 45, 7));
        let empty_internal_state = make_empty_internals_state(5);
        Widget::render(empty_internal_state, *buf.area(), &mut buf);

        let mut expected = Buffer::with_lines(vec![
            "┌───────────────────────────────────────────┐",
            "│                                           │",
            "│            NO PROCESS SELECTED            │",
            "│                                           │",
            "│   Select a process from the sidebar to    │",
            "│             inspect details.              │",
            "└───────────────────────────────────────────┘",
        ]);

        let title_style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);

        expected.set_style(Rect::new(13, 2, 19, 1), title_style);

        assert_eq!(buf, expected);
    }
}
