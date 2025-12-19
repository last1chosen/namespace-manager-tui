use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
};

pub(super) fn proc_display_cell(s: String) -> String {
    if s.is_empty() {
        return "-".to_string();
    }
    s
}

pub(super) fn footer_bar<'a>(footer_text: &'a str) -> Paragraph<'a> {
    Paragraph::new(footer_text)
        .block(Block::default().borders(Borders::ALL).title("Controls"))
        .style(Style::default().fg(Color::Cyan))
        .alignment(Alignment::Center)
}

pub(super) fn centered_rect(width: u16, height: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(height),
            Constraint::Fill(1),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(width),
            Constraint::Fill(1),
        ])
        .split(popup_layout[1])[1]
}
#[cfg(test)]
mod tests {

    use super::*;
    use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};

    #[test]
    fn test_proc_display_cell_returns_input() {
        assert_eq!(proc_display_cell("hello".to_string()), "hello");
    }

    #[test]
    fn test_proc_display_cell_returns_dash() {
        assert_eq!(proc_display_cell("".to_string()), "-")
    }

    #[test]
    fn test_footer_bar_renders_correctly() {
        let rect_sizing = Rect::new(0, 0, 20, 3);
        let mut buf = Buffer::empty(rect_sizing);
        let footer = footer_bar("text");
        Widget::render(footer, *buf.area(), &mut buf);

        let mut expected = Buffer::with_lines(vec![
            "┌Controls──────────┐",
            "│       text       │",
            "└──────────────────┘",
        ]);
        expected.set_style(rect_sizing, Style::default().fg(Color::Cyan));
        assert_eq!(buf, expected)
    }

    #[test]
    fn test_centered_rect_fixed_size() {
        let sizing = Rect::new(0, 0, 100, 100);

        let cent_rect = centered_rect(40, 20, sizing);

        assert_eq!(cent_rect.x, 30);
        assert_eq!(cent_rect.y, 40);
        assert_eq!(cent_rect.width, 40);
        assert_eq!(cent_rect.height, 20);
    }

    #[test]
    fn test_centered_rect_clamping() {
        let sizing = Rect::new(0, 0, 10, 10);
        let cent_rect = centered_rect(40, 20, sizing);

        assert_eq!(cent_rect.width, 10);
        assert_eq!(cent_rect.height, 10);
        assert_eq!(cent_rect.x, 0);
        assert_eq!(cent_rect.y, 0);
    }
}
