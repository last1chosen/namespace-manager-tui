pub mod internals_tab;
pub mod network_tab;

use ratatui::{
    style::{Color, Style},
    widgets::{Block, Borders, Tabs},
};

use crate::models::DetailTab;

pub fn make_details_tabs(active_tab: &DetailTab) -> Tabs<'_> {
    let titles = vec![" [1] Network ", " [2] Internals "];
    Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL))
        .highlight_style(Style::default().fg(Color::Yellow))
        .select(match active_tab {
            DetailTab::Network => 0,
            DetailTab::Internals => 1,
        })
}

#[cfg(test)]
mod tests {
    use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};

    use super::*;

    #[test]
    fn test_make_details_tabs_with_internals_tab_selected() {
        let widget = make_details_tabs(&DetailTab::Internals);
        let mut buf = Buffer::empty(Rect::new(0, 0, 50, 3));
        Widget::render(widget, *buf.area(), &mut buf);

        let mut expected = Buffer::with_lines(vec![
            "┌────────────────────────────────────────────────┐",
            "│  [1] Network  │  [2] Internals                 │",
            "└────────────────────────────────────────────────┘",
        ]);
        expected.set_style(Rect::new(18, 1, 15, 1), Style::default().fg(Color::Yellow));
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_make_details_tabs_with_network_tab_selected() {
        let widget = make_details_tabs(&DetailTab::Network);
        let mut buf = Buffer::empty(Rect::new(0, 0, 50, 3));
        Widget::render(widget, *buf.area(), &mut buf);
        let mut expected = Buffer::with_lines(vec![
            "┌────────────────────────────────────────────────┐",
            "│  [1] Network  │  [2] Internals                 │",
            "└────────────────────────────────────────────────┘",
        ]);
        expected.set_style(Rect::new(2, 1, 13, 1), Style::default().fg(Color::Yellow));
        assert_eq!(buf, expected);
    }
}
