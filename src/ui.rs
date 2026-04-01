mod helpers;
mod namespace_details_view;
mod namespaces_list_view;

use helpers::centered_rect;
use namespace_details_view::render_detail;
use namespaces_list_view::render_list;

use ratatui::{
    Frame,
    layout::Alignment,
    style::{Color, Style},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
};

use crate::{
    app::{App, ViewState},
    scanner::host::Host,
};

pub fn render_ui<H: Host + 'static>(f: &mut Frame, app: &mut App<H>) {
    match &app.view_state {
        ViewState::List => render_list(f, app),
        ViewState::Detail(info) => {
            let selected_index = app.table_state.selected().unwrap_or(0);

            render_detail(
                f,
                &mut app.detail_state,
                &app.namespaces,
                selected_index,
                info,
            )
        }
    }

    if app.is_loading {
        let area = centered_rect(40, 15, f.area());
        f.render_widget(Clear, area);

        let block = Block::default()
            .title(" Refreshing ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Yellow));

        let text = Paragraph::new("\n\nScanning system...")
            .block(block)
            .alignment(Alignment::Center);

        f.render_widget(text, area);
    }
}
