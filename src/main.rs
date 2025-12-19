mod app;
mod models;
mod scanner;
mod ui;

use std::io;

use crate::app::App;

fn main() -> io::Result<()> {
    let mut app = App::new()?;
    let mut terminal = ratatui::init();

    let app_result = app.run(&mut terminal);

    ratatui::restore();

    app_result
}
