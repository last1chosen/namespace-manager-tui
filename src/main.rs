mod app;
mod models;
mod scanner;
mod ui;

use std::{fs::File, io, sync::Arc};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::app::App;

fn main() -> io::Result<()> {
    let log_file = File::create("ns-visualizer.log")?;

    let file_writer = Arc::new(log_file);

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::DEBUG.into()))
        .with(
            fmt::layer()
                .with_writer(file_writer)
                .with_ansi(false)
                .with_thread_ids(true)
                .with_target(false),
        )
        .init();

    info!("Namespace manager started logging to file.");

    let mut app = App::new()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Startup Error: {:?}", e)))?;

    let mut terminal = ratatui::init();

    let app_result = app.run(&mut terminal);

    ratatui::restore();

    app_result
}
