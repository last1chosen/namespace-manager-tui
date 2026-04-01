mod app;
mod models;
mod scanner;
mod ui;

use std::{fs::File, io, sync::Arc};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::{
    app::App,
    scanner::{NamespaceService, NsError},
};
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

    let service = NamespaceService::new().map_err(|e| {
        tracing::error!("Internal Startup Failure: {:?}", e);

        match e {
            NsError::InsufficientPrivileges(_) => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Access Denied: High-privilege (root) capabilities required.",
            ),
            NsError::IoWithPath { .. } => io::Error::new(
                io::ErrorKind::NotFound,
                "System Error: A required kernel interface or path is unreachable.",
            ),
            _ => io::Error::new(
                io::ErrorKind::Other,
                "Initialization Failed: Check log file for incident details.",
            ),
        }
    })?;

    let service_arc = Arc::new(service);

    // 2. APP INITIALIZATION
    let mut app = App::with_service(service_arc).map_err(|e| {
        tracing::error!("App Init Panic: {:?}", e);
        io::Error::new(
            io::ErrorKind::Other,
            "Application Error: Failed to initialize UI state.",
        )
    })?;

    let mut terminal = ratatui::init();
    let app_result = app.run(&mut terminal);
    ratatui::restore();

    // 3. EXIT HANDLING
    if let Err(ref e) = app_result {
        tracing::error!("Runtime Crash: {:?}", e);
    }

    app_result
}
