mod navigation;
mod scroll;

use std::{
    io,
    sync::{
        Arc,
        mpsc::{self, Receiver},
    },
    thread,
    time::Duration,
};

use crossterm::event::{self, Event, KeyCode};
use ratatui::DefaultTerminal;
use ratatui::widgets::TableState;
use tracing::debug;

use crate::scanner::{Inode, NamespaceService, NsResult};
use crate::ui::render_ui;
use crate::{
    models::{DetailSection, DetailState, DetailTab, NamespaceDetail, NetworkNamespace},
    scanner::host::Host,
};

#[derive(Debug)]
pub enum ViewState {
    List,
    Detail(NamespaceDetail),
}

/// App is now generic over <H: Host>.
/// This allows us to inject a 'MockHost' during unit tests to verify
/// TUI behavior without needing root or /proc access.
pub struct App<H: Host + 'static> {
    pub service: Arc<NamespaceService<H>>,
    pub namespaces: Arc<Vec<NetworkNamespace>>,
    pub table_state: TableState,
    pub view_state: ViewState,
    pub exit: bool,
    pub detail_state: DetailState,
    pub is_loading: bool,
    /// Stores non-fatal warnings (e.g., "NFTables scan failed") to display in UI
    pub warnings: Vec<String>,
    // Channels using NsResult to propagate errors across thread boundaries
    pub ns_rx: Option<Receiver<NsResult<Vec<NetworkNamespace>>>>,
    pub detail_rx: Option<Receiver<NsResult<(NamespaceDetail, Vec<String>)>>>,
}

impl<H: Host + 'static> App<H> {
    pub fn with_service(service: Arc<NamespaceService<H>>) -> NsResult<Self> {
        let namespaces = Arc::new(service.gather_all_namespaces()?);

        let mut table_state = TableState::default();
        if !namespaces.is_empty() {
            table_state.select(Some(0));
        }

        Ok(App {
            service,
            namespaces,
            table_state,
            view_state: ViewState::List,
            exit: false,
            detail_state: DetailState::default(),
            is_loading: false,
            warnings: Vec::new(),
            ns_rx: None,
            detail_rx: None,
        })
    }

    /// The main application loop.
    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        while !self.exit {
            // 1. Reconcile asynchronous background results
            self.check_background_tasks();

            // 2. Redraw UI (handles rendering loading spinners or warnings)
            terminal.draw(|f| render_ui(f, self))?;

            // 3. Process blocking input events
            self.handle_events()?;
        }
        Ok(())
    }

    /// Checks the MPSC receivers for any completed background work.
    /// This allows the UI to update as soon as the background scan finishes.
    fn check_background_tasks(&mut self) {
        if let Some(ref rx) = self.ns_rx {
            if let Ok(result) = rx.try_recv() {
                match result {
                    Ok(new_ns) => {
                        let selected = self.table_state.selected();
                        self.namespaces = Arc::new(new_ns);
                        if let Some(idx) = selected {
                            if idx < self.namespaces.len() {
                                self.table_state.select(Some(idx));
                            } else if !self.namespaces.is_empty() {
                                self.table_state.select(Some(0));
                            }
                        }
                    }
                    Err(e) => self.warnings.push(format!("Namespace scan failed: {}", e)),
                }
                self.ns_rx = None;
                self.is_loading = false;
            }
        }

        if let Some(ref rx) = self.detail_rx {
            if let Ok(result) = rx.try_recv() {
                match result {
                    Ok((details, warnings)) => {
                        self.view_state = ViewState::Detail(details);
                        self.detail_state.env_vars.select(None);
                        self.warnings = warnings;
                    }
                    Err(e) => self.warnings.push(format!("Detail fetch failed: {}", e)),
                }
                self.detail_rx = None;
                self.is_loading = false;
            }
        }
    }

    fn handle_events(&mut self) -> io::Result<()> {
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if !self.warnings.is_empty() {
                    self.warnings.clear();
                }
                if let ViewState::Detail(_) = self.view_state {
                    if self.detail_state.is_typing_filter {
                        self.handle_filter_input(key.code);
                        return Ok(());
                    }
                }

                match key.code {
                    KeyCode::Char('/') => {
                        if let ViewState::Detail(_) = self.view_state {
                            self.detail_state.is_typing_filter = true;
                        }
                    }

                    KeyCode::Char('q') => self.exit = true,
                    KeyCode::Char('r') => self.refresh(),
                    KeyCode::Down => match self.view_state {
                        ViewState::List => self.next(),
                        ViewState::Detail(_) => self.scroll_detail(false),
                    },
                    KeyCode::Up => match self.view_state {
                        ViewState::List => self.previous(),
                        ViewState::Detail(_) => self.scroll_detail(true),
                    },
                    KeyCode::Enter => self.on_enter(),
                    KeyCode::Esc => self.on_escape(),
                    KeyCode::Tab => self.namespace_detail_focus(),
                    KeyCode::Right => {
                        self.detail_state.focus = DetailSection::Processes;
                        self.detail_state.active_tab = DetailTab::Internals;
                    }
                    KeyCode::Left => {
                        self.detail_state.focus = DetailSection::Processes;
                        self.detail_state.active_tab = DetailTab::Network;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub fn refresh(&mut self) {
        // 1. ATOMIC LOCK: If a scan is already in flight, skip and log.
        if self.is_loading {
            debug!("Refresh skipped: discovery already in progress.");
            return;
        }

        // 2. SET STATE: Prepare for the async operation
        self.is_loading = true;
        self.warnings.clear();

        // Setup Namespace Discovery Channel
        let (ns_tx, ns_rx) = mpsc::channel();
        self.ns_rx = Some(ns_rx);

        // Strategy 1: The Global List Scan
        let service_list = Arc::clone(&self.service);
        thread::spawn(move || {
            let result = service_list.gather_all_namespaces();
            let _ = ns_tx.send(result);
        });

        // Strategy 2: The Deep-Dive Detail Scan (Only if in Detail View)
        if let ViewState::Detail(_) = self.view_state {
            if let Some(idx) = self.table_state.selected() {
                if let Some(ns) = self.namespaces.get(idx) {
                    let (d_tx, d_rx) = mpsc::channel();
                    self.detail_rx = Some(d_rx);

                    let service = Arc::clone(&self.service);
                    let path = ns.ns_path.clone();
                    let inode = Inode(ns.inode);
                    let all_ns_snapshot = Arc::clone(&self.namespaces);

                    thread::spawn(move || match service.fetch_details(&path, inode) {
                        Ok((mut details, warnings)) => {
                            let current_ips: Vec<String> = details
                                .interfaces
                                .iter()
                                .filter(|i| i.ip != "N/A")
                                .map(|i| i.ip.clone())
                                .collect();

                            // Resolve cross-namespace peers for the detail view
                            details.peers =
                                service.resolve_peers(&current_ips, &all_ns_snapshot, inode);

                            let _ = d_tx.send(Ok((details, warnings)));
                        }
                        Err(e) => {
                            let _ = d_tx.send(Err(e));
                        }
                    });
                }
            }
        }
    }

    fn handle_filter_input(&mut self, code: KeyCode) {
        match code {
            KeyCode::Enter | KeyCode::Char('/') => self.detail_state.is_typing_filter = false,
            KeyCode::Char(c) => {
                self.detail_state.filter_input.push(c);
                self.detail_state.processes.select(Some(0));
            }
            KeyCode::Backspace => {
                self.detail_state.filter_input.pop();
                self.detail_state.processes.select(Some(0));
            }
            _ => {}
        }
    }
}
