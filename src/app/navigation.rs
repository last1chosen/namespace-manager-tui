use std::sync::{Arc, mpsc};
use std::thread;

use crate::app::ViewState;
use crate::models::{DetailSection, DetailTab};
use crate::scanner::Inode;

use super::App;

impl App {
    /// Handles the Enter key: Transitions from List to Detail view by spawning
    /// a background inspection task.
    pub fn on_enter(&mut self) {
        // Prevent overlapping requests if a scan is already in progress
        if self.is_loading {
            return;
        }

        if let ViewState::List = self.view_state {
            if let Some(idx) = self.table_state.selected() {
                if let Some(ns) = self.namespaces.get(idx) {
                    self.is_loading = true;
                    self.warnings.clear();

                    let (d_tx, d_rx) = mpsc::channel();
                    self.detail_rx = Some(d_rx);

                    let service = Arc::clone(&self.service);
                    let path = ns.ns_path.clone();
                    let inode = Inode(ns.inode);
                    let all_ns_snapshot = Arc::clone(&self.namespaces);

                    thread::spawn(move || {
                        // Step 1: Fetch raw data from the namespace
                        match service.fetch_details(&path, inode) {
                            Ok((mut details, warnings)) => {
                                // Step 2: Extract IPs found during fetch to resolve peers
                                let current_ips: Vec<String> = details
                                    .interfaces
                                    .iter()
                                    .filter(|i| i.ip != "N/A")
                                    .map(|i| i.ip.clone())
                                    .collect();

                                // Step 3: Decoupled peer resolution
                                details.peers =
                                    service.resolve_peers(&current_ips, &all_ns_snapshot, inode);

                                let _ = d_tx.send(Ok((details, warnings)));
                            }
                            Err(e) => {
                                let _ = d_tx.send(Err(e));
                            }
                        }
                    });
                }
            }
        }
    }

    pub fn on_escape(&mut self) {
        if let ViewState::Detail(_) = self.view_state {
            self.view_state = ViewState::List;

            self.detail_rx = None;
            self.is_loading = false;
            self.warnings.clear();
        }
    }

    /// Selects the next item in the namespace list.
    pub fn next(&mut self) {
        if let ViewState::List = self.view_state {
            if self.namespaces.is_empty() {
                return;
            }
            let i = match self.table_state.selected() {
                Some(i) => {
                    if i >= self.namespaces.len() - 1 {
                        0
                    } else {
                        i + 1
                    }
                }
                None => 0,
            };
            self.table_state.select(Some(i));
        }
    }

    /// Selects the previous item in the namespace list.
    pub fn previous(&mut self) {
        if let ViewState::List = self.view_state {
            if self.namespaces.is_empty() {
                return;
            }
            let i = match self.table_state.selected() {
                Some(i) => {
                    if i == 0 {
                        self.namespaces.len() - 1
                    } else {
                        i - 1
                    }
                }
                None => 0,
            };
            self.table_state.select(Some(i));
        }
    }

    /// Rotates focus between different UI sections (Processes, Interfaces, etc.)
    /// within the Detail view.
    pub fn namespace_detail_focus(&mut self) {
        if let ViewState::Detail(_) = self.view_state {
            self.detail_state.focus = match self.detail_state.active_tab {
                DetailTab::Network => match self.detail_state.focus {
                    DetailSection::Processes => DetailSection::Interfaces,
                    DetailSection::Interfaces => DetailSection::Routes,
                    DetailSection::Routes => DetailSection::Ports,
                    DetailSection::Ports => DetailSection::Processes,
                    _ => DetailSection::Processes,
                },
                DetailTab::Internals => match self.detail_state.focus {
                    DetailSection::Processes => DetailSection::EnvVars,
                    DetailSection::EnvVars => DetailSection::Processes,
                    _ => DetailSection::Processes,
                },
            };
        }
    }
}
