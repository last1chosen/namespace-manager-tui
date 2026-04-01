use std::sync::{Arc, mpsc};
use std::thread;

use tracing::{debug, error};

use crate::app::ViewState;
use crate::models::{DetailSection, DetailTab, NamespaceDetail};
use crate::scanner::host::Host;
use crate::scanner::{Inode, NsResult};

use super::App;

impl<H: Host + 'static> App<H> {
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
                        debug!(
                            "Background thread started for namespace inspection: {}",
                            path
                        );

                        let res = (|| -> NsResult<(NamespaceDetail, Vec<String>)> {
                            let (mut details, warnings) = service.fetch_details(&path, inode)?;

                            debug!("Fetch successful, resolving peers...");
                            let current_ips: Vec<String> = details
                                .interfaces
                                .iter()
                                .filter(|i| i.ip != "N/A")
                                .map(|i| i.ip.clone())
                                .collect();

                            details.peers =
                                service.resolve_peers(&current_ips, &all_ns_snapshot, inode);
                            Ok((details, warnings))
                        })();

                        if let Err(ref e) = res {
                            error!("INSPECTION THREAD FAILED: {}", e);
                        }

                        let _ = d_tx.send(res);
                        debug!("Background thread finished and result sent.");
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
            let len = self.namespaces.len();
            if len == 0 {
                self.table_state.select(None);
                return;
            }

            let prev_idx = self
                .table_state
                .selected()
                .map(|i| {
                    if i >= self.namespaces.len() - 1 {
                        0
                    } else {
                        i + 1
                    }
                })
                .unwrap_or(0);

            self.table_state.select(Some(prev_idx));
        }
    }

    /// Selects the previous item in the namespace list.
    pub fn previous(&mut self) {
        if let ViewState::List = self.view_state {
            let len = self.namespaces.len();
            if len == 0 {
                self.table_state.select(None);
                return;
            }

            // Mapping logic: if at 0, go to end; else go back 1. Default to 0.
            let prev_idx = self
                .table_state
                .selected()
                .map(|i| if i == 0 { len - 1 } else { i - 1 })
                .unwrap_or(0);

            self.table_state.select(Some(prev_idx));
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

#[cfg(test)]
mod tests {
    use crate::{
        models::{NamespaceDetail, NamespaceType, NetworkNamespace},
        scanner::{NamespaceService, host::MockHost},
    };

    use super::*;

    /// Helper function to create a test app with a specific number of namespaces.
    fn setup_test_app(num_namespaces: usize) -> App<MockHost> {
        let host = MockHost { mock_inode: 123 };

        // Create dummy namespaces
        let mut namespaces = Vec::new();
        for i in 0..num_namespaces {
            namespaces.push(NetworkNamespace {
                name: format!("ns-{}", i),
                ns_type: NamespaceType::Regular, // We pick one for testing purposes
                inode: (1000 + i) as u64,
                ns_path: format!("/proc/fake/{}", i),
                num_interfaces: 0,
                process_names: vec![],
                primary_pid: None,
                ip_prefixes: vec![],
            });
        }
        let service = NamespaceService::with_host(host).expect("Failed to create service");
        let service_arc = Arc::new(service);

        let mut app = App::with_service(service_arc).expect("Failed to create test app");
        app.namespaces = Arc::new(namespaces);
        app
    }

    #[test]
    fn test_on_escape_transitions_back_to_list() {
        let mut app = setup_test_app(1);

        // 1. Manually set state to Detail
        app.view_state = ViewState::Detail(NamespaceDetail::default());
        app.is_loading = true;
        app.warnings.push("Dummy warning".into());

        // 2. Trigger escape
        app.on_escape();

        // 3. Verify state reset
        assert!(matches!(app.view_state, ViewState::List));
        assert!(!app.is_loading);
        assert!(app.warnings.is_empty());
        assert!(app.detail_rx.is_none());
    }

    #[test]
    fn test_next_navigation_and_wrapping() {
        // Setup app with 3 items (Indices: 0, 1, 2)
        let mut app = setup_test_app(3);

        // Start at index 0
        app.table_state.select(Some(0));

        // Move to index 1
        app.next();
        assert_eq!(app.table_state.selected(), Some(1));

        // Move to index 2
        app.next();
        assert_eq!(app.table_state.selected(), Some(2));

        // Move again: should wrap around to 0
        app.next();
        assert_eq!(app.table_state.selected(), Some(0));
    }

    #[test]
    fn test_previous_navigation_and_wrapping() {
        let mut app = setup_test_app(3);

        // Start at index 0
        app.table_state.select(Some(0));

        // Move back: should wrap to last index (2)
        app.previous();
        assert_eq!(app.table_state.selected(), Some(2));

        // Move back to index 1
        app.previous();
        assert_eq!(app.table_state.selected(), Some(1));
    }

    #[test]
    fn test_navigation_with_empty_list() {
        let mut app = setup_test_app(0);

        app.next();
        assert!(app.table_state.selected().is_none());

        app.previous();
        assert!(app.table_state.selected().is_none());
    }

    #[test]
    fn test_navigation_locked_in_detail_view() {
        let mut app = setup_test_app(3);
        app.table_state.select(Some(0));

        // Change to detail view
        app.view_state = ViewState::Detail(NamespaceDetail::default());

        // Pressing next/previous should NOT change selection while in detail view
        app.next();
        assert_eq!(app.table_state.selected(), Some(0));

        app.previous();
        assert_eq!(app.table_state.selected(), Some(0));
    }
}
