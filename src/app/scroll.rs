use ratatui::widgets::{ListState, TableState};

use crate::app::ViewState;
use crate::models::DetailSection;
use crate::scanner::host::Host;

use super::App;

/// Trait to unify widgets that have a selectable state.
pub trait Scrollable {
    fn selected(&self) -> Option<usize>;
    fn select(&mut self, index: Option<usize>);
}

impl Scrollable for TableState {
    fn selected(&self) -> Option<usize> {
        self.selected()
    }
    fn select(&mut self, index: Option<usize>) {
        self.select(index);
    }
}

impl Scrollable for ListState {
    fn selected(&self) -> Option<usize> {
        self.selected()
    }
    fn select(&mut self, index: Option<usize>) {
        self.select(index);
    }
}

fn scroll_generic<S: Scrollable>(state: &mut S, count: usize, up: bool) {
    if count == 0 {
        return;
    }
    let i = match state.selected() {
        Some(i) => {
            if up {
                if i == 0 { count - 1 } else { i - 1 }
            } else {
                if i >= count - 1 { 0 } else { i + 1 }
            }
        }
        None => 0,
    };
    state.select(Some(i));
}

impl<H: Host + 'static> App<H> {
    pub fn scroll_detail(&mut self, up: bool) {
        if let ViewState::Detail(details) = &self.view_state {
            match self.detail_state.focus {
                DetailSection::Interfaces => scroll_generic(
                    &mut self.detail_state.interfaces,
                    details.interfaces.len(),
                    up,
                ),
                DetailSection::Routes => {
                    scroll_generic(&mut self.detail_state.routes, details.routes.len(), up)
                }
                DetailSection::Ports => {
                    scroll_generic(&mut self.detail_state.ports, details.ports.len(), up)
                }
                DetailSection::Processes => {
                    let filter = self.detail_state.filter_input.to_lowercase();
                    let filtered_count = details
                        .processes
                        .iter()
                        .filter(|p| {
                            filter.is_empty()
                                || p.name.to_lowercase().contains(&filter)
                                || p.pid.to_string().contains(&filter)
                        })
                        .count();

                    scroll_generic(&mut self.detail_state.processes, filtered_count, up);
                    self.detail_state.env_vars.select(None);
                }
                DetailSection::EnvVars => {
                    if let Some(selected_ui_idx) = self.detail_state.processes.selected() {
                        let filter = self.detail_state.filter_input.to_lowercase();
                        let target_proc = details
                            .processes
                            .iter()
                            .filter(|p| {
                                filter.is_empty()
                                    || p.name.to_lowercase().contains(&filter)
                                    || p.pid.to_string().contains(&filter)
                            })
                            .nth(selected_ui_idx);

                        if let Some(proc) = target_proc {
                            scroll_generic(
                                &mut self.detail_state.env_vars,
                                proc.env_vars.len(),
                                up,
                            );
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        models::{NamespaceDetail, NamespaceType, NetworkNamespace, ProcessInfo},
        scanner::{NamespaceService, host::MockHost},
    };

    use super::*;
    use rstest::rstest;

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

    fn setup_detail_app() -> App<MockHost> {
        let mut app = setup_test_app(1);

        // Create mock data
        let details = NamespaceDetail {
            processes: vec![
                ProcessInfo {
                    pid: 1,
                    name: "target-1".into(),
                    ..Default::default()
                },
                ProcessInfo {
                    pid: 2,
                    name: "target-2".into(),
                    ..Default::default()
                },
                ProcessInfo {
                    pid: 3,
                    name: "other-proc".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        app.view_state = ViewState::Detail(details);
        app
    }

    #[test]
    fn test_scroll_detail_resets_env_vars_on_process_change() {
        let mut app = setup_detail_app();
        app.detail_state.focus = DetailSection::Processes;

        // Ensure we are on the first process and have an env var selected
        app.detail_state.processes.select(Some(0));
        app.detail_state.env_vars.select(Some(5));

        app.scroll_detail(false); // Move to next process

        assert_eq!(
            app.detail_state.env_vars.selected(),
            None,
            "Env vars should clear when process selection changes"
        );
    }

    #[test]
    fn test_scroll_detail_with_filter_bounds() {
        let mut app = setup_detail_app();
        app.detail_state.focus = DetailSection::Processes;

        // Filter so only "target-1" and "target-2" show up (Count = 2)
        app.detail_state.filter_input = "target".to_string();
        app.detail_state.processes.select(Some(0));

        app.scroll_detail(false); // Move to index 1 (target-2)
        assert_eq!(app.detail_state.processes.selected(), Some(1));

        app.scroll_detail(false); // Should wrap to index 0 (target-1)
        assert_eq!(app.detail_state.processes.selected(), Some(0));
    }

    #[test]
    fn test_scroll_env_vars_requires_process_selection() {
        let mut app = setup_detail_app();
        app.detail_state.focus = DetailSection::EnvVars;

        app.detail_state.processes.select(None);
        app.detail_state.env_vars.select(None);

        app.scroll_detail(false);

        assert_eq!(app.detail_state.env_vars.selected(), None);
    }

    #[rstest]
    #[case(0, 5, false, Some(1))] // Down from start
    #[case(4, 5, false, Some(0))] // Down from end (Wrap)
    #[case(4, 5, true, Some(3))] // Up from end
    #[case(0, 5, true, Some(4))] // Up from start (Wrap)
    #[case(0, 0, false, None)] // Empty list safety
    fn test_scroll_generic_logic(
        #[case] start: usize,
        #[case] len: usize,
        #[case] up: bool,
        #[case] expected: Option<usize>,
    ) {
        let mut state = TableState::default();
        if len > 0 {
            state.select(Some(start));
        }

        scroll_generic(&mut state, len, up);
        assert_eq!(state.selected(), expected);
    }
}
