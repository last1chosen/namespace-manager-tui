use ratatui::widgets::{ListState, TableState};

use crate::app::ViewState;
use crate::models::{DetailSection, DetailTab};
use crate::scanner::fetch_details;

use super::App;

impl App {
    pub fn on_enter(&mut self) {
        if let ViewState::List = self.view_state {
            if let Some(idx) = self.table_state.selected() {
                if let Some(ns) = self.namespaces.get(idx) {
                    let detail = fetch_details(&ns.ns_path, ns.inode);
                    self.view_state = ViewState::Detail(detail);
                }
            }
        }
    }

    pub fn on_escape(&mut self) {
        if let ViewState::Detail(_) = self.view_state {
            self.view_state = ViewState::List;
        }
    }

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

    pub fn scroll_detail(&mut self, up: bool) {
        if let ViewState::Detail(details) = &self.view_state {
            match self.detail_state.focus {
                DetailSection::Interfaces => scroll_table(
                    &mut self.detail_state.interfaces,
                    details.interfaces.len(),
                    up,
                ),
                DetailSection::Routes => {
                    scroll_table(&mut self.detail_state.routes, details.routes.len(), up)
                }
                DetailSection::Ports => {
                    scroll_table(&mut self.detail_state.ports, details.ports.len(), up)
                }
                DetailSection::Processes => {
                    let filtered_count = if self.detail_state.filter_input.is_empty() {
                        details.processes.len()
                    } else {
                        let filter = self.detail_state.filter_input.to_lowercase();
                        details
                            .processes
                            .iter()
                            .filter(|p| {
                                p.name.to_lowercase().contains(&filter)
                                    || p.pid.to_string().contains(&filter)
                            })
                            .count()
                    };

                    scroll_list(&mut self.detail_state.processes, filtered_count, up);
                }
                DetailSection::EnvVars => {
                    if let Some(proc_idx) = self.detail_state.processes.selected() {
                        if let Some(proc) = details.processes.get(proc_idx) {
                            scroll_table(&mut self.detail_state.env_vars, proc.env_vars.len(), up);
                        }
                    }
                }
            }
        }
    }
}

fn scroll_table(state: &mut TableState, count: usize, up: bool) {
    if count == 0 {
        return;
    };
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

fn scroll_list(state: &mut ListState, len: usize, up: bool) {
    if len == 0 {
        return;
    }
    let i = match state.selected() {
        Some(i) => {
            if up {
                if i == 0 { len - 1 } else { i - 1 }
            } else {
                if i >= len - 1 { 0 } else { i + 1 }
            }
        }
        None => 0,
    };
    state.select(Some(i))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::models::{
        DetailState, FirewallInfo, NamespaceDetail, NamespaceType, NetworkNamespace,
    };
    use ratatui::widgets::TableState;

    fn create_test_namespace() -> Vec<NetworkNamespace> {
        vec![
            NetworkNamespace {
                name: "default".to_string(),
                ns_type: NamespaceType::Container,
                inode: 4026531840,
                ns_path: "/proc/1/ns/net".to_string(),
                num_interfaces: 3,
                process_names: vec!["systemd".to_string()],
                primary_pid: Some(1),
                ip_prefixes: vec!["127.0.0.1/8".to_string()],
            },
            NetworkNamespace {
                name: "container1".to_string(),
                ns_type: NamespaceType::Container,
                inode: 4026532448,
                ns_path: "/proc/1234/ns/net".to_string(),
                num_interfaces: 2,
                process_names: vec!["docker".to_string()],
                primary_pid: Some(1234),
                ip_prefixes: vec!["172.17.0.0/16".to_string()],
            },
            NetworkNamespace {
                name: "container2".to_string(),
                ns_type: NamespaceType::Container,
                inode: 4026532448,
                ns_path: "/proc/1235/ns/net".to_string(),
                num_interfaces: 5,
                process_names: vec!["docker".to_string()],
                primary_pid: Some(1235),
                ip_prefixes: vec!["172.17.0.2/16".to_string()],
            },
        ]
    }

    fn create_test_namespace_detail() -> NamespaceDetail {
        NamespaceDetail {
            interfaces: vec![],
            routes: vec![],
            processes: vec![],
            firewall: FirewallInfo {
                chains: 10,
                rules: 10,
            },
            ports: vec![],
        }
    }

    fn create_test_app() -> App {
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        App {
            view_state: ViewState::List,
            namespaces: create_test_namespace(),
            table_state: table_state,
            exit: false,
            detail_state: DetailState::default(),
            is_loading: false,
        }
    }

    #[test]
    fn test_on_escape_changes_view_state_from_detail_to_list() {
        let mut app = App {
            view_state: ViewState::Detail(create_test_namespace_detail()),
            ..create_test_app()
        };
        app.on_escape();

        assert!(matches!(app.view_state, ViewState::List));
    }

    #[test]
    fn test_on_escape_does_not_change_view_when_on_list_view() {
        let mut app = App {
            view_state: ViewState::List,
            ..create_test_app()
        };
        app.on_escape();

        assert!(matches!(app.view_state, ViewState::List));
    }

    #[test]
    fn test_next_moves_down_in_list() {
        let mut app = create_test_app();

        app.next();
        assert_eq!(app.table_state.selected(), Some(1));
    }

    #[test]
    fn test_next_wraps_from_end_to_beginning() {
        let mut app = App {
            table_state: {
                let mut ts = TableState::default();
                ts.select(Some(2));
                ts
            },
            ..create_test_app()
        };

        app.next();

        assert_eq!(app.table_state.selected(), Some(0));
    }

    #[test]
    fn test_next_does_nothing_with_empty_namespaces() {
        let mut app = App {
            namespaces: vec![],
            ..create_test_app()
        };
        app.next();

        assert_eq!(app.table_state.selected(), Some(0));
    }

    #[test]
    fn test_next_does_nothing_when_not_in_view() {
        let mut app = App {
            view_state: ViewState::Detail(NamespaceDetail {
                interfaces: vec![],
                routes: vec![],
                processes: vec![],
                firewall: FirewallInfo {
                    chains: 10,
                    rules: 10,
                },
                ports: vec![],
            }),
            ..create_test_app()
        };
        app.next();

        assert_eq!(app.table_state.selected(), Some(0));
    }

    #[test]
    fn test_previous_moves_up_in_list() {
        let mut app = App {
            table_state: {
                let mut ts = TableState::default();
                ts.select(Some(2));
                ts
            },
            ..create_test_app()
        };

        app.previous();
        assert_eq!(app.table_state.selected(), Some(1));
    }

    #[test]
    fn test_previous_wraps_to_beginning_to_end() {
        let mut app = create_test_app();

        app.previous();

        assert_eq!(app.table_state.selected(), Some(2));
    }

    #[test]
    fn test_previous_does_nothing_with_empty_namespaces() {
        let mut app = App {
            namespaces: vec![],
            ..create_test_app()
        };
        app.previous();

        assert_eq!(app.table_state.selected(), Some(0));
    }

    #[test]
    fn test_previous_does_nothing_when_not_in_view() {
        let mut app = App {
            view_state: ViewState::Detail(create_test_namespace_detail()),
            ..create_test_app()
        };
        app.previous();

        assert_eq!(app.table_state.selected(), Some(0));
    }
}
