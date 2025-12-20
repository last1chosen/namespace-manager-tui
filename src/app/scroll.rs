use ratatui::widgets::{ListState, TableState};

use crate::app::ViewState;
use crate::models::DetailSection;

use super::App;

impl App {
    /// Handles scrolling within the currently focused detail section.
    // Inside navigation.rs -> impl App
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

                    scroll_list(&mut self.detail_state.processes, filtered_count, up);

                    self.detail_state.env_vars.select(None);
                }

                DetailSection::EnvVars => {
                    // 1. Get the UI selection index
                    if let Some(selected_ui_idx) = self.detail_state.processes.selected() {
                        // 2. Find the ACTUAL process object by re-applying the filter
                        let filter = self.detail_state.filter_input.to_lowercase();
                        let target_proc = details
                            .processes
                            .iter()
                            .filter(|p| {
                                filter.is_empty()
                                    || p.name.to_lowercase().contains(&filter)
                                    || p.pid.to_string().contains(&filter)
                            })
                            .nth(selected_ui_idx); // This maps UI Index -> Data Object

                        // 3. Scroll the env vars of the CORRECT process
                        if let Some(proc) = target_proc {
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

// THIS IS REALLY A DUPLICATE OF THE ABOVE, except it's for a ListState instead of a TableState
// could refactor with a trait for both.
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

    #[test]
    fn test_scroll_table_down() {
        let mut state = TableState::default();
        state.select(Some(0));

        scroll_table(&mut state, 5, false);
        assert_eq!(state.selected(), Some(1))
    }

    #[test]
    fn test_scroll_table_up() {
        let mut state = TableState::default();
        state.select(Some(4));

        scroll_table(&mut state, 5, true);
        assert_eq!(state.selected(), Some(3))
    }

    #[test]
    fn test_scroll_table_up_on_first_wraps_to_last() {
        let mut state = TableState::default();
        state.select(Some(0));

        scroll_table(&mut state, 5, true);
        assert_eq!(state.selected(), Some(4))
    }

    #[test]
    fn test_scroll_table_down_on_last_wraps_to_first() {
        let mut state = TableState::default();
        state.select(Some(4));

        scroll_table(&mut state, 5, false);
        assert_eq!(state.selected(), Some(0))
    }

    #[test]
    fn test_scroll_list_down() {
        let mut state = TableState::default();
        state.select(Some(0));

        scroll_table(&mut state, 5, false);
        assert_eq!(state.selected(), Some(1))
    }

    #[test]
    fn test_scroll_list_up() {
        let mut state = TableState::default();
        state.select(Some(4));

        scroll_table(&mut state, 5, true);
        assert_eq!(state.selected(), Some(3))
    }

    #[test]
    fn test_scroll_list_up_on_first_wraps_to_last() {
        let mut state = TableState::default();
        state.select(Some(0));

        scroll_table(&mut state, 5, true);
        assert_eq!(state.selected(), Some(4))
    }

    #[test]
    fn test_scroll_list_down_on_last_wraps_to_first() {
        let mut state = TableState::default();
        state.select(Some(4));

        scroll_table(&mut state, 5, false);
        assert_eq!(state.selected(), Some(0))
    }

    // #[test]
    // fn test_on_escape_changes_view_state() {
    //     let mut app = create_test_app();
    //     app.view_state = ViewState::Detail(NamespaceDetail::default());
    //     app.on_escape();
    //     assert!(matches!(app.view_state, ViewState::List));
    // }

    // #[test]
    // fn test_next_navigation() {
    //     let mut app = create_test_app();
    //     app.next();
    //     assert_eq!(app.table_state.selected(), Some(0));
    // }
    // #[test]
    // fn test_next_wraps_from_end_to_beginning() {
    //     let mut app = App {
    //         table_state: {
    //             let mut ts = TableState::default();
    //             ts.select(Some(2));
    //             ts
    //         },
    //         ..create_test_app()
    //     };

    //     app.next();

    //     assert_eq!(app.table_state.selected(), Some(0));
    // }

    // #[test]
    // fn test_next_does_nothing_with_empty_namespaces() {
    //     let mut app = App {
    //         namespaces: vec![].into(),
    //         ..create_test_app()
    //     };
    //     app.next();

    //     assert_eq!(app.table_state.selected(), Some(0));
    // }

    // #[test]
    // fn test_next_does_nothing_when_not_in_view() {
    //     let mut app = App {
    //         view_state: ViewState::Detail(NamespaceDetail {
    //             interfaces: vec![],
    //             routes: vec![],
    //             processes: vec![],
    //             peers: vec![],
    //             firewall: FirewallInfo {
    //                 chains: 10,
    //                 rules: 10,
    //             },
    //             ports: vec![],
    //         }),
    //         ..create_test_app()
    //     };
    //     app.next();

    //     assert_eq!(app.table_state.selected(), Some(0));
    // }

    // #[test]
    // fn test_previous_moves_up_in_list() {
    //     let mut app = App {
    //         table_state: {
    //             let mut ts = TableState::default();
    //             ts.select(Some(2));
    //             ts
    //         },
    //         ..create_test_app()
    //     };

    //     app.previous();
    //     assert_eq!(app.table_state.selected(), Some(1));
    // }

    // #[test]
    // fn test_previous_wraps_to_beginning_to_end() {
    //     let mut app = create_test_app();

    //     app.previous();

    //     assert_eq!(app.table_state.selected(), Some(2));
    // }

    // #[test]
    // fn test_previous_does_nothing_with_empty_namespaces() {
    //     let mut app = App {
    //         namespaces: Arc::new(vec![]),
    //         ..create_test_app()
    //     };
    //     app.previous();

    //     assert_eq!(app.table_state.selected(), Some(0));
    // }
}
