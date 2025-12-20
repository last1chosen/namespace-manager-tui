mod interfaces_widget;
mod listening_ports_widget;
mod nftables_widget;
mod routing_table_widget;
mod subnet_peers_widget;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
};

use interfaces_widget::make_interfaces_widget;
use listening_ports_widget::make_listening_ports_widget;
use nftables_widget::make_nftables_widget;
use routing_table_widget::make_routing_table_widget;
use subnet_peers_widget::make_subnet_peers;

use crate::models::{DetailState, NamespaceDetail};

pub fn render_network_tab(
    f: &mut Frame,
    state: &mut DetailState,
    info: &NamespaceDetail,
    area: Rect,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8), // Interfaces
            Constraint::Length(8), // Routes & Ports
            Constraint::Min(4),    // Firewall & Peers
        ])
        .split(area);

    f.render_stateful_widget(
        make_interfaces_widget(&info.interfaces, state.focus),
        chunks[0],
        &mut state.interfaces,
    );

    let mid_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    f.render_stateful_widget(
        make_routing_table_widget(&info.routes, state.focus),
        mid_row[0],
        &mut state.routes,
    );
    f.render_stateful_widget(
        make_listening_ports_widget(&info.ports, state.focus),
        mid_row[1],
        &mut state.ports,
    );

    let bottom_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[2]);

    f.render_widget(make_nftables_widget(&info.firewall), bottom_row[0]);

    f.render_widget(make_subnet_peers(info), bottom_row[1]);
}
