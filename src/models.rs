use ratatui::widgets::{ListState, TableState};

#[derive(Debug, Clone, PartialEq)]
pub enum NamespaceType {
    Container,
    Vpn,
    Regular,
}
#[derive(Debug)]
pub struct NetworkNamespace {
    pub name: String,
    pub ns_type: NamespaceType,
    pub inode: u64,
    pub ns_path: String,
    pub num_interfaces: usize,
    pub process_names: Vec<String>,
    pub primary_pid: Option<u32>,

    pub ip_prefixes: Vec<String>,
}

#[derive(Debug, Default)]
pub struct NamespaceDetail {
    pub interfaces: Vec<InterfaceInfo>,
    pub routes: Vec<RouteInfo>,
    pub processes: Vec<ProcessInfo>,
    pub firewall: FirewallInfo,
    pub ports: Vec<ListeningPort>,
    pub peers: Vec<PeerInfo>,
}

#[derive(Debug, Default)]
pub struct InterfaceInfo {
    pub name: String,
    pub ip: String,
    pub state: String,
    pub mtu: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Default)]
pub struct RouteInfo {
    pub dst: String,
    pub gateway: String,
    pub dev: String,
}

#[derive(Debug, Default, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub env_vars: Vec<String>,
}

#[derive(Debug, Default)]
pub struct FirewallInfo {
    pub chains: usize,
    pub rules: usize,
}

#[derive(Debug, Default)]
pub struct ListeningPort {
    pub proto: String,
    pub addr: String,
    pub port: String,
}

#[derive(Debug, Default)]
pub struct PeerInfo {
    pub name: String,
    pub _ip: String, // Not used yet, we only render the name in the subnet peer widget
    pub _inode: u64, // Not used yet, we only render the name in the subnet peer widget
}

#[derive(Debug)]
pub enum DetailTab {
    Network,
    Internals,
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum DetailSection {
    Interfaces,
    Routes,
    Ports,
    Processes,
    EnvVars,
}

#[derive(Debug)]
pub struct DetailState {
    pub focus: DetailSection,
    pub interfaces: TableState,
    pub routes: TableState,
    pub ports: TableState,
    pub processes: ListState,
    pub active_tab: DetailTab,
    pub env_vars: TableState,

    pub filter_input: String,
    pub is_typing_filter: bool,
}

impl Default for DetailState {
    fn default() -> Self {
        Self {
            focus: DetailSection::Processes,
            interfaces: TableState::default(),
            routes: TableState::default(),
            ports: TableState::default(),
            processes: ListState::default(),

            active_tab: DetailTab::Network,
            env_vars: TableState::default(),

            filter_input: String::new(),
            is_typing_filter: false,
        }
    }
}
