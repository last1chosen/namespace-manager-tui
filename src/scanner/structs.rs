use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct IpAddrJson {
    pub ifname: String,
    pub operstate: String,
    pub mtu: u64,
    pub addr_info: Vec<AddrInfo>,
    pub stats64: Option<Stats64>,
}
#[derive(Deserialize)]
pub(super) struct AddrInfo {
    pub local: String,
    pub prefixlen: u32,
}
#[derive(Deserialize)]
pub(super) struct Stats64 {
    pub rx: ByteStat,
    pub tx: ByteStat,
}
#[derive(Deserialize)]
pub(super) struct ByteStat {
    pub bytes: u64,
}
#[derive(Deserialize)]
pub(super) struct IpRouteJson {
    pub dst: String,
    pub gateway: Option<String>,
    pub dev: Option<String>,
}
