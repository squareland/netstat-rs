use std::net::IpAddr;
use types::tcp_state::TcpState;

/// General socket information.
#[derive(Clone, Debug)]
pub struct SocketInfo {
    /// Protocol-specific socket information.
    pub protocol_socket_info: ProtocolSocketInfo,
    /// Identifiers of processes associated with this socket.
    pub associated_pids: Vec<u32>,
    #[cfg(target_os = "linux")]
    pub inode: u32,
}

/// Protocol-specific socket information.
#[derive(Clone, Debug)]
pub enum ProtocolSocketInfo {
    /// TCP-specific socket information.
    Tcp(TcpSocketInfo),
    /// UDP-specific socket information.
    Udp(UdpSocketInfo),
}

/// TCP-specific socket information.
#[derive(Clone, Debug)]
pub struct TcpSocketInfo {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub state: TcpState,
}

/// UDP-specific socket information.
#[derive(Clone, Debug)]
pub struct UdpSocketInfo {
    pub local_addr: IpAddr,
    pub local_port: u16,
}
