use integrations::linux::ffi::*;
use libc::*;
use std;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use types::*;
use utils::*;

const TCPF_ALL: __u32 = 0xFFF;
const SOCKET_BUFFER_SIZE: size_t = 8192;

pub unsafe fn collect_sockets_info(
    family: __u8,
    protocol: __u8,
    results: &mut Vec<SocketInfo>,
) -> Result<(), Error> {
    let mut recv_buf = [0u8; SOCKET_BUFFER_SIZE as usize];
    let nl_sock = socket(AF_NETLINK as i32, SOCK_DGRAM, NETLINK_INET_DIAG);
    send_diag_msg(nl_sock, family, protocol)?;
    let buf_ptr = &mut recv_buf[0] as *mut u8 as *mut c_void;
    loop {
        let mut numbytes = recv(nl_sock, buf_ptr, SOCKET_BUFFER_SIZE, 0);
        let mut nlh = buf_ptr as *const u8 as *const nlmsghdr;
        while NLMSG_OK!(nlh, numbytes) {
            if (&*nlh).nlmsg_type == NLMSG_DONE as u16 {
                return try_close(nl_sock);
            }
            if (&*nlh).nlmsg_type == NLMSG_ERROR as u16 {
                try_close(nl_sock);
                // TODO: parse error code from msg properly
                // https://www.infradead.org/~tgr/libnl/doc/core.html#core_errmsg
                return Result::Err(Error::InternalError(
                    "Found netlink message with nlmsg_type == NLMSG_ERROR.",
                ));
            }
            let diag_msg = NLMSG_DATA!(nlh) as *const inet_diag_msg;
            let rtalen = (&*nlh).nlmsg_len as usize - NLMSG_LENGTH!(size_of::<inet_diag_msg>());
            parse_diag_msg(&*diag_msg, protocol, rtalen, results);
            nlh = NLMSG_NEXT!(nlh, numbytes);
        }
    }
}

unsafe fn send_diag_msg(sockfd: c_int, family: __u8, protocol: __u8) -> Result<(), Error> {
    let mut sa: sockaddr_nl = std::mem::uninitialized();
    sa.nl_family = AF_NETLINK as sa_family_t;
    sa.nl_pid = 0;
    sa.nl_groups = 0;
    let mut conn_req = inet_diag_req_v2 {
        family: family,
        protocol: protocol,
        ext: 1 << (INET_DIAG_INFO - 1),
        pad: 0,
        states: TCPF_ALL,
        id: Default::default(),
    };
    let mut nlh = nlmsghdr {
        nlmsg_len: NLMSG_LENGTH!(size_of::<inet_diag_req_v2>()) as __u32,
        nlmsg_type: SOCK_DIAG_BY_FAMILY,
        nlmsg_flags: (NLM_F_DUMP | NLM_F_REQUEST) as u16,
        nlmsg_seq: 0,
        nlmsg_pid: 0,
    };
    let mut iov = [
        iovec {
            iov_base: &mut nlh as *mut _ as *mut c_void,
            iov_len: size_of::<nlmsghdr>() as size_t,
        },
        iovec {
            iov_base: &mut conn_req as *mut _ as *mut c_void,
            iov_len: size_of::<inet_diag_req_v2>() as size_t,
        },
    ];
    let msg = msghdr {
        msg_name: &mut sa as *mut _ as *mut c_void,
        msg_namelen: size_of::<sockaddr_nl>() as c_uint,
        msg_iov: &mut iov[0],
        msg_iovlen: 2,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    match sendmsg(sockfd, &msg, 0) {
        -1 => Result::Err(Error::ForeignError {
            api_name: "sendmsg",
            err_code: get_raw_os_error(),
        }),
        _ => Result::Ok(()),
    }
}

unsafe fn parse_diag_msg(
    diag_msg: &inet_diag_msg,
    protocol: __u8,
    rtalen: usize,
    results: &mut Vec<SocketInfo>,
) {
    let src_port = u16::from_be(diag_msg.id.sport);
    let dst_port = u16::from_be(diag_msg.id.dport);
    let src_ip = parse_ip(diag_msg.family, &diag_msg.id.src);
    let dst_ip = parse_ip(diag_msg.family, &diag_msg.id.dst);
    match protocol as i32 {
        IPPROTO_TCP => {
            results.push(SocketInfo {
                protocol_socket_info: ProtocolSocketInfo::Tcp(TcpSocketInfo {
                    local_addr: src_ip,
                    local_port: src_port,
                    remote_addr: dst_ip,
                    remote_port: dst_port,
                    state: parse_tcp_state(diag_msg, rtalen),
                }),
                associated_pids: Vec::with_capacity(0),
                inode: diag_msg.inode,
            });
        }
        IPPROTO_UDP => results.push(SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Udp(UdpSocketInfo {
                local_addr: src_ip,
                local_port: src_port,
            }),
            associated_pids: Vec::with_capacity(0),
            inode: diag_msg.inode,
        }),
        _ => panic!("Unknown protocol!"),
    }
}

unsafe fn parse_ip(family: u8, bytes: &[__be32; 4]) -> IpAddr {
    match family as i32 {
        AF_INET => IpAddr::V4(Ipv4Addr::from(
            *(&bytes[0] as *const __be32 as *const [u8; 4]),
        )),
        AF_INET6 => IpAddr::V6(Ipv6Addr::from(
            *(bytes as *const [__be32; 4] as *const u8 as *const [u8; 16]),
        )),
        _ => panic!("Unknown family!"),
    }
}

unsafe fn parse_tcp_state(diag_msg: &inet_diag_msg, rtalen: usize) -> TcpState {
    let mut len = rtalen as isize;
    let mut attr = (diag_msg as *const inet_diag_msg).offset(1) as *const rtattr;
    while RTA_OK!(attr, len) {
        if (&*attr).rta_type == INET_DIAG_INFO as u16 {
            let tcpi = &*(RTA_DATA!(attr) as *const tcp_info);
            return TcpState::from(tcpi.state);
        }
        attr = RTA_NEXT!(attr, len);
    }
    panic!("Tcp state not found!");
}

unsafe fn try_close(sockfd: c_int) -> Result<(), Error> {
    match close(sockfd) {
        -1 => Result::Err(Error::ForeignError {
            api_name: "close",
            err_code: get_raw_os_error(),
        }),
        _ => Result::Ok(()),
    }
}
