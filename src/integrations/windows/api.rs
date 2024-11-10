use integrations::windows::ffi::*;
use integrations::windows::tcp::*;
use integrations::windows::udp::*;
use types::*;

/// Returns a vector of active sockets of specified address families and protocols.
pub fn get_sockets_info(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> Result<Vec<SocketInfo>, Error> {
    unsafe {
        let mut results = Vec::new();
        let ipv4 = af_flags.contains(AddressFamilyFlags::IPV4);
        let ipv6 = af_flags.contains(AddressFamilyFlags::IPV6);
        let tcp = proto_flags.contains(ProtocolFlags::TCP);
        let udp = proto_flags.contains(ProtocolFlags::UDP);
        if ipv4 {
            if tcp {
                collect_tcp_sockets_info(AF_INET, &mut results)?;
            }
            if udp {
                collect_udp_sockets_info(AF_INET, &mut results)?;
            }
        }
        if ipv6 {
            if tcp {
                collect_tcp_sockets_info(AF_INET6, &mut results)?;
            }
            if udp {
                collect_udp_sockets_info(AF_INET6, &mut results)?;
            }
        }
        Result::Ok(results)
    }
}
