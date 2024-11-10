use integrations::windows::ffi::*;
use std;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use types::*;

pub unsafe fn collect_udp_sockets_info(
    address_family: ULONG,
    bindings: &mut Vec<SocketInfo>,
) -> Result<(), Error> {
    let mut buffer_size: DWORD = 0;
    let mut err_code = GetExtendedUdpTable(
        std::ptr::null_mut(),
        &mut buffer_size,
        FALSE,
        address_family,
        UDP_TABLE_OWNER_PID,
        0,
    );
    let mut buffer = Vec::<u8>::new();
    let mut iterations = 0;
    while err_code == ERROR_INSUFFICIENT_BUFFER {
        buffer = Vec::<u8>::with_capacity(buffer_size as usize);
        err_code = GetExtendedUdpTable(
            buffer.as_mut_ptr() as PVOID,
            &mut buffer_size,
            FALSE,
            address_family,
            UDP_TABLE_OWNER_PID,
            0,
        );
        iterations += 1;
        if iterations > 100 {
            return Result::Err(Error::InternalError(
                "Failed to allocate buffer for GetExtendedTcpTable!",
            ));
        }
    }
    if err_code == NO_ERROR {
        match address_family {
            AF_INET => {
                let table_ref = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                let rows_count = table_ref.rows_count as usize;
                let row_ptr = &table_ref.rows[0] as *const MIB_UDPROW_OWNER_PID;
                for i in 0..rows_count {
                    let row = &*row_ptr.offset(i as isize);
                    bindings.push(SocketInfo {
                        protocol_socket_info: ProtocolSocketInfo::Udp(UdpSocketInfo {
                            local_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.local_addr))),
                            local_port: u16::from_be(row.local_port as u16),
                        }),
                        associated_pids: vec![row.owning_pid],
                    });
                }
            }
            AF_INET6 => {
                let table_ref = &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
                let rows_count = table_ref.rows_count as usize;
                let row_ptr = &table_ref.rows[0] as *const MIB_UDP6ROW_OWNER_PID;
                for i in 0..rows_count {
                    let row = &*row_ptr.offset(i as isize);
                    bindings.push(SocketInfo {
                        protocol_socket_info: ProtocolSocketInfo::Udp(UdpSocketInfo {
                            local_addr: IpAddr::V6(Ipv6Addr::from(row.local_addr)),
                            // local_scope: Option::Some(row.local_scope_id),
                            local_port: u16::from_be(row.local_port as u16),
                        }),
                        associated_pids: vec![row.owning_pid],
                    });
                }
            }
            _ => panic!("Unknown address family!"),
        }
        return Result::Ok(());
    } else {
        return Result::Err(Error::ForeignError {
            api_name: "GetExtendedUdpTable",
            err_code: err_code as i32,
        });
    }
}
