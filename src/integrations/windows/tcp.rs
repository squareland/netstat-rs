use integrations::windows::ffi::*;
use std;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use types::*;

pub unsafe fn collect_tcp_sockets_info(
    address_family: ULONG,
    results: &mut Vec<SocketInfo>,
) -> Result<(), Error> {
    let mut buffer_size: DWORD = 0;
    let mut err_code = GetExtendedTcpTable(
        std::ptr::null_mut(),
        &mut buffer_size,
        FALSE,
        address_family,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    );
    let mut buffer = Vec::<u8>::new();
    let mut iterations = 0;
    while err_code == ERROR_INSUFFICIENT_BUFFER {
        buffer = Vec::<u8>::with_capacity(buffer_size as usize);
        err_code = GetExtendedTcpTable(
            buffer.as_mut_ptr() as PVOID,
            &mut buffer_size,
            FALSE,
            address_family,
            TCP_TABLE_OWNER_PID_ALL,
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
                let table_ref = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let rows_count = table_ref.rows_count as usize;
                let row_ptr = &table_ref.rows[0] as *const MIB_TCPROW_OWNER_PID;
                for i in 0..rows_count {
                    let row = &*row_ptr.offset(i as isize);
                    results.push(SocketInfo {
                        protocol_socket_info: ProtocolSocketInfo::Tcp(TcpSocketInfo {
                            local_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.local_addr))),
                            local_port: u16::from_be(row.local_port as u16),
                            remote_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.remote_addr))),
                            remote_port: u16::from_be(row.remote_port as u16),
                            state: TcpState::from(row.state),
                        }),
                        associated_pids: vec![row.owning_pid],
                    });
                }
            }
            AF_INET6 => {
                let table_ref = &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
                let rows_count = table_ref.rows_count as usize;
                let row_ptr = &table_ref.rows[0] as *const MIB_TCP6ROW_OWNER_PID;
                for i in 0..rows_count {
                    let row = &*row_ptr.offset(i as isize);
                    results.push(SocketInfo {
                        protocol_socket_info: ProtocolSocketInfo::Tcp(TcpSocketInfo {
                            local_addr: IpAddr::V6(Ipv6Addr::from(row.local_addr)),
                            // local_scope: Option::Some(row.local_scope_id),
                            local_port: u16::from_be(row.local_port as u16),
                            remote_addr: IpAddr::V6(Ipv6Addr::from(row.remote_addr)),
                            // remote_scope: Option::Some(row.remote_scope_id),
                            remote_port: u16::from_be(row.remote_port as u16),
                            state: TcpState::from(row.state),
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
            api_name: "GetExtendedTcpTable",
            err_code: err_code as i32,
        });
    }
}
