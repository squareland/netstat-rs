use integrations::windows::ffi::*;
use std;

pub type BOOL = std::os::raw::c_int;
pub const FALSE: BOOL = 0;

pub type TCP_TABLE_CLASS = DWORD;
pub const TCP_TABLE_OWNER_PID_ALL: TCP_TABLE_CLASS = 5;

pub type MIB_TCP_STATE = DWORD;
pub const MIB_TCP_STATE_CLOSED: MIB_TCP_STATE = 1;
pub const MIB_TCP_STATE_LISTEN: MIB_TCP_STATE = 2;
pub const MIB_TCP_STATE_SYN_SENT: MIB_TCP_STATE = 3;
pub const MIB_TCP_STATE_SYN_RCVD: MIB_TCP_STATE = 4;
pub const MIB_TCP_STATE_ESTAB: MIB_TCP_STATE = 5;
pub const MIB_TCP_STATE_FIN_WAIT1: MIB_TCP_STATE = 6;
pub const MIB_TCP_STATE_FIN_WAIT2: MIB_TCP_STATE = 7;
pub const MIB_TCP_STATE_CLOSE_WAIT: MIB_TCP_STATE = 8;
pub const MIB_TCP_STATE_CLOSING: MIB_TCP_STATE = 9;
pub const MIB_TCP_STATE_LAST_ACK: MIB_TCP_STATE = 10;
pub const MIB_TCP_STATE_TIME_WAIT: MIB_TCP_STATE = 11;
pub const MIB_TCP_STATE_DELETE_TCB: MIB_TCP_STATE = 12;

pub type UDP_TABLE_CLASS = DWORD;
pub const UDP_TABLE_OWNER_PID: UDP_TABLE_CLASS = 1;

pub type ERROR_CODE = DWORD;
pub const NO_ERROR: ERROR_CODE = 0;
pub const ERROR_INSUFFICIENT_BUFFER: ERROR_CODE = 0x7A;

pub const AF_INET: ULONG = 2;
pub const AF_INET6: ULONG = 23;
