///|
/// Transport-layer message numbers (RFC 4250 section 4.1.2, RFC 4253) and
/// disconnect reason codes (RFC 4250 section 4.2.2). See docs/02 section 8.

///|
pub const SSH_MSG_DISCONNECT : Byte = 1

///|
pub const SSH_MSG_IGNORE : Byte = 2

///|
pub const SSH_MSG_UNIMPLEMENTED : Byte = 3

///|
pub const SSH_MSG_DEBUG : Byte = 4

///|
pub const SSH_MSG_SERVICE_REQUEST : Byte = 5

///|
pub const SSH_MSG_SERVICE_ACCEPT : Byte = 6

///|
/// RFC 8308; we ignore it on receive.
pub const SSH_MSG_EXT_INFO : Byte = 7

///|
pub const SSH_MSG_KEXINIT : Byte = 20

///|
pub const SSH_MSG_NEWKEYS : Byte = 21

///|
pub const SSH_MSG_KEX_ECDH_INIT : Byte = 30

///|
pub const SSH_MSG_KEX_ECDH_REPLY : Byte = 31

///|
pub const SSH_DISCONNECT_PROTOCOL_ERROR : UInt = 2

///|
pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED : UInt = 3

///|
pub const SSH_DISCONNECT_MAC_ERROR : UInt = 5

///|
pub const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE : UInt = 7

///|
pub const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE : UInt = 14
