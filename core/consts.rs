pub const C25519_PRIM_L: usize = 32;
pub const PK_L: usize = C25519_PRIM_L;
pub const SK_L: usize = C25519_PRIM_L;
pub const XK_L: usize = C25519_PRIM_L;
pub const HASH_L: usize = C25519_PRIM_L;
pub const XSIG_L: usize = C25519_PRIM_L;
pub const EDSIG_L: usize = C25519_PRIM_L + C25519_PRIM_L;
pub const CONN_K_L: usize = XK_L;
pub const REQ_K_L: usize = XK_L;

pub const SEED_L: usize = 64;
pub const MAC_L: usize = 32;

pub const TS_L: usize = 8;
pub const KEYTYPE_L: usize = 2;
pub const UID_L: usize = 8;
pub const REQ_ID_L: usize = 2;
pub const FR_LEN_L: usize = 2;
pub const MSG_ID_L: usize = 2;
pub const FR_ID_L: usize = 2;
pub const FR_L_MAX: usize = 0x10000;

pub const CHELLO_L: usize = /*CX*/PK_L;
pub const SIGNED_PKINFO_L: usize = TS_L + KEYTYPE_L + PK_L + EDSIG_L;
pub const SHELLO_AHEAD_L: usize = /*SX*/PK_L;
pub const SHELLO_BEHIND_L: usize = /*S*/SIGNED_PKINFO_L;
pub const SHELLO_L: usize = SHELLO_AHEAD_L + SHELLO_BEHIND_L;
pub const CLOGIN_L: usize = /*C*/SIGNED_PKINFO_L;
pub const SLOGINV_L: usize = UID_L + EDSIG_L;
pub const FR_AHEAD_HEADER_L: usize = REQ_ID_L + FR_LEN_L + /*HEADER*/MAC_L;
pub const FR_BEHIND_HEADER_L: usize = /*PAYLOAD*/MAC_L + MSG_ID_L + FR_ID_L;
pub const FR_HEADER_L: usize = FR_AHEAD_HEADER_L + FR_BEHIND_HEADER_L;
pub const FR_PAYLOAD_L_MAX: usize = FR_L_MAX - FR_HEADER_L;

pub const MAX_LATENCY: i64 = 3;

/// equivalent to `crate::cshake::HANDSHAKE_PRE_MASK.once_to_array(&[])`
pub const HANDSHAKE_PRE_MASK_BYTES: [u8; PK_L] = [
    0x50, 0xa2, 0x9a, 0x88, 0x3b, 0x5b, 0x87, 0x05, 0x15, 0x4d, 0x0e, 0x70, 0x81, 0xec, 0x6d, 0x23,
    0x8d, 0xf9, 0x36, 0x3d, 0x5f, 0x0a, 0x0f, 0x5e, 0x6d, 0x73, 0xc9, 0x2f, 0x41, 0x7a, 0x09, 0xb1,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_pre_mask() {
        use crate::cshake::{CShakeCustom, HANDSHAKE_PRE_MASK};
        assert_eq!(HANDSHAKE_PRE_MASK.custom_string(), "__bcsp__HANDSHAKE_PRE_MASK".as_bytes());
        assert_eq!(HANDSHAKE_PRE_MASK_BYTES, HANDSHAKE_PRE_MASK.once_to_array(&[]));
    }

    #[test]
    fn message_len() {
        use foundations::byterepr::ByteRepr;
        const _: () = assert!(SIGNED_PKINFO_L == crate::PKInfo::SIZE);
        const _: () = assert!(SLOGINV_L == crate::LoginVerify::SIZE);
    }
}
