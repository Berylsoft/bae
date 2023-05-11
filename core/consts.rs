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
pub const SHELLO_AHEAD_L: usize = /*SX*/PK_L;
pub const SHELLO_BEHIND_L: usize = TS_L + /*S*/PK_L + EDSIG_L;
pub const SHELLO_L: usize = SHELLO_AHEAD_L + SHELLO_BEHIND_L;
pub const CLOGIN_L: usize = TS_L + KEYTYPE_L + /*C*/PK_L + EDSIG_L;
pub const SLOGINV_L: usize = UID_L + EDSIG_L;
pub const FR_AHEAD_HEADER_L: usize = REQ_ID_L + FR_LEN_L + /*HEADER*/MAC_L;
pub const FR_BEHIND_HEADER_L: usize = /*PAYLOAD*/MAC_L + MSG_ID_L + FR_ID_L;
pub const FR_HEADER_L: usize = FR_AHEAD_HEADER_L + FR_BEHIND_HEADER_L;
pub const FR_PAYLOAD_L_MAX: usize = FR_L_MAX - FR_HEADER_L;

/// equivalent to `crate::cshake::HANDSHAKE_PRE_MASK.create().once_to_array(&[])`
pub const HANDSHAKE_PRE_MASK: [u8; PK_L] = [
    0x37, 0x7e, 0x55, 0x62, 0x1b, 0xeb, 0x5a, 0xb4, 0x0f, 0xf5, 0xf3, 0xca, 0x42, 0xcf, 0x4e, 0x64,
    0x10, 0xce, 0xdf, 0xac, 0x3a, 0x56, 0xdb, 0x48, 0xa6, 0x3b, 0x02, 0x08, 0xf6, 0x5a, 0x4e, 0xff,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_pre_mask() {
        assert_eq!(HANDSHAKE_PRE_MASK, crate::cshake::HANDSHAKE_PRE_MASK.create().once_to_array(&[]))
    }
}
