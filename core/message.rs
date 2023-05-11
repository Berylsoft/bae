use foundations::byterepr_structs;
use crate::{curve25519::{XPK, PK, EdLikeSignature}, consts::MAC_L};

byterepr_structs! {
    pub struct ClientHello {
        pub cxpk: XPK,
    }

    pub struct ServerHello {
        pub sxpk: XPK,
        pub ts: i64,
        pub spk: PK,
        pub sig: EdLikeSignature,
    }

    pub struct ClientLogin {
        pub ts: i64,
        pub keytype: u16,
        pub cpk: PK,
        pub sig: EdLikeSignature,
    }

    pub struct ServerLoginVerify {
        pub uid: u64,
        pub sig: EdLikeSignature,
    }

    pub struct FrameAheadHeader {
        pub req_id: u16,
        pub frame_len: u16,
        pub mac: [u8; MAC_L],
    }

    pub struct FrameBehindHeader {
        pub mac: [u8; MAC_L],
        pub msg_id: u16,
        pub frame_id: u16,
    }
}
