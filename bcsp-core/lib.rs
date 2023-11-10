pub mod consts;
pub mod cshake_customs;

use std::{sync::Arc, collections::BTreeMap, num::NonZeroU16};
use zeroize::Zeroize;
use foundations::{byterepr::ByteRepr, xor::xor_array, now::now_raw, timestamp, byterepr_structs};
use bae_core::{cshake::*, curve25519::*, cshake_customs::*};
use crate::{consts::*, cshake_customs::*};

byterepr_structs! {
    pub struct PKInfoInner {
        pub ts: i64,
        pub keytype: u16,
        pub pk: PK,
    }

    pub struct PKInfo {
        pub inner: PKInfoInner,
        pub sig: EdLikeSignature,
    }

    pub struct LoginVerify {
        pub uid: u64,
        pub sig: EdLikeSignature,
    }
}

pub fn xpk_from_masked(mut bytes: [u8; PK_L]) -> XPK {
    xor_array(&mut bytes, &HANDSHAKE_PRE_MASK_BYTES);
    XPK::from_bytes(bytes)
}

pub fn xpk_to_masked(xpk: &XPK) -> [u8; PK_L] {
    let mut bytes = xpk.to_bytes();
    xor_array(&mut bytes, &HANDSHAKE_PRE_MASK_BYTES);
    bytes
}

macro_rules! crypto_byterepr {
    ($($ty:ty => $custom:ty)*) => {$(
        impl $ty {
            pub fn decrypt(mut bytes: <Self as ByteRepr>::Bytes, cipher: &mut CShake<$custom>) -> Self {
                cipher.squeeze_xor(&mut bytes);
                Self::from_bytes(bytes)
            }

            pub fn encrypt(&self, cipher: &mut CShake<$custom>) -> <Self as ByteRepr>::Bytes {
                let mut bytes = self.to_bytes();
                cipher.squeeze_xor(&mut bytes);
                bytes
            }
        }
    )*};
}

crypto_byterepr!(
    PKInfo => HANDSHAKE_CIPHER
    LoginVerify => HANDSHAKE_CIPHER
);

struct SKInfo {
    keytype: u16,
    sk: SK,
}

impl SKInfo {
    fn create_pkinfo(&self, ts: i64) -> PKInfo {
        let inner = PKInfoInner {
            ts,
            keytype: self.keytype,
            pk: self.sk.pk(),
        };
        let sig = self.sk.edlike_sign(&inner.to_bytes());
        PKInfo { inner, sig }
    }

    fn create_login_verify(&self, uid: u64) -> LoginVerify {
        let sig = self.sk.edlike_sign(&uid.to_bytes());
        LoginVerify { uid, sig }
    }
}

pub struct ClientConnector {
    csk: Arc<SKInfo>,
    dh_rng: CShake<DH_SK_GEN_PRNG>,
}

pub struct ServerConnector {
    ssk: Arc<SKInfo>,
    dh_rng: CShake<DH_SK_GEN_PRNG>,
}

pub struct ClientBuilderA {
    csk: Arc<SKInfo>,
    spk: PK,
    cxsk: XSK,
}

pub struct ClientBuilderB {
    spk: PK,
    conn_key: ExchangedSecret,
    handshake_cipher: CShake<HANDSHAKE_CIPHER>,
}

pub struct ServerBuilder {
    ssk: Arc<SKInfo>,
    conn_key: ExchangedSecret,
    handshake_cipher: CShake<HANDSHAKE_CIPHER>,
}

impl ClientConnector {
    pub fn init(keytype: u16, csk: [u8; SK_L], seed: &[u8; SEED_L]) -> ClientConnector {
        ClientConnector {
            csk: Arc::new(SKInfo { keytype, sk: SK::from_key(csk) }),
            dh_rng: DH_SK_GEN_PRNG.create().chain_absorb(seed),
        }
    }
}

impl ServerConnector {
    pub fn init(keytype: u16, ssk: [u8; SK_L], seed: &[u8; SEED_L]) -> ServerConnector {
        ServerConnector {
            ssk: Arc::new(SKInfo { keytype, sk: SK::from_key(ssk) }),
            dh_rng: DH_SK_GEN_PRNG.create().chain_absorb(seed),
        }
    }
}

impl ClientConnector {
    pub fn connect(&mut self, spk: [u8; PK_L]) -> (ClientBuilderA, [u8; CHELLO_L]) {
        let csk = self.csk.clone();
        let spk = PK::from_bytes(spk);

        let cxsk = XSK::generate(&mut self.dh_rng);
        let cxpk = cxsk.pk();
        let output = xpk_to_masked(&cxpk);

        (ClientBuilderA { csk, spk, cxsk }, output)
    }
}

impl ServerConnector {
    pub fn accept(&mut self, input: [u8; CHELLO_L]) -> (ServerBuilder, [u8; SHELLO_L]) {
        let (ts, _) = timestamp::from_now_raw(now_raw());

        let ssk = self.ssk.clone();

        let cxpk = xpk_from_masked(input);
        let sxsk = XSK::generate(&mut self.dh_rng);
        let sxpk = xpk_to_masked(&sxsk.pk());
        let conn_key = sxsk.exchange(cxpk);
        let mut handshake_cipher = HANDSHAKE_CIPHER.create().chain_absorb(conn_key.as_bytes());

        let spki = self.ssk.create_pkinfo(ts).encrypt(&mut handshake_cipher);

        let mut output = [0; SHELLO_L];
        output[..SHELLO_AHEAD_L].copy_from_slice(&sxpk);
        output[SHELLO_AHEAD_L..].copy_from_slice(&spki);

        (ServerBuilder { ssk, conn_key, handshake_cipher }, output)
    }
}

impl ClientBuilderA {
    pub fn login(self, input: [u8; SHELLO_L]) -> (ClientBuilderB, [u8; CLOGIN_L]) {
        let (ts, _) = timestamp::from_now_raw(now_raw());

        let ClientBuilderA { csk, spk, cxsk } = self;

        let sxpk = xpk_from_masked(input[..SHELLO_AHEAD_L].try_into().unwrap());
        let conn_key = cxsk.exchange(sxpk);
        let mut handshake_cipher = HANDSHAKE_CIPHER.create().chain_absorb(conn_key.as_bytes());

        let spki_bytes = input[SHELLO_AHEAD_L..].try_into().unwrap();
        let spki = PKInfo::decrypt(spki_bytes, &mut handshake_cipher);
        assert!(spk == spki.inner.pk);
        assert!(spk.edlike_verify(&spki_bytes, &spki.sig));
        assert!(ts - spki.inner.ts <= MAX_LATENCY);

        let output = csk.create_pkinfo(ts).encrypt(&mut handshake_cipher);

        (ClientBuilderB { spk, conn_key, handshake_cipher }, output)
    }
}

impl ServerBuilder {
    pub fn login<F: FnOnce(PK) -> u64>(self, input: [u8; CLOGIN_L], find_uid: F) -> (ConnectionState, [u8; SLOGINV_L]) {
        let (ts, _) = timestamp::from_now_raw(now_raw());

        let ServerBuilder { ssk, conn_key, mut handshake_cipher } = self;

        let spk_info = PKInfo::decrypt(input, &mut handshake_cipher);
        assert!(spk_info.inner.pk.edlike_verify(&input, &spk_info.sig));
        assert!(ts - spk_info.inner.ts <= MAX_LATENCY);

        let uid = find_uid(spk_info.inner.pk);
        let output = ssk.create_login_verify(uid).encrypt(&mut handshake_cipher);

        (ConnectionState::init(ConnectionPeer::Server, uid, conn_key), output)
    }
}

impl ClientBuilderB {
    pub fn finish_login(self, input: [u8; SLOGINV_L]) -> ConnectionState {
        let ClientBuilderB { spk, conn_key, mut handshake_cipher } = self;

        let LoginVerify { uid, sig } = LoginVerify::decrypt(input, &mut handshake_cipher);
        spk.edlike_verify(&input, &sig);
        ConnectionState::init(ConnectionPeer::Client, uid, conn_key)
    }
}

byterepr_structs! {
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

pub struct HeaderState {
    cipher: CShake<FRAME_HEADER_CIPHER>,
    mac: CShake<FRAME_HEADER_MAC>,
}

pub struct RequestState {
    next_msg_id: u16,
    cipher: CShake<FRAME_PAYLOAD_CIPHER>,
    mac: CShake<FRAME_PAYLOAD_MAC>,
}

pub enum ConnectionPeer {
    Client,
    Server,
}

pub struct ConnectionState {
    peer: ConnectionPeer,
    uid: u64,
    conn_key: ExchangedSecret,
    req_key_deriver: CShake<REQ_KEY_DERIVE>,
    header: HeaderState,
    request: BTreeMap<NonZeroU16, RequestState>,
}

impl HeaderState {
    pub fn init(header_key: &[u8; REQ_K_L]) -> HeaderState {
        HeaderState {
            cipher: FRAME_HEADER_CIPHER.create().chain_absorb(header_key),
            mac: FRAME_HEADER_MAC.create().chain_absorb(header_key),
        }
    }
}

impl RequestState {
    pub fn init(req_key: &[u8; REQ_K_L]) -> RequestState {
        RequestState {
            next_msg_id: 0,
            cipher: FRAME_PAYLOAD_CIPHER.create().chain_absorb(req_key),
            mac: FRAME_PAYLOAD_MAC.create().chain_absorb(req_key),
        }
    }
}

impl ConnectionState {
    pub fn init(peer: ConnectionPeer, uid: u64, conn_key: ExchangedSecret) -> ConnectionState {
        let mut req_key_deriver = REQ_KEY_DERIVE.create().chain_absorb(conn_key.as_bytes());
        let mut header_key: [u8; REQ_K_L] = req_key_deriver.squeeze_to_array();
        let header = HeaderState::init(&header_key);
        header_key.zeroize();
        let request = BTreeMap::new();
        ConnectionState { peer, uid, conn_key, req_key_deriver, header, request }
    }

    pub fn send_message(&mut self, req_id: NonZeroU16, msg: &[u8]) -> Vec<Vec<u8>> {
        let ts = timestamp::from_now_raw(now_raw());
        let request = self.request.entry(req_id).or_insert_with(|| {
            let mut req_key = self.req_key_deriver.squeeze_to_array();
            let req = RequestState::init(&req_key);
            req_key.zeroize();
            req
        });
        let msg_len = msg.len();
        // TODO array chunk when stablized
        let chunks = msg.chunks_exact(FR_PAYLOAD_L_MAX);

        todo!()
    }
}
