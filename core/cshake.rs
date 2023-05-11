use keccak_core::{KeccakState, KeccakF};

pub struct CShake {
    ctx: KeccakState<KeccakF>,
    pub custom: CShakeCustom,
}

pub fn init(name: &[u8], custom_string: &[u8]) -> KeccakState<KeccakF> {
    use keccak_core::{bits_to_rate, DELIM_CSHAKE, DELIM_SHAKE};
    let rate = bits_to_rate(256);
    // if there is no name and no customization string
    // cSHAKE is SHAKE
    if name.is_empty() && custom_string.is_empty() {
        KeccakState::new(rate, DELIM_SHAKE)
    } else {
        let mut ctx = KeccakState::new(rate, DELIM_CSHAKE);
        ctx.absorb_len_left(rate);
        ctx.absorb_len_left(name.len() * 8);
        ctx.absorb(name);
        ctx.absorb_len_left(custom_string.len() * 8);
        ctx.absorb(custom_string);
        ctx.fill_block();
        ctx
    }
}

impl CShake {
    #[inline]
    pub fn absorb(&mut self, input: &[u8]) {
        self.ctx.absorb(input);
    }

    #[inline]
    pub fn chain_absorb(mut self, input: &[u8]) -> CShake {
        self.ctx.absorb(input);
        self
    }

    #[inline]
    pub fn squeeze(&mut self, output: &mut [u8]) {
        self.ctx.squeeze(output);
    }

    #[inline]
    pub fn squeeze_to_array<const N: usize>(&mut self) -> [u8; N] {
        let mut buf = [0; N];
        self.ctx.squeeze(&mut buf);
        buf
    }

    // pub fn squeeze_then_drop<const N: usize>(&mut self) {
    //     use zeroize::Zeroize;
    //     self.squeeze_to_array::<N>().zeroize()
    // }

    #[inline]
    pub fn once(mut self, input: &[u8], output: &mut [u8]) {
        self.ctx.absorb(input);
        self.ctx.squeeze(output);
    }

    #[inline]
    pub fn once_to_array<const N: usize>(mut self, input: &[u8]) -> [u8; N] {
        self.ctx.absorb(input);
        self.squeeze_to_array()
    }
}

// TODO: trait
#[allow(non_camel_case_types)]
pub enum CShakeCustom {
    DSA_SK_DERIVE        ,
    DSA_XSIGN_HASH       ,
    DSA_EDSIGN_R_HASH    ,
    DSA_EDSIGN_K_HASH    ,
    DH_RNG               ,
    HANDSHAKE_PRE_MASK   ,
    HANDSHAKE_CIPHER     ,
    REQ_KEY_DERIVER      ,
    FRAME_HEADER_CIPHER  ,
    FRAME_PAYLOAD_CIPHER ,
    FRAME_HEADER_MAC     ,
    FRAME_PAYLOAD_MAC    ,
}

pub use CShakeCustom::*;

impl CShakeCustom {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DSA_SK_DERIVE        => "__bcsp__dsa-sk-derive"        ,
            Self::DSA_XSIGN_HASH       => "__bcsp__dsa-xsign-hash"       ,
            Self::DSA_EDSIGN_R_HASH    => "__bcsp__dsa-edsign-r-hash"    ,
            Self::DSA_EDSIGN_K_HASH    => "__bcsp__dsa-edsign-k-hash"    ,
            Self::DH_RNG               => "__bcsp__dh-rng"               ,
            Self::HANDSHAKE_PRE_MASK   => "__bcsp__handshake-pre-mask"   ,
            Self::HANDSHAKE_CIPHER     => "__bcsp__handshake-cipher"     ,
            Self::REQ_KEY_DERIVER      => "__bcsp__req-key-deriver"      ,
            Self::FRAME_HEADER_CIPHER  => "__bcsp__frame-header-cipher"  ,
            Self::FRAME_PAYLOAD_CIPHER => "__bcsp__frame-payload-cipher" ,
            Self::FRAME_HEADER_MAC     => "__bcsp__frame-header-mac"     ,
            Self::FRAME_PAYLOAD_MAC    => "__bcsp__frame-payload-mac"    ,
        }
    }

    #[inline]
    pub fn create(self) -> CShake {
        CShake {
            ctx: init(&[], self.as_str().as_bytes()),
            custom: self
        }
    }
}
