use zeroize::Zeroize;
use foundations::xor::{xor_array, xor};
use keccak_core::{KeccakState, KeccakF};

pub struct CShake<C: CShakeCustom> {
    ctx: KeccakState<KeccakF>,
    custom: C,
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

impl<C: CShakeCustom> CShake<C> {
    #[inline]
    pub fn custom(&self) -> &C {
        &self.custom
    }

    #[inline]
    pub fn absorb(&mut self, input: &[u8]) {
        self.ctx.absorb(input);
    }

    #[inline]
    pub fn chain_absorb(mut self, input: &[u8]) -> CShake<C> {
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

    #[inline]
    pub fn squeeze_to_vec(&mut self, len: usize) -> Vec<u8> {
        // TODO use MaybeUninit
        let mut buf = vec![0; len];
        self.ctx.squeeze(&mut buf);
        buf
    }

    // TODO(below 3 methods): necessary to zeroize?
    // TODO(below 5 methods): inline?

    #[inline]
    pub fn skip<const N: usize>(&mut self) {
        self.squeeze_to_array::<N>().zeroize()
    }

    #[inline]
    pub fn squeeze_xor_array<const N: usize>(&mut self, dest: &mut [u8; N]) {
        let mut mask = self.squeeze_to_array();
        xor_array(dest, &mask);
        mask.zeroize();
    }

    #[inline]
    pub fn squeeze_xor_slice(&mut self, dest: &mut [u8]) {
        let mut mask = self.squeeze_to_vec(dest.len());
        // hardcode inline without reslicing because no need to check
        xor(dest, &mask);
        mask.zeroize();
    }

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

    #[inline]
    pub fn squeeze_to_ctx<const N: usize, C2: CShakeCustom>(&mut self, custom: C2) -> CShake<C2> {
        let mut buf = self.squeeze_to_array::<N>();
        let ctx = custom.create().chain_absorb(&buf);
        buf.zeroize();
        ctx
    }
}

pub trait CShakeCustom: Sized {
    const CUSTOM_STRING: &'static str;

    #[inline]
    fn create(self) -> CShake<Self> {
        CShake {
            ctx: init(&[], Self::CUSTOM_STRING.as_bytes()),
            custom: self,
        }
    }
}

macro_rules! cshake_customs {
    ($($name:ident)*) => {$(
        #[allow(non_camel_case_types)]
        pub struct $name;

        impl CShakeCustom for $name {
            const CUSTOM_STRING: &'static str = concat!("__bcsp__", stringify!($name));
        }
    )*};
}

cshake_customs! {
    DSA_SK_DERIVE
    DSA_XSIGN_HASH
    DSA_EDSIGN_R_HASH
    DSA_EDSIGN_K_HASH
    DH_SK_GEN_PRNG
    HANDSHAKE_PRE_MASK
    HANDSHAKE_CIPHER
    REQ_KEY_DERIVE
    FRAME_HEADER_CIPHER
    FRAME_PAYLOAD_CIPHER
    FRAME_HEADER_MAC
    FRAME_PAYLOAD_MAC
}
