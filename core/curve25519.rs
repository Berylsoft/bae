use curve25519_dalek::{Scalar, EdwardsPoint, edwards::CompressedEdwardsY, MontgomeryPoint};
use zeroize::Zeroize;
use foundations::{byterepr::ByteRepr, byterepr_struct};
use crate::{
    consts::{PK_L, XK_L, SK_L, HASH_L, XSIG_L, EDSIG_L, C25519_PRIM_L},
    cshake::{CShake, Absorb, Squeeze, CShakeCustom, DSA_SK_DERIVE, DSA_EDSIGN_R_HASH, DSA_EDSIGN_K_HASH, DH_SK_GEN_PRNG},
};

pub struct XSK {
    scalar: Scalar,
}

pub struct XPK {
    montgomery: MontgomeryPoint,
}

pub struct ExchangedSecret {
    montgomery: MontgomeryPoint,
}

pub struct SK {
    key: [u8; SK_L],
    scalar: Scalar,
    nonce: [u8; 32],
}

#[derive(PartialEq, Eq)]
pub struct PK {
    edwards: CompressedEdwardsY,
}

byterepr_struct! {
    pub struct ExchangeSignature {
        pub hash: [u8; HASH_L],
        pub exchanged: [u8; XSIG_L],
    }
}

pub struct EdLikeSignature {
    r: CompressedEdwardsY,
    s: Scalar,
}

// region: impl Drop

impl Drop for XSK {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

impl Drop for ExchangedSecret {
    fn drop(&mut self) {
        self.montgomery.zeroize();
    }
}

impl Drop for SK {
    fn drop(&mut self) {
        self.key.zeroize();
        self.scalar.zeroize();
        self.nonce.zeroize();
    }
}

// endregion

// region: impl ByteRepr

impl ByteRepr for XPK {
    const SIZE: usize = PK_L;
    type Bytes = [u8; Self::SIZE];

    fn from_bytes(bytes: Self::Bytes) -> Self {
        XPK { montgomery: MontgomeryPoint(bytes) }
    }

    fn to_bytes(&self) -> Self::Bytes {
        self.montgomery.to_bytes()
    }
}

impl ByteRepr for PK {
    const SIZE: usize = PK_L;
    type Bytes = [u8; Self::SIZE];

    fn from_bytes(bytes: Self::Bytes) -> Self {
        PK { edwards: CompressedEdwardsY(bytes) }
    }

    fn to_bytes(&self) -> Self::Bytes {
        self.edwards.to_bytes()
    }
}

impl ByteRepr for EdLikeSignature {
    const SIZE: usize = EDSIG_L;
    type Bytes = [u8; Self::SIZE];

    fn from_bytes(bytes: Self::Bytes) -> Self {
        EdLikeSignature {
            r: CompressedEdwardsY(bytes[..C25519_PRIM_L].try_into().unwrap()),
            s: Scalar::from_canonical_bytes(bytes[C25519_PRIM_L..].try_into().unwrap()).unwrap(),
        }
    }

    fn to_bytes(&self) -> Self::Bytes {
        let mut bytes = [0; EDSIG_L];
        bytes[..C25519_PRIM_L].copy_from_slice(self.r.as_bytes());
        bytes[C25519_PRIM_L..].copy_from_slice(self.s.as_bytes());
        bytes
    }
}

// endregion

// region: common

impl XSK {
    pub fn generate(ctx: &mut CShake<DH_SK_GEN_PRNG>) -> XSK {
        XSK { scalar: Scalar::from_bits_clamped(ctx.squeeze_to_array()) }
    }

    #[inline]
    pub fn pk(&self) -> XPK {
        XPK { montgomery: EdwardsPoint::mul_base(&self.scalar).to_montgomery() }
    }
}

impl ExchangedSecret {
    pub fn as_bytes(&self) -> &[u8; XK_L] {
        self.montgomery.as_bytes()
    }
}

impl SK {
    pub fn from_key(key: [u8; SK_L]) -> SK {
        let mut ctx = DSA_SK_DERIVE.create().chain_absorb(&key);
        SK {
            key,
            scalar: Scalar::from_bits_clamped(ctx.squeeze_to_array()),
            nonce: ctx.squeeze_to_array(),
        }
    }

    #[inline]
    pub fn pk(&self) -> PK {
        PK { edwards: EdwardsPoint::mul_base(&self.scalar).compress() }
    }
}

// endregion

// region: exchange

impl XSK {
    pub fn exchange(self, peer_pk: XPK) -> ExchangedSecret {
        ExchangedSecret { montgomery: self.scalar * peer_pk.montgomery }
    }
}

// endregion

// region: exchange sign

impl SK {
    // let hash = DSA_XSIGN_HASH.create().once_to_array(msg);
    pub fn exchange_sign(&self, hash: [u8; HASH_L]) -> ExchangeSignature {
        ExchangeSignature {
            hash,
            exchanged: (self.scalar * EdwardsPoint::mul_base(&Scalar::from_bits_clamped(hash))).compress().0,
        }
    }
}

impl PK {
    pub fn exchange_verify(&self, ExchangeSignature { hash, exchanged }: ExchangeSignature) -> bool {
        (Scalar::from_bits_clamped(hash) * self.edwards.decompress().unwrap()).compress().0 == exchanged
    }
}

// endregion

// region: ed-like sign

fn calc_k(r: &CompressedEdwardsY, pk: &PK, msg: &[u8]) -> Scalar {
    let mut k_ctx = DSA_EDSIGN_K_HASH.create();
    k_ctx.absorb(r.as_bytes());
    k_ctx.absorb(pk.edwards.as_bytes());
    k_ctx.absorb(msg);
    Scalar::from_bits_clamped(k_ctx.squeeze_to_array())
}

fn calc_r(nonce: &[u8; 32], msg: &[u8]) -> (Scalar, CompressedEdwardsY) {
    let mut r_ctx = DSA_EDSIGN_R_HASH.create();
    r_ctx.absorb(nonce);
    r_ctx.absorb(msg);
    let r_scalar = Scalar::from_bits_clamped(r_ctx.squeeze_to_array());
    let r = EdwardsPoint::mul_base(&r_scalar).compress();
    (r_scalar, r)
}

fn calc_s(sk: &SK, k: &Scalar, r_scalar: &Scalar) -> Scalar {
    (sk.scalar * k) + r_scalar
}

fn calc2_r(k: &Scalar, pk: &PK, s: &Scalar) -> CompressedEdwardsY {
    let neg_pk = - pk.edwards.decompress().unwrap();
    EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &neg_pk, &s).compress()
}

impl SK {
    pub fn edlike_sign(&self, msg: &[u8]) -> EdLikeSignature {
        let (r_scalar, r) = calc_r(&self.nonce, msg);
        let k = calc_k(&r, &self.pk(), msg);
        let s = calc_s(&self, &k, &r_scalar);
        EdLikeSignature { r, s }
    }
}

impl PK {
    pub fn edlike_verify(&self, msg: &[u8], EdLikeSignature { r, s }: &EdLikeSignature) -> bool {
        let k2 = calc_k(&r, &self, msg);
        let r2 = calc2_r(&k2, &self, &s);
        &r2 == r
    }
}

// endregion
