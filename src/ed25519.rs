use rand_core::{ RngCore, CryptoRng };
use hacl_star_sys as ffi;


pub const SECRET_LENGTH: usize = 32;
pub const PUBLIC_LENGTH: usize = 32;
pub const SIG_LENGTH  : usize = 64;

define!{
    pub struct SecretKey/secretkey(pub [u8; SECRET_LENGTH]);
    pub struct PublicKey/publickey(pub [u8; PUBLIC_LENGTH]);
    pub struct Signature/signature(pub [u8; SIG_LENGTH]);
}

#[inline]
pub fn keypair<R: RngCore + CryptoRng>(mut rng: R) -> (SecretKey, PublicKey) {
    let mut sk = [0; SECRET_LENGTH];
    let mut pk = [0; PUBLIC_LENGTH];

    rng.fill_bytes(&mut sk);

    unsafe {
        ffi::ed25519::Hacl_Ed25519_secret_to_public(
            pk.as_mut_ptr(),
            sk.as_ptr() as _
        );
    }

    (SecretKey(sk), PublicKey(pk))
}

impl SecretKey {
    #[inline]
    pub fn get_public(&self) -> PublicKey {
        let SecretKey(sk) = self;
        let mut pk = [0; PUBLIC_LENGTH];

        unsafe {
            ffi::ed25519::Hacl_Ed25519_secret_to_public(
                pk.as_mut_ptr(),
                sk.as_ptr() as _
            );
        }

        PublicKey(pk)
    }

    pub fn signature(&self, msg: &[u8]) -> Signature {
        let SecretKey(sk) = self;
        let mut sig = [0; SIG_LENGTH];

        unsafe {
            ffi::ed25519::Hacl_Ed25519_sign(
                sig.as_mut_ptr(),
                sk.as_ptr() as _,
                msg.as_ptr() as _,
                msg.len() as _
            );
        }

        Signature(sig)
    }
}

impl PublicKey {
    pub fn verify(self, msg: &[u8], &Signature(ref sig): &Signature) -> bool {
        let PublicKey(pk) = self;

        unsafe {
            ffi::ed25519::Hacl_Ed25519_verify(
                pk.as_ptr() as _,
                msg.as_ptr() as _,
                msg.len() as _,
                sig.as_ptr() as _
            )
        }
    }
}
