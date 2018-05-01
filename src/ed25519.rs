use rand_core::{ RngCore, CryptoRng };
use hacl_star_sys as ffi;


pub const SECRET_LENGTH: usize = 32;
pub const PUBLIC_LENGTH: usize = 32;
pub const SIGN_LENGTH  : usize = 64;

#[derive(Default, Clone)]
pub struct SecretKey(pub [u8; SECRET_LENGTH]);
#[derive(Default, Clone)]
pub struct PublicKey(pub [u8; PUBLIC_LENGTH]);
#[derive(Clone)]
pub struct Signature(pub [u8; SIGN_LENGTH]);


pub fn keypair<R: RngCore + CryptoRng>(
    mut rng: R,
    &mut SecretKey(ref mut sk): &mut SecretKey,
    &mut PublicKey(ref mut pk): &mut PublicKey
) {
    rng.fill_bytes(sk);
    unsafe {
        ffi::ed25519::Hacl_Ed25519_secret_to_public(
            pk.as_mut_ptr(),
            sk.as_ptr() as _
        );
    }
}

impl SecretKey {
    #[inline]
    pub fn read_public(&self) -> PublicKey {
        let mut pk = [0; PUBLIC_LENGTH];

        unsafe {
            ffi::ed25519::Hacl_Ed25519_secret_to_public(
                pk.as_mut_ptr(),
                self.0.as_ptr() as _
            );
        }

        PublicKey(pk)
    }

    pub fn signature(&self, msg: &[u8]) -> Signature {
        let mut sig = [0; SIGN_LENGTH];

        unsafe {
            ffi::ed25519::Hacl_Ed25519_sign(
                sig.as_mut_ptr(),
                self.0.as_ptr() as _,
                msg.as_ptr() as _,
                msg.len() as _
            );
        }

        Signature(sig)
    }
}

impl PublicKey {
    pub fn verify(self, msg: &[u8], &Signature(ref sig): &Signature) -> bool {
        unsafe {
            ffi::ed25519::Hacl_Ed25519_verify(
                self.0.as_ptr() as _,
                msg.as_ptr() as _,
                msg.len() as _,
                sig.as_ptr() as _
            )
        }
    }
}
