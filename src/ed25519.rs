use rand::Rng;
use hacl_star_sys as ffi;


pub const SECRET_LENGTH: usize = 32;
pub const PUBLIC_LENGTH: usize = 32;
pub const SIGN_LENGTH  : usize = 64;

#[derive(Default, Clone)]
pub struct SecretKey(pub [u8; SECRET_LENGTH]);
#[derive(Default, Clone)]
pub struct PublicKey(pub [u8; PUBLIC_LENGTH]);
pub struct Signature(pub [u8; SIGN_LENGTH]);


pub fn keypair<R: Rng>(rng: &mut R, sk: &mut SecretKey, pk: &mut PublicKey) {
    rng.fill_bytes(&mut sk.0);
    sk.read_public(pk);
}

impl SecretKey {
    pub fn read_public(&self, pubkey: &mut PublicKey) {
        unsafe {
            ffi::ed25519::Hacl_Ed25519_secret_to_public(
                pubkey.0.as_mut_ptr(),
                self.0.as_ptr() as _
            );
        }
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
    pub fn verify(self, msg: &[u8], sign: &Signature) -> bool {
        unsafe {
            ffi::ed25519::Hacl_Ed25519_verify(
                self.0.as_ptr() as _,
                msg.as_ptr() as _,
                msg.len() as _,
                sign.0.as_ptr() as _
            )
        }
    }
}
