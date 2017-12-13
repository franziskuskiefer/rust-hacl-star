use hacl_star_sys as ffi;


pub const SECRET_LENGTH: usize = 32;
pub const PUBLIC_LENGTH: usize = 32;
pub const SIGN_LENGTH  : usize = 64;

/*
pub fn keypair(rng: &mut Rng, secret: &mut [u8], public: &mut [u8]) {
    // TODO
}
*/

pub fn secret_to_public(out: &mut [u8; PUBLIC_LENGTH], secret: &[u8; SECRET_LENGTH]) {
    unsafe {
        ffi::ed25519::Hacl_Ed25519_secret_to_public(
            out.as_mut_ptr(),
            secret.as_ptr() as _
        );
    }
}

pub fn sign(signature: &mut [u8; SIGN_LENGTH], secret: &[u8; SECRET_LENGTH], msg: &[u8]) {
    unsafe {
        ffi::ed25519::Hacl_Ed25519_sign(
            signature.as_mut_ptr(),
            secret.as_ptr() as _,
            msg.as_ptr() as _,
            msg.len() as _
        );
    }
}

pub fn verify(public: &[u8; PUBLIC_LENGTH], msg: &[u8], signature: &[u8; SIGN_LENGTH]) -> bool {
    unsafe {
        ffi::ed25519::Hacl_Ed25519_verify(
            public.as_ptr() as _,
            msg.as_ptr() as _,
            msg.len() as _,
            signature.as_ptr() as _
        )
    }
}
