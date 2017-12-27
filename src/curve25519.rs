use hacl_star_sys as ffi;


pub const BASEPOINT: [u8; 32] = [9; 32];

pub fn scalarmult(mypublic: &mut [u8; 32], secret: &[u8; 32], basepoint: &[u8; 32]) {
    unsafe {
        ffi::curve25519::Hacl_Curve25519_crypto_scalarmult(
            mypublic.as_mut_ptr(),
            secret.as_ptr() as _,
            basepoint.as_ptr() as _
        );
    }
}
