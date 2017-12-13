use hacl_star_sys as ffi;


pub const KEY_LENGTH  : usize = 32;
pub const NONCE_LENGTH: usize = 12;
pub const MAC_LENGTH  : usize = 16;

pub fn aead_encrypt(c: &mut [u8], mac: &mut [u8; MAC_LENGTH], m: &[u8], aad: &[u8], key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH]) {
    unsafe {
        ffi::chacha20poly1305::Hacl_Chacha20Poly1305_aead_encrypt(
            c.as_mut_ptr(),
            mac.as_mut_ptr(),
            m.as_ptr() as _,
            m.len() as _,
            aad.as_ptr() as _,
            aad.len() as _,
            key.as_ptr() as _,
            nonce.as_ptr() as _
        );
    }
}

pub fn aead_decrypt(m: &mut [u8], c: &[u8], mac: &[u8; MAC_LENGTH], aad: &[u8], key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH]) -> bool {
    unsafe {
        ffi::chacha20poly1305::Hacl_Chacha20Poly1305_aead_decrypt(
            m.as_mut_ptr(),
            c.as_ptr() as _,
            c.len() as _,
            mac.as_ptr() as _,
            aad.as_ptr() as _,
            aad.len() as _,
            key.as_ptr() as _,
            nonce.as_ptr() as _
        ) == 0
    }
}
