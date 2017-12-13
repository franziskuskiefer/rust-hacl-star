use hacl_star_sys as ffi;


pub struct SecretBox<'a>(pub &'a [u8; 32]);

impl<'a> SecretBox<'a> {
    pub const KEY_LENGTH: usize = 32;
    pub const NONCE_LENGTH: usize = 24;
    pub const MAC_LENGTH: usize = 16;

    pub fn seal(&self, nonce: &[u8; 24], m: &[u8], c: &mut [u8]) {
        unsafe {
            ffi::nacl::NaCl_crypto_secretbox_easy(
                c.as_mut_ptr(),
                m.as_ptr() as _,
                m.len() as _,
                nonce.as_ptr() as _,
                self.0.as_ptr() as _
            );
        }
    }

    pub fn open(&self, nonce: &[u8; 24], c: &[u8], m: &mut [u8]) -> bool {
        unsafe {
            ffi::nacl::NaCl_crypto_secretbox_open_easy(
                m.as_mut_ptr(),
                c.as_ptr() as _,
                c.len() as _,
                nonce.as_ptr() as _,
                self.0.as_ptr() as _
            ) == 0
        }
    }
}

pub struct Box<'a>(pub &'a [u8; 32]);

impl<'a> Box<'a> {
    pub const PUBLIC_LENGTH: usize = 32;
    pub const SECRET_LENGTH: usize = 32;
    pub const NONCE_LENGTH: usize = 24;
    pub const MAC_LENGTH: usize = 16;

    pub fn seal(&self, pk: &[u8; 32], nonce: &[u8; 24], m: &mut [u8], mac: &mut [u8; 16]) {
        unsafe {
            ffi::nacl::NaCl_crypto_box_detached(
                m.as_mut_ptr(),
                mac.as_mut_ptr(),
                m.as_ptr() as _,
                m.len() as _,
                nonce.as_ptr() as _,
                pk.as_ptr() as _,
                self.0.as_ptr() as _,
            );
        }
    }

    pub fn open(&self, pk: &[u8; 32], nonce: &[u8; 24], m: &mut [u8], mac: &[u8; 16]) -> bool {
        unsafe {
            ffi::nacl::NaCl_crypto_box_open_detached(
                m.as_mut_ptr(),
                m.as_ptr() as _,
                mac.as_ptr() as _,
                m.len() as _,
                nonce.as_ptr() as _,
                pk.as_ptr() as _,
                self.0.as_ptr() as _,
            ) == 0
        }
    }
}
