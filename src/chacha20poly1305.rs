use hacl_star_sys as ffi;
use And;

pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 12;
pub const MAC_LENGTH: usize = 16;

pub type ChaCha20Poly1305<'a> = And<&'a Key, &'a Nonce>;

define! {
    pub struct Key/key(pub [u8; KEY_LENGTH]);
    pub struct Nonce/nonce(pub [u8; NONCE_LENGTH]);
}

impl Key {
    #[inline]
    pub fn nonce<'a>(&'a self, n: &'a [u8; NONCE_LENGTH]) -> ChaCha20Poly1305<'a> {
        And(self, nonce(n))
    }
}

impl<'a> ChaCha20Poly1305<'a> {
    pub fn encrypt(self, aad: &[u8], m: &mut [u8], mac: &mut [u8; MAC_LENGTH]) {
        unsafe {
            ffi::chacha20poly1305::Hacl_Chacha20Poly1305_aead_encrypt(
                m.as_mut_ptr(),
                mac.as_mut_ptr(),
                m.as_ptr() as _,
                m.len() as _,
                aad.as_ptr() as _,
                aad.len() as _,
                (self.0).0.as_ptr() as _,
                (self.1).0.as_ptr() as _,
            );
        }
    }

    pub fn decrypt(self, aad: &[u8], c: &mut [u8], mac: &[u8; MAC_LENGTH]) -> bool {
        unsafe {
            ffi::chacha20poly1305::Hacl_Chacha20Poly1305_aead_decrypt(
                c.as_mut_ptr(),
                c.as_ptr() as _,
                c.len() as _,
                mac.as_ptr() as _,
                aad.as_ptr() as _,
                aad.len() as _,
                (self.0).0.as_ptr() as _,
                (self.1).0.as_ptr() as _,
            ) == 0
        }
    }
}
