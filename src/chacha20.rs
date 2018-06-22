use hacl_star_sys as ffi;
use ::And;


pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 12;
pub const BLOCK_LENGTH: usize = 64;

pub type ChaCha20<'a> = And<&'a Key, &'a Nonce>;

define!{
    pub struct Key/key(pub [u8; KEY_LENGTH]);
    pub struct Nonce/nonce(pub [u8; NONCE_LENGTH]);
}

impl Key {
    #[inline]
    pub fn nonce<'a>(&'a self, n: &'a [u8; NONCE_LENGTH]) -> ChaCha20<'a> {
        And(self, nonce(n))
    }
}

impl<'a> ChaCha20<'a> {
    pub fn process(self, buf: &mut [u8]) {
        unsafe {
            ffi::chacha20::Hacl_Chacha20_chacha20(
                buf.as_mut_ptr(),
                buf.as_ptr() as _,
                buf.len() as _,
                (self.0).0.as_ptr() as _,
                (self.1).0.as_ptr() as _,
                0
            )
        }
    }

    pub fn process_ic(self, ctr: u32, input: &[u8], output: &mut [u8]) {
        assert!(output.len() >= input.len());

        unsafe {
            ffi::chacha20::Hacl_Chacha20_chacha20(
                output.as_mut_ptr(),
                input.as_ptr() as _,
                input.len() as _,
                (self.0).0.as_ptr() as _,
                (self.1).0.as_ptr() as _,
                ctr
            );
        }
    }

    pub fn keyblock(self, ctr: u32, block: &mut [u8; BLOCK_LENGTH]) {
        unsafe {
            ffi::chacha20::Hacl_Chacha20_chacha20_key_block(
                block.as_mut_ptr(),
                (self.0).0.as_ptr() as _,
                (self.1).0.as_ptr() as _,
                ctr
            );
        }
    }
}
