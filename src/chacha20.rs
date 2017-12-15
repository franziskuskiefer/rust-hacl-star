use hacl_star_sys as ffi;
use ::And;


pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 12;
pub const BLOCK_LENGTH: usize = 64;

pub type ChaCha20<'a, 'b> = And<Key<'a>, Nonce<'b>>;

pub struct Key<'a>(pub &'a [u8; KEY_LENGTH]);
pub struct Nonce<'b>(pub &'b [u8; NONCE_LENGTH]);

impl<'a, 'b> Key<'a> {
    #[inline]
    pub fn nonce(&self, nonce: &'b [u8; NONCE_LENGTH]) -> ChaCha20<'a, 'b> {
        And(Key(self.0), Nonce(nonce))
    }
}

impl<'a, 'b> ChaCha20<'a, 'b> {
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
