use hacl_star_sys as ffi;
use crate::And;


pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 8;
pub const BLOCK_LENGTH: usize = 64;

pub type Salsa20<'a> = And<&'a Key, &'a Nonce>;

define!{
    pub struct Key/key(pub [u8; KEY_LENGTH]);
    pub struct Nonce/nonce(pub [u8; NONCE_LENGTH]);
}

impl Key {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub fn nonce<'a>(&'a self, n: &'a [u8; NONCE_LENGTH]) -> Salsa20<'a> {
        And(self, nonce(n))
    }
}

impl<'a> Salsa20<'a> {
    pub fn process(self, buf: &mut [u8]) {
        unsafe {
            ffi::salsa20::Hacl_Salsa20_salsa20(
                buf.as_mut_ptr(),
                buf.as_ptr() as _,
                buf.len() as _,
                (self.0).0.as_ptr() as _,
                (self.1).0.as_ptr() as _,
                0
            );
        }
    }

    pub fn process_ic(self, ctr: u64, input: &[u8], output: &mut [u8]) {
        assert!(output.len() >= input.len());

        unsafe {
            ffi::salsa20::Hacl_Salsa20_salsa20(
                output.as_mut_ptr(),
                input.as_ptr() as _,
                input.len() as _,
                (self.0).0.as_ptr() as _,
                (self.1).0.as_ptr() as _,
                ctr
            );
        }
    }
}


pub fn hasalsa20(output: &mut [u8; 32], key: &[u8; KEY_LENGTH], nonce: &[u8; 16]) {
    unsafe {
        ffi::salsa20::Hacl_Salsa20_hsalsa20(
            output.as_mut_ptr(),
            nonce.as_ptr() as _,
            key.as_ptr() as _
        );
    }
}
