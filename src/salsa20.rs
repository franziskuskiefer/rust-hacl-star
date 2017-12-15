use hacl_star_sys as ffi;
use ::And;


pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 32;
pub const BLOCK_LENGTH: usize = 64;

pub type Salsa20<'a, 'b> = And<Key<'a>, Nonce<'b>>;

pub struct Key<'a>(pub &'a [u8; KEY_LENGTH]);
pub struct Nonce<'b>(pub &'b [u8; NONCE_LENGTH]);

impl<'a, 'b> Key<'a> {
    #[inline]
    pub fn nonce(&self, nonce: &'b [u8; NONCE_LENGTH]) -> Salsa20<'a, 'b> {
        And(Key(self.0), Nonce(nonce))
    }
}

impl<'a, 'b> Salsa20<'a, 'b> {
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

    pub fn hasalsa20(self, output: &mut [u8; 32]) {
        unsafe {
            ffi::salsa20::Hacl_Salsa20_hsalsa20(
                output.as_mut_ptr(),
                (self.0).0.as_ptr() as _,
                (self.1).0.as_ptr() as _
            );
        }
    }
}
