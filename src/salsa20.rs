use hacl_sys as ffi;


pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 32;
pub const BLOCK_LENGTH: usize = 64;

pub fn salsa20(buf: &mut [u8], key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH]) {
    unsafe {
        ffi::salsa20::Hacl_Salsa20_salsa20(
            buf.as_mut_ptr(),
            buf.as_ptr() as _,
            buf.len() as _,
            key.as_ptr() as _,
            nonce.as_ptr() as _,
            0
        );
    }
}

pub fn salsa20_ic(output: &mut [u8], input: &[u8], key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH], ctr: u64) {
    unsafe {
        ffi::salsa20::Hacl_Salsa20_salsa20(
            output.as_mut_ptr(),
            input.as_ptr() as _,
            input.len() as _,
            key.as_ptr() as _,
            nonce.as_ptr() as _,
            ctr
        );
    }
}

pub fn hasalsa20(output: &mut [u8; 32], key: &[u8; 32], nonce: &[u8; 16]) {
    unsafe {
        ffi::salsa20::Hacl_Salsa20_hsalsa20(
            output.as_mut_ptr(),
            key.as_ptr() as _,
            nonce.as_ptr() as _
        );
    }
}
