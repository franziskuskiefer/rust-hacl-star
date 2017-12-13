use hacl_star_sys as ffi;


pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 12;
pub const BLOCK_LENGTH: usize = 64;

pub fn chacha20(buf: &mut [u8], key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH]) {
    unsafe {
        ffi::chacha20::Hacl_Chacha20_chacha20(
            buf.as_mut_ptr(),
            buf.as_ptr() as _,
            buf.len() as _,
            key.as_ptr() as _,
            nonce.as_ptr() as _,
            0
        )
    }
}

pub fn chacha20_ic(output: &mut [u8], input: &[u8], key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH], ctr: u32) {
    unsafe {
        ffi::chacha20::Hacl_Chacha20_chacha20(
            output.as_mut_ptr(),
            input.as_ptr() as _,
            input.len() as _,
            key.as_ptr() as _,
            nonce.as_ptr() as _,
            ctr
        );
    }
}

pub fn chacha20_keyblock(block: &mut [u8; BLOCK_LENGTH], key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH], ctr: u32) {
    unsafe {
        ffi::chacha20::Hacl_Chacha20_chacha20_key_block(
            block.as_mut_ptr(),
            key.as_ptr() as _,
            nonce.as_ptr() as _,
            ctr
        );
    }
}
