use hacl_sys as ffi;


pub const KEY_LENGTH: usize = 64;
pub const MAC_LENGTH: usize = 32;

pub fn hmac_sha256(mac: &mut [u8; MAC_LENGTH], key: &[u8], data: &[u8]) {
    unsafe {
        ffi::hmac_sha2_256::hmac(
            mac.as_mut_ptr(),
            key.as_ptr() as _,
            key.len() as _,
            data.as_ptr() as _,
            data.len() as _
        );
    }
}

pub fn hmac_sha256_core(mac: &mut [u8; MAC_LENGTH], key: &[u8; KEY_LENGTH], data: &[u8]) {
    unsafe {
        ffi::hmac_sha2_256::hmac_core(
            mac.as_mut_ptr(),
            key.as_ptr() as _,
            data.as_ptr() as _,
            data.len() as _
        );
    }
}
