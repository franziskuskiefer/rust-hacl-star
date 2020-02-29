use std::ptr;
use hacl_star_sys as ffi;
use crate::error;


pub struct CtrCipher(*mut ffi::EverCrypt_CTR_state_s);

#[repr(u8)]
pub enum Algorithm {
    Aes128 = ffi::Spec_Agile_Cipher_AES128 as ffi::Spec_Agile_Cipher_cipher_alg,
    Aes256 = ffi::Spec_Agile_Cipher_AES256 as ffi::Spec_Agile_Cipher_cipher_alg
}

impl CtrCipher {
    #[inline]
    pub fn new(alg: Algorithm, key: &[u8], nonce: &[u8]) -> error::Result<CtrCipher> {
        CtrCipher::with_count(alg, key, nonce, 0)
    }

    pub fn with_count(alg: Algorithm, key: &[u8], nonce: &[u8], count: u32) -> error::Result<CtrCipher> {
        let mut state = ptr::null_mut();

        // TODO assert key length

        error::from(unsafe {
            ffi::EverCrypt_CTR_create_in(
                alg as ffi::Spec_Agile_Cipher_cipher_alg,
                &mut state,
                key.as_ptr() as *mut _,
                nonce.as_ptr() as *mut _,
                nonce.len() as _,
                count
            )
        })?;

        Ok(CtrCipher(state))
    }

    pub fn update_block(&mut self, dst: &mut [u8], src: &[u8]) {
        // TODO assert block length

        unsafe {
            ffi::EverCrypt_CTR_update_block(
                self.0,
                dst.as_mut_ptr(),
                src.as_ptr() as *mut _
            )
        }
    }

    // init
    // alg of
}

impl Drop for CtrCipher {
    fn drop(&mut self) {
        unsafe {
            ffi::EverCrypt_CTR_free(self.0);
        }
    }
}
