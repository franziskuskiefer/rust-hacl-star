use std::ptr;
use hacl_star_sys as ffi;
use crate::error;


pub struct AeadCipher(*mut ffi::EverCrypt_AEAD_state_s);

#[repr(u8)]
pub enum Algorithm {
    Aes128GCM = ffi::Spec_Agile_AEAD_AES128_GCM as ffi::Spec_Agile_AEAD_alg,
    Aes128CCM = ffi::Spec_Agile_AEAD_AES128_CCM as ffi::Spec_Agile_AEAD_alg,
    Aes256GCM = ffi::Spec_Agile_AEAD_AES256_GCM as ffi::Spec_Agile_AEAD_alg,
    Aes256CCM = ffi::Spec_Agile_AEAD_AES256_CCM as ffi::Spec_Agile_AEAD_alg,
    Chacha20Poly1305 = ffi::Spec_Agile_AEAD_CHACHA20_POLY1305 as ffi::Spec_Agile_AEAD_alg
}

impl AeadCipher {
    pub fn new(alg: Algorithm, key: &[u8]) -> error::Result<AeadCipher> {
        let mut state = ptr::null_mut();

        // TODO assert key length

        error::from(unsafe {
            ffi::EverCrypt_AEAD_create_in(
                alg as ffi::Spec_Agile_AEAD_alg,
                &mut state,
                key.as_ptr() as *mut _
            )
        })?;

        Ok(AeadCipher(state))
    }

    pub fn encrypt(
        &self,
        nonce: &[u8], aad: &[u8], plain: &[u8],
        cipher: &mut [u8], tag: &mut [u8]
    ) -> error::Result<()> {
        // TODO assert tag length

        error::from(unsafe {
            ffi::EverCrypt_AEAD_encrypt(
                self.0,
                nonce.as_ptr() as *mut _,
                nonce.len() as _,
                aad.as_ptr() as *mut _,
                aad.len() as _,
                plain.as_ptr() as *mut _,
                plain.len() as _,
                cipher.as_mut_ptr(),
                tag.as_mut_ptr()
            )
        })
    }

    pub fn decrypt(
        &self,
        nonce: &[u8], aad: &[u8], cipher: &[u8], tag: &[u8],
        dst: &mut [u8]
    ) -> error::Result<()> {
        // TODO assert tag length

        error::from(unsafe {
            ffi::EverCrypt_AEAD_decrypt(
                self.0,
                nonce.as_ptr() as *mut _,
                nonce.len() as _,
                aad.as_ptr() as *mut _,
                aad.len() as _,
                cipher.as_ptr() as *mut _,
                cipher.len() as _,
                tag.as_ptr() as *mut _,
                dst.as_mut_ptr()
            )
        })
    }

    // TODO alg of
}

impl Drop for AeadCipher {
    fn drop(&mut self) {
        unsafe {
            ffi::EverCrypt_AEAD_free(self.0);
        }
    }
}
