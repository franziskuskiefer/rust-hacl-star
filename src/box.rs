use hacl_star_sys as ffi;
use ::And;


pub mod secret {
    use super::*;

    pub const KEY_LENGTH: usize = 32;
    pub const NONCE_LENGTH: usize = 24;
    pub const MAC_LENGTH: usize = 16;

    pub type SecretBox<'a> = And<&'a Key, &'a Nonce>;

    define!{
        pub struct Key/key(pub [u8; KEY_LENGTH]);
        pub struct Nonce/nonce(pub [u8; NONCE_LENGTH]);
    }

    impl Key {
        #[inline]
        pub fn nonce<'a>(&'a self, n: &'a [u8; NONCE_LENGTH]) -> SecretBox<'a> {
            And(self, nonce(n))
        }
    }

    impl<'a> SecretBox<'a> {
        pub fn seal(self, m: &[u8], c: &mut [u8], mac: &mut [u8; MAC_LENGTH]) {
            assert!(c.len() > 32);
            assert_eq!(c.len(), m.len());

            let And(Key(key), Nonce(nonce)) = self;

            unsafe {
                ffi::nacl::NaCl_crypto_secretbox_detached(
                    c.as_mut_ptr(),
                    mac.as_mut_ptr(),
                    m.as_ptr() as _,
                    (m.len() - 32) as _,
                    nonce.as_ptr() as _,
                    key.as_ptr() as _
                );
            }
        }

        pub fn open(self, m: &mut [u8], c: &[u8], mac: &[u8; MAC_LENGTH]) -> bool {
            assert!(c.len() > 32);
            assert_eq!(c.len(), m.len());

            let And(Key(key), Nonce(nonce)) = self;

            unsafe {
                ffi::nacl::NaCl_crypto_secretbox_open_detached(
                    m.as_mut_ptr(),
                    c.as_ptr() as _,
                    mac.as_ptr() as _,
                    (c.len() - 32) as _,
                    nonce.as_ptr() as _,
                    key.as_ptr() as _
                ) == 0
            }
        }
    }
}


pub mod sealed {
    use super::*;
    pub use ::curve25519::{
        PUBLIC_LENGTH, SECRET_LENGTH,
        SecretKey, PublicKey,
        keypair
    };
    pub use super::secret::{
        self,
        NONCE_LENGTH, MAC_LENGTH,
        Nonce
    };

    pub type SealedBox<'a> = And<And<&'a SecretKey, &'a PublicKey>, &'a Nonce>;

    impl SecretKey {
        #[inline]
        pub fn and<'a>(&'a self, pk: &'a PublicKey) -> And<&'a SecretKey, &'a PublicKey> {
            And(self, pk)
        }
    }

    impl<'a> And<&'a SecretKey, &'a PublicKey> {
        #[inline]
        pub fn nonce(&self, n: &'a [u8; NONCE_LENGTH]) -> SealedBox<'a> {
            And(And(self.0, self.1), secret::nonce(n))
        }
    }

    impl<'a> SealedBox<'a> {
        pub fn seal(self, m: &[u8], c: &mut [u8], mac: &mut [u8; MAC_LENGTH]) {
            assert!(c.len() > 32);
            assert_eq!(m.len(), c.len());

            let And(And(SecretKey(sk), PublicKey(pk)), Nonce(nonce)) = self;

            unsafe {
                ffi::nacl::NaCl_crypto_box_detached(
                    c.as_mut_ptr(),
                    mac.as_mut_ptr(),
                    m.as_ptr() as _,
                    (m.len() - 32) as _,
                    nonce.as_ptr() as _,
                    pk.as_ptr() as _,
                    sk.as_ptr() as _
                );
            }
        }

        pub fn open(self, m: &mut [u8], c: &[u8], mac: &[u8; MAC_LENGTH]) -> bool {
            assert!(c.len() > 32);
            assert_eq!(m.len(), c.len());

            let And(And(SecretKey(sk), PublicKey(pk)), Nonce(nonce)) = self;

            unsafe {
                ffi::nacl::NaCl_crypto_box_open_detached(
                    m.as_mut_ptr(),
                    c.as_ptr() as _,
                    mac.as_ptr() as _,
                    (c.len() - 32) as _,
                    nonce.as_ptr() as _,
                    pk.as_ptr() as _,
                    sk.as_ptr() as _
                ) == 0
            }
        }
    }
}
