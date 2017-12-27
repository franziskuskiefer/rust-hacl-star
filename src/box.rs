use rand::Rng;
use hacl_star_sys as ffi;
use ::And;


pub mod secret {
    use super::*;

    pub const KEY_LENGTH: usize = 32;
    pub const NONCE_LENGTH: usize = 24;
    pub const MAC_LENGTH: usize = 16;

    pub type SecretBox<'a, 'b> = And<Key<'a>, Nonce<'b>>;

    pub struct Key<'a>(pub &'a [u8; KEY_LENGTH]);
    pub struct Nonce<'a>(pub &'a [u8; NONCE_LENGTH]);

    impl<'a, 'b> Key<'a> {
        #[inline]
        pub fn nonce(&self, nonce: &'b [u8; NONCE_LENGTH]) -> SecretBox<'a, 'b> {
            And(Key(self.0), Nonce(nonce))
        }
    }

    impl<'a, 'b> SecretBox<'a, 'b> {
        pub fn seal(self, m: &[u8], c: &mut [u8], mac: &mut [u8; MAC_LENGTH]) {
            assert!(c.len() > 32);
            assert_eq!(c.len(), m.len());

            unsafe {
                ffi::nacl::NaCl_crypto_secretbox_detached(
                    c.as_mut_ptr(),
                    mac.as_mut_ptr(),
                    m.as_ptr() as _,
                    (m.len() - 32) as _,
                    (self.1).0.as_ptr() as _,
                    (self.0).0.as_ptr() as _
                );
            }
        }

        pub fn open(self, m: &mut [u8], c: &[u8], mac: &[u8; MAC_LENGTH]) -> bool {
            assert!(c.len() > 32);
            assert_eq!(c.len(), m.len());

            unsafe {
                ffi::nacl::NaCl_crypto_secretbox_open_detached(
                    m.as_mut_ptr(),
                    c.as_ptr() as _,
                    mac.as_ptr() as _,
                    (c.len() - 32) as _,
                    (self.1).0.as_ptr() as _,
                    (self.0).0.as_ptr() as _
                ) == 0
            }
        }
    }
}


pub mod sealed {
    use super::*;
    use ::curve25519;

    pub const PUBLIC_LENGTH: usize = 32;
    pub const SECRET_LENGTH: usize = 32;
    pub const NONCE_LENGTH: usize = 24;
    pub const MAC_LENGTH: usize = 16;

    pub type SealedBox<'a, 'b, 'c> = And<And<&'a SecretKey, &'b PublicKey>, Nonce<'c>>;

    #[derive(Default, Clone)]
    pub struct SecretKey(pub [u8; SECRET_LENGTH]);
    #[derive(Default, Clone)]
    pub struct PublicKey(pub [u8; PUBLIC_LENGTH]);
    pub struct Nonce<'a>(pub &'a [u8; NONCE_LENGTH]);

    pub fn keypair<R: Rng>(rng: &mut R, sk: &mut SecretKey, pk: &mut PublicKey) {
        rng.fill_bytes(&mut sk.0);
        curve25519::scalarmult(&mut pk.0, &sk.0, &curve25519::BASEPOINT);
    }

    impl SecretKey {
        #[inline]
        pub fn to<'a, 'b>(&'a self, pk: &'b PublicKey) -> And<&'a SecretKey, &'b PublicKey> {
            And(self, pk)
        }
    }

    impl<'a, 'b> And<&'a SecretKey, &'b PublicKey> {
        #[inline]
        pub fn nonce<'c>(&self, nonce: &'c [u8; NONCE_LENGTH]) -> SealedBox<'a, 'b, 'c> {
            And(And(self.0, self.1), Nonce(nonce))
        }
    }

    impl<'a, 'b, 'c> SealedBox<'a, 'b, 'c> {
        pub fn seal(self, m: &[u8], c: &mut [u8], mac: &mut [u8; MAC_LENGTH]) {
            assert!(c.len() > 32);
            assert_eq!(m.len(), c.len());

            unsafe {
                ffi::nacl::NaCl_crypto_box_detached(
                    c.as_mut_ptr(),
                    mac.as_mut_ptr(),
                    m.as_ptr() as _,
                    (m.len() - 32) as _,
                    (self.1).0.as_ptr() as _,
                    ((self.0).1).0.as_ptr() as _,
                    ((self.0).0).0.as_ptr() as _,
                );
            }
        }

        pub fn open(self, m: &mut [u8], c: &[u8], mac: &[u8; MAC_LENGTH]) -> bool {
            assert!(c.len() > 32);
            assert_eq!(m.len(), c.len());

            unsafe {
                ffi::nacl::NaCl_crypto_box_open_detached(
                    m.as_mut_ptr(),
                    c.as_ptr() as _,
                    mac.as_ptr() as _,
                    (c.len() - 32) as _,
                    (self.1).0.as_ptr() as _,
                    ((self.0).1).0.as_ptr() as _,
                    ((self.0).0).0.as_ptr() as _,
                ) == 0
            }
        }
    }
}
