use rand_core::{ RngCore, CryptoRng };
use hacl_star_sys as ffi;


const BASEPOINT: [u8; 32] = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

pub const PUBLIC_LENGTH: usize = 32;
pub const SECRET_LENGTH: usize = 32;

#[derive(Default, Clone)]
pub struct SecretKey(pub [u8; SECRET_LENGTH]);

#[derive(Default, Clone)]
pub struct PublicKey(pub [u8; PUBLIC_LENGTH]);

#[derive(Default, Clone)]
pub struct BasePoint(pub [u8; 32]);


pub fn keypair<R: RngCore + CryptoRng>(
    mut rng: R,
    &mut SecretKey(ref mut sk): &mut SecretKey,
    &mut PublicKey(ref mut pk): &mut PublicKey
) {
    rng.fill_bytes(sk);
    scalarmult(pk, sk, &BASEPOINT);
}

impl SecretKey {
    #[inline]
    pub fn get_public(&self) -> PublicKey {
        let SecretKey(sk) = self;
        let mut pk = [0; 32];

        scalarmult(&mut pk, sk, &BASEPOINT);

        PublicKey(pk)
    }

    pub fn exchange(&self, &PublicKey(ref pk): &PublicKey, output: &mut [u8; 32]) {
        let SecretKey(sk) = self;

        scalarmult(output, sk, pk);
    }
}


pub fn scalarmult(mypublic: &mut [u8; 32], secret: &[u8; 32], basepoint: &[u8; 32]) {
    unsafe {
        ffi::curve25519::Hacl_Curve25519_crypto_scalarmult(
            mypublic.as_mut_ptr(),
            secret.as_ptr() as _,
            basepoint.as_ptr() as _
        );
    }
}
