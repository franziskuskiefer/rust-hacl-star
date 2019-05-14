use wasm_bindgen::prelude::*;
use arrayref::{ array_ref, array_mut_ref };
use hacl_star::{ curve25519, box_::sealed };


#[wasm_bindgen]
pub fn scalarmult(sk: &[u8]) -> Vec<u8> {
    const BASEPOINT: [u8; 32] = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let sk = array_ref!(sk, 0, sealed::SECRET_LENGTH);
    let mut pk = vec![0; sealed::PUBLIC_LENGTH];
    {
        let pk = array_mut_ref!(pk, 0, sealed::PUBLIC_LENGTH);
        curve25519::scalarmult(pk, sk, &BASEPOINT);
    }
    pk
}

#[wasm_bindgen]
pub fn seal(sk: &[u8], pk: &[u8], nonce: &[u8], input: &[u8]) -> Vec<u8> {
    let sk = curve25519::secretkey(array_ref!(sk, 0, sealed::SECRET_LENGTH));
    let pk = curve25519::publickey(array_ref!(pk, 0, sealed::PUBLIC_LENGTH));
    let mut output = vec![0; input.len() + sealed::MAC_LENGTH];

    {
        let nonce = array_ref!(nonce, 0, sealed::NONCE_LENGTH);
        let (output, tag) = output.split_at_mut(input.len());
        let tag = array_mut_ref!(tag, 0, sealed::MAC_LENGTH);
        sk.and(pk).nonce(nonce)
            .seal(input, output, tag);
    }

    output
}

#[wasm_bindgen]
pub fn open(sk: &[u8], pk: &[u8], nonce: &[u8], input: &[u8]) -> Vec<u8> {
    let sk = curve25519::secretkey(array_ref!(sk, 0, sealed::SECRET_LENGTH));
    let pk = curve25519::publickey(array_ref!(pk, 0, sealed::PUBLIC_LENGTH));

    let nonce = array_ref!(nonce, 0, sealed::NONCE_LENGTH);
    let (input, tag) = input.split_at(input.len() - sealed::MAC_LENGTH);
    let tag = array_ref!(tag, 0, 16);
    let mut output = vec![0; input.len()];
    if sk.and(pk).nonce(nonce).open(&mut output, input, tag) {
        output
    } else {
        wasm_bindgen::throw_str("decrypt failed!")
    }
}
