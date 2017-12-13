#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate libc;

macro_rules! ffi {
    ( $( $name:ident ),* ) => {
        $(
            pub mod $name {
                include!(concat!(env!("OUT_DIR"), "/", stringify!($name), ".rs"));
            }
        )*
    }
}

ffi!{
    aead_poly1305,
    chacha20poly1305,
    salsa20, chacha20, poly1305,
    hmac_sha2_256, sha2_256, sha2_384, sha2_512,
    ed25519, curve25519,
    hacl_policies,
    nacl
}
