#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate libc;

pub mod aead_poly1305;
pub mod chacha20poly1305;
pub mod salsa20;
pub mod chacha20;
pub mod poly1305;
pub mod hmac_sha2_256;
pub mod sha2_256;
pub mod sha2_384;
pub mod sha2_512;
pub mod ed25519;
pub mod curve25519;
pub mod hacl_policies;
pub mod nacl;
