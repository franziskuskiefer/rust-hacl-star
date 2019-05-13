#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(not(all(target_arch = "wasm32", not(target_os = "emscripten"))))]
extern crate libc;

#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
mod libc {
    pub type c_void = u8;
    pub type c_int = i32;
    pub type c_uint = u32;
    pub type c_ulong = u32;
    pub type c_uchar = u8;
}

pub mod aead_poly1305;
pub mod chacha20;
pub mod chacha20poly1305;
pub mod curve25519;
pub mod ed25519;
pub mod hacl_policies;
pub mod hmac_sha2_256;
pub mod nacl;
pub mod poly1305;
pub mod salsa20;
pub mod sha2_256;
pub mod sha2_384;
pub mod sha2_512;
