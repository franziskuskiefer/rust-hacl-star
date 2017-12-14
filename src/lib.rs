#![no_std]

extern crate hacl_star_sys;

pub mod sha2;
pub mod hmac;
pub mod chacha20;
pub mod salsa20;
pub mod chacha20poly1305;
pub mod ed25519;
pub mod curve25519;

// TODO
// #[path = "box.rs"] pub mod box_;

pub struct And<A, B>(pub A, pub B);
