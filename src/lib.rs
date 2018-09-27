#![no_std]

extern crate rand_core;
extern crate hacl_star_sys;


pub struct And<A, B>(pub A, pub B);

macro_rules! define {
    ( $( pub struct $name:ident / $lower:ident ( pub $ty:ty ) ; )* ) => {
        $(
            #[repr(transparent)]
            #[derive(Clone)]
            pub struct $name(pub $ty);

            pub fn $lower(target: &$ty) -> &$name {
                // unsafe { ::core::mem::transmute(target) }
                unsafe { &*(target as *const $ty as *const $name) }
            }
        )*
    };
}


pub mod sha2;
pub mod hmac;
pub mod poly1305;
pub mod chacha20;
pub mod salsa20;
pub mod chacha20poly1305;
pub mod ed25519;
pub mod curve25519;
#[path = "box.rs"] pub mod box_;
pub mod randombytes;
