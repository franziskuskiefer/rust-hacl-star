#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]


macro_rules! ffi {
    ( $( $name:ident ),* ) => {
        $(
            pub mod $name {
                include!(concat!(env!("OUT_DIR"), concat!("/", stringify!($name), ".rs")));
            }
        )*
    }
}

ffi!{
    salsa20, chacha20,
    poly1305, aead_poly1305,
    hmac_sha2_256, sha2_256, sha2_384, sha2_512,
    ed25519, curve25519,
    chacha20poly1305,
    hacl_policies,
    nacl
}
