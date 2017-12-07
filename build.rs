extern crate cmake;
extern crate bindgen;

use std::env;
use std::path::PathBuf;


fn main() {
    let outdir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let dst = cmake::Config::new("hacl-star")
        .build_target("all")
        .build();

    macro_rules! bindgen {
        ( @bind $input:expr => $output:expr , $white:expr ) => {
            bindgen::Builder::default()
                .header($input)
                .ctypes_prefix("::libc")
                .use_core()
                .whitelist_type($white)
                .whitelist_function($white)
                .whitelist_var($white)
                .generate().unwrap()
                .write_to_file(outdir.join($output)).unwrap();
        };
        ( $( $input:expr => $output:expr , $white:expr );* ) => {
            $(
                bindgen!(@bind $input => $output, $white);
            )*
        }
    }

    bindgen!{
        "hacl-star/snapshots/hacl-c/AEAD_Poly1305_64.h"      => "aead_poly1305.rs",      "AEAD_Poly1305_.+";
        "hacl-star/snapshots/hacl-c/Hacl_Salsa20.h"          => "salsa20.rs",            "Hacl_Salsa20_.+";
        "hacl-star/snapshots/hacl-c/Hacl_Chacha20.h"         => "chacha20.rs",           "Hacl_Chacha20_.+";
        "hacl-star/snapshots/hacl-c/Hacl_Poly1305_64.h"      => "poly1305.rs",           "Hacl_Poly1305_.+";
        "hacl-star/snapshots/hacl-c/Hacl_HMAC_SHA2_256.h"    => "hmac_sha2_256.rs",      "hmac.*";
        "hacl-star/snapshots/hacl-c/Hacl_SHA2_256.h"         => "sha2_256.rs",           "Hacl_SHA2_256_.+";
        "hacl-star/snapshots/hacl-c/Hacl_SHA2_384.h"         => "sha2_384.rs",           "Hacl_SHA2_384_.+";
        "hacl-star/snapshots/hacl-c/Hacl_SHA2_512.h"         => "sha2_512.rs",           "Hacl_SHA2_512_.+";
        "hacl-star/snapshots/hacl-c/Hacl_Ed25519.h"          => "ed25519.rs",            "Hacl_Ed25519_.+";
        "hacl-star/snapshots/hacl-c/Hacl_Curve25519.h"       => "curve25519.rs",         "Hacl_Curve25519_.+";
        "hacl-star/snapshots/hacl-c/Hacl_Chacha20Poly1305.h" => "chacha20poly1305.rs",   "Hacl_Chacha20Poly1305_.+";
        "hacl-star/snapshots/hacl-c/Hacl_Policies.h"         => "hacl_policies.rs",      "Hacl_Policies_.+";
        "hacl-star/snapshots/hacl-c/NaCl.h"                  => "nacl.rs",               "NaCl_.+"
    };

    println!("cargo:rustc-link-search=native={}/build", dst.display());
    println!("cargo:rustc-link-lib=static=hacl");
}
