#[cfg(feature = "bindgen")]
extern crate bindgen;
extern crate cc;

use std::env;
#[cfg(feature = "bindgen")]
use std::path::PathBuf;

fn main() {
    let mut cc = cc::Build::new();

    // from https://github.com/project-everest/hacl-star/blob/master/snapshots/makefiles/CMakeLists.txt#L62
    if env::var("CARGO_CFG_TARGET_POINTER_WIDTH") == Ok("32".into())
        || env::var("CARGO_CFG_TARGET_ENV") == Ok("msvc".into())
    {
        cc.shared_flag(true)
            .define("KRML_NOUINT128", None)
            .flag_if_supported("-Wno-unused-function")
            .file("hacl-c/FStar.c");
    }

    cc.flag_if_supported(
        if cc::Build::new().get_compiler().is_like_gnu()
            || cc::Build::new().get_compiler().is_like_clang()
        {
            "-std=gnu11"
        } else {
            "-std=c11"
        },
    )
    .include("hacl-c")
    // from https://github.com/mitls/hacl-star/blob/master/snapshots/hacl-c/Makefile#L8
    .flag_if_supported("-fwrapv")
    .flag_if_supported("-fomit-frame-pointer")
    .flag_if_supported("-funroll-loops")
    .files(&[
        "hacl-c/Hacl_Salsa20.c",
        "hacl-c/Hacl_Poly1305_32.c",
        "hacl-c/Hacl_Poly1305_64.c",
        "hacl-c/Hacl_Chacha20.c",
        "hacl-c/AEAD_Poly1305_64.c",
        "hacl-c/Hacl_Chacha20Poly1305.c",
        "hacl-c/Hacl_HMAC_SHA2_256.c",
        "hacl-c/Hacl_SHA2_256.c",
        "hacl-c/Hacl_SHA2_384.c",
        "hacl-c/Hacl_SHA2_512.c",
        "hacl-c/Hacl_Ed25519.c",
        "hacl-c/Hacl_Curve25519.c",
        "hacl-c/kremlib.c",
        "hacl-c/Hacl_Policies.c",
        "hacl-c/NaCl.c",
    ])
    // ignore some warnings
    .flag_if_supported("-Wno-unused-parameter")
    .flag_if_supported("-Wno-unused-variable")
    .compile("hacl");

    #[cfg(feature = "bindgen")]
    let outdir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("src");

    #[cfg(feature = "bindgen")]
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

    #[cfg(feature = "bindgen")]
    bindgen! {
        "hacl-c/AEAD_Poly1305_64.h"      => "aead_poly1305.rs",      "AEAD_Poly1305_.+";
        "hacl-c/Hacl_Salsa20.h"          => "salsa20.rs",            "Hacl_Salsa20_.+";
        "hacl-c/Hacl_Chacha20.h"         => "chacha20.rs",           "Hacl_Chacha20_.+";
        "hacl-c/Hacl_Poly1305_64.h"      => "poly1305.rs",           "Hacl_Poly1305_.+";
        "hacl-c/Hacl_HMAC_SHA2_256.h"    => "hmac_sha2_256.rs",      "hmac.*";
        "hacl-c/Hacl_SHA2_256.h"         => "sha2_256.rs",           "Hacl_SHA2_256_.+";
        "hacl-c/Hacl_SHA2_384.h"         => "sha2_384.rs",           "Hacl_SHA2_384_.+";
        "hacl-c/Hacl_SHA2_512.h"         => "sha2_512.rs",           "Hacl_SHA2_512_.+";
        "hacl-c/Hacl_Ed25519.h"          => "ed25519.rs",            "Hacl_Ed25519_.+";
        "hacl-c/Hacl_Curve25519.h"       => "curve25519.rs",         "Hacl_Curve25519_.+";
        "hacl-c/Hacl_Chacha20Poly1305.h" => "chacha20poly1305.rs",   "Hacl_Chacha20Poly1305_.+";
        "hacl-c/Hacl_Policies.h"         => "hacl_policies.rs",      "Hacl_Policies_.+";
        "hacl-c/NaCl.h"                  => "nacl.rs",               "NaCl_.+"
    };
}
