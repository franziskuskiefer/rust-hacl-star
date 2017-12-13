use hacl_star_sys as ffi;


macro_rules! sha2 {
    (
        pub struct $name:ident {
            state: [ $s:ty; $size:expr ],
            block: [ u8; $block:expr ]
        }

        const HASH_LENGTH = $outlen:expr;

        impl $hash:path;
        impl $init:path;
        impl $update:path;
        impl $update_multi:path;
        impl $update_last:path;
        impl $finish:path;
    ) => {
        #[derive(Clone)]
        pub struct $name {
            state: [$s; $size],
            block: [u8; $block],
            pos: usize
        }

        impl $name {
            pub const BLOCK_LENGTH: usize = $block;
            pub const HASH_LENGTH: usize = $outlen;

            pub fn hash(output: &mut [u8; $outlen], input: &[u8]) {
                unsafe { $hash(output.as_mut_ptr(), input.as_ptr() as _, input.len() as _) };
            }
        }

        impl Default for $name {
            fn default() -> Self {
                let mut state = [0; $size];
                unsafe { $init(state.as_mut_ptr()) };
                $name { state, block: [0; $block], pos: 0 }
            }
        }

        impl $name {
            pub fn update(&mut self, buf: &[u8]) {
                let len = buf.len();
                let br = $block - self.pos;

                if len >= br {
                    self.block[self.pos..][..br].copy_from_slice(&buf[..br]);
                    unsafe { $update(self.state.as_mut_ptr(), self.block.as_ptr() as _) };
                    self.pos = 0;
                } else {
                    self.block[self.pos..][..len].copy_from_slice(buf);
                    self.pos += len;
                    return;
                }

                let buf = &buf[br..];
                let len = buf.len();
                let n1 = len / $block;
                let r = len % $block;

                unsafe { $update_multi(self.state.as_mut_ptr(), buf.as_ptr() as _, n1 as _) };

                self.block[..r].copy_from_slice(&buf[n1 * $block..][..r]);
                self.pos = r;
            }

            pub fn finish(mut self, buf: &mut [u8; $outlen]) {
                unsafe {
                    $update_last(self.state.as_mut_ptr(), self.block.as_ptr() as _, self.pos as _);
                    $finish(self.state.as_ptr() as _, buf.as_mut_ptr());
                }
            }
        }
    }
}

sha2!{
    pub struct Sha256 {
        state: [u32; 137],
        block: [u8; 64]
    }

    const HASH_LENGTH = 32;

    impl ffi::sha2_256::Hacl_SHA2_256_hash;
    impl ffi::sha2_256::Hacl_SHA2_256_init;
    impl ffi::sha2_256::Hacl_SHA2_256_update;
    impl ffi::sha2_256::Hacl_SHA2_256_update_multi;
    impl ffi::sha2_256::Hacl_SHA2_256_update_last;
    impl ffi::sha2_256::Hacl_SHA2_256_finish;
}

sha2!{
    pub struct Sha384 {
        state: [u64; 169],
        block: [u8; 128]
    }

    const HASH_LENGTH = 48;

    impl ffi::sha2_384::Hacl_SHA2_384_hash;
    impl ffi::sha2_384::Hacl_SHA2_384_init;
    impl ffi::sha2_384::Hacl_SHA2_384_update;
    impl ffi::sha2_384::Hacl_SHA2_384_update_multi;
    impl ffi::sha2_384::Hacl_SHA2_384_update_last;
    impl ffi::sha2_384::Hacl_SHA2_384_finish;
}

sha2!{
    pub struct Sha512 {
        state: [u64; 169],
        block: [u8; 128]
    }

    const HASH_LENGTH = 64;

    impl ffi::sha2_512::Hacl_SHA2_512_hash;
    impl ffi::sha2_512::Hacl_SHA2_512_init;
    impl ffi::sha2_512::Hacl_SHA2_512_update;
    impl ffi::sha2_512::Hacl_SHA2_512_update_multi;
    impl ffi::sha2_512::Hacl_SHA2_512_update_last;
    impl ffi::sha2_512::Hacl_SHA2_512_finish;
}
