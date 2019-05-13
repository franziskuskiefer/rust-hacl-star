use hacl_star_sys as ffi;

#[derive(Default, Clone, Debug)]
struct Inner {
    r: [u64; 3],
    h: [u64; 3],
}

#[derive(Clone, Debug)]
pub struct Poly1305 {
    state: Inner,
    key: [u8; 16],
    block: [u8; 16],
    pos: usize,
}

impl Poly1305 {
    pub const BLOCK_LENGTH: usize = 16;
    pub const HASH_LENGTH: usize = 16;

    pub fn onetimeauth(output: &mut [u8; 16], input: &[u8], key: &[u8; 32]) {
        unsafe {
            ffi::poly1305::Hacl_Poly1305_64_crypto_onetimeauth(
                output.as_mut_ptr(),
                input.as_ptr() as _,
                input.len() as _,
                key.as_ptr() as _,
            );
        }
    }
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Poly1305 {
        let mut state = Inner::default();

        unsafe {
            let state = ffi::poly1305::Hacl_Poly1305_64_mk_state(
                state.r.as_mut_ptr(),
                state.h.as_mut_ptr(),
            );
            ffi::poly1305::Hacl_Poly1305_64_init(state, key.as_ptr() as _);
        }

        let mut key2 = [0; 16];
        key2.copy_from_slice(&key[16..]);

        Poly1305 {
            state,
            key: key2,
            block: [0; 16],
            pos: 0,
        }
    }

    pub fn update(&mut self, buf: &[u8]) {
        let len = buf.len();
        let br = Self::BLOCK_LENGTH - self.pos;

        unsafe {
            let state = ffi::poly1305::Hacl_Poly1305_64_mk_state(
                self.state.r.as_mut_ptr(),
                self.state.h.as_mut_ptr(),
            );

            if len >= br {
                self.block[self.pos..][..br].copy_from_slice(&buf[..br]);
                ffi::poly1305::Hacl_Poly1305_64_update_block(state, self.block.as_ptr() as _);
                self.pos = 0;
            } else {
                self.block[self.pos..][..len].copy_from_slice(buf);
                self.pos += len;
                return;
            }

            let buf = &buf[br..];
            let len = buf.len();
            let n = len / Self::BLOCK_LENGTH;
            let r = len % Self::BLOCK_LENGTH;

            ffi::poly1305::Hacl_Poly1305_64_update(state, buf.as_ptr() as _, n as _);

            self.block[..r].copy_from_slice(&buf[n * Self::BLOCK_LENGTH..][..r]);
            self.pos = r;
        }
    }

    pub fn finish(mut self, buf: &mut [u8; 16]) {
        unsafe {
            let state = ffi::poly1305::Hacl_Poly1305_64_mk_state(
                self.state.r.as_mut_ptr(),
                self.state.h.as_mut_ptr(),
            );

            ffi::poly1305::Hacl_Poly1305_64_update_last(
                state,
                self.block.as_ptr() as _,
                self.pos as _,
            );
            ffi::poly1305::Hacl_Poly1305_64_finish(state, buf.as_mut_ptr(), self.key.as_ptr() as _);
        }
    }
}
