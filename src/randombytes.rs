use hacl_star_sys as ffi;

pub fn randombytes(buf: &mut [u8]) {
    unsafe {
        ffi::randombytes::randombytes(buf.as_mut_ptr(), buf.len() as _);
    }
}
