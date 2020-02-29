use hacl_star_sys as ffi;


pub type Result<T> = std::result::Result<T, Error>;

pub struct Error(ffi::EverCrypt_Error_error_code);

#[inline]
pub fn from(ret: ffi::EverCrypt_Error_error_code) -> Result<()> {
    if ret == ffi::EverCrypt_Error_Success as _ {
        Ok(())
    } else {
        Err(Error(ret))
    }
}
