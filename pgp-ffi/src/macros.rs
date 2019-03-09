#[macro_export]
macro_rules! try_ffi {
    ($e:expr, $fmt:expr) => {
        match $e {
            Ok(v) => v,
            Err(err) => {
                $crate::errors::update_last_error(err.into());
                return std::ptr::null_mut();
            }
        }
    };
}
