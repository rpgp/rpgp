use std::slice;

/// Represents a vector, that can be passed to C land.
/// Has to be deallocated using [rpgp_cvec_drop], otherwise leaks memory.
#[repr(C)]
#[derive(Debug)]
pub struct cvec {
    data: *mut u8,
    len: libc::size_t,
}

impl PartialEq for cvec {
    fn eq(&self, other: &cvec) -> bool {
        if self.len != other.len {
            return false;
        }

        unsafe {
            slice::from_raw_parts(self.data, self.len)
                == slice::from_raw_parts(other.data, other.len)
        }
    }
}

impl Eq for cvec {}

impl Into<cvec> for Vec<u8> {
    fn into(mut self) -> cvec {
        self.shrink_to_fit();
        assert!(self.len() == self.capacity());

        let res = cvec {
            data: self.as_mut_ptr(),
            len: self.len() as libc::size_t,
        };

        // prevent deallocation in Rust
        std::mem::forget(self);
        res
    }
}

impl Into<Vec<u8>> for cvec {
    fn into(self) -> Vec<u8> {
        unsafe { Vec::from_raw_parts(self.data, self.len, self.len) }
    }
}

/// Get the length of the data of the given [cvec].
#[no_mangle]
pub unsafe extern "C" fn rpgp_cvec_len(cvec_ptr: *mut cvec) -> libc::size_t {
    assert!(!cvec_ptr.is_null());

    let cvec = &*cvec_ptr;
    cvec.len
}

/// Get a pointer to the data of the given [cvec].
#[no_mangle]
pub unsafe extern "C" fn rpgp_cvec_data(cvec_ptr: *mut cvec) -> *const u8 {
    assert!(!cvec_ptr.is_null());

    let cvec = &*cvec_ptr;
    cvec.data
}

/// Free the given [cvec].
#[no_mangle]
pub unsafe extern "C" fn rpgp_cvec_drop(cvec_ptr: *mut cvec) {
    assert!(!cvec_ptr.is_null());

    let v = &*cvec_ptr;
    let _ = Vec::from_raw_parts(v.data, v.len, v.len);
    // Drop
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvec() {
        for i in 0..100 {
            let a = vec![i as u8; i * 10];
            let b: cvec = a.clone().into();
            let c: Vec<u8> = b.into();
            assert_eq!(a, c);
        }
    }
}
