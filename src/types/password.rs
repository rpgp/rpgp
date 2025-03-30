use zeroize::Zeroizing;

/// Wraps around a callback to unlock keys.
#[derive(derive_more::Debug)]
pub enum Password {
    Dynamic(#[debug("Box<Fn>")] Box<dyn Fn() -> Zeroizing<Vec<u8>> + 'static + Send + Sync>),
    Static(#[debug("***")] Zeroizing<Vec<u8>>),
}

impl From<String> for Password {
    fn from(value: String) -> Self {
        Self::Static(value.as_bytes().to_vec().into())
    }
}

impl From<&str> for Password {
    fn from(value: &str) -> Self {
        Self::Static(value.as_bytes().to_vec().into())
    }
}

impl From<&[u8]> for Password {
    fn from(value: &[u8]) -> Self {
        Self::Static(value.to_vec().into())
    }
}

impl Default for Password {
    fn default() -> Self {
        Self::empty()
    }
}

impl Password {
    /// Creates an empty password unlocker.
    pub fn empty() -> Self {
        Self::Static(Vec::new().into())
    }

    /// Executes the callback and returns the result.
    pub fn read(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::Dynamic(ref f) => f(),
            Self::Static(ref s) => s.clone(),
        }
    }
}

impl<F: Fn() -> Zeroizing<Vec<u8>> + 'static + Send + Sync> From<F> for Password {
    fn from(value: F) -> Self {
        Self::Dynamic(Box::new(value))
    }
}
