// Language: Rust 2021 | File: src/error.rs | Target: Transport-agnostic CoreError shared by PyO3 & C-ABI FFI
use std::fmt;

#[derive(Debug, Clone)]
pub enum CoreError {
    Value(String),
    Runtime(String),
}

pub type CoreResult<T> = Result<T, CoreError>;

impl CoreError {
    pub fn value(msg: impl Into<String>) -> Self {
        Self::Value(msg.into())
    }

    pub fn runtime(msg: impl Into<String>) -> Self {
        Self::Runtime(msg.into())
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Value(s) | Self::Runtime(s) => s.as_str(),
        }
    }

    /// Split `[kind] detail` tags emitted by transport layers into `(kind, clean_message)`.
    pub fn split_kind(&self) -> (&str, &str) {
        let msg = self.message();
        if let Some(rest) = msg.strip_prefix('[') {
            if let Some((kind, detail)) = rest.split_once(']') {
                return (kind.trim(), detail.trim());
            }
        }
        match self {
            Self::Value(_) => ("value", msg),
            Self::Runtime(_) => ("request", msg),
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for CoreError {}

#[cfg(feature = "python")]
impl From<CoreError> for pyo3::PyErr {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::Value(msg) => pyo3::exceptions::PyValueError::new_err(msg),
            CoreError::Runtime(msg) => pyo3::exceptions::PyRuntimeError::new_err(msg),
        }
    }
}
