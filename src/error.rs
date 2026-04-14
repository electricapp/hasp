/// Structured error type with optional cause chain — replaces `anyhow` with
/// zero dependencies while preserving context layers for programmatic access.
use std::fmt;

#[derive(Debug)]
pub(crate) struct Error {
    msg: String,
    cause: Option<Box<Self>>,
}

impl Error {
    pub(crate) const fn new(msg: String) -> Self {
        Self { msg, cause: None }
    }

    /// Access the top-level error message (without the cause chain).
    pub(crate) fn msg(&self) -> &str {
        &self.msg
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)?;
        if let Some(cause) = &self.cause {
            write!(f, ": {cause}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_deref().map(|e| {
            let r: &(dyn std::error::Error + 'static) = e;
            r
        })
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new(e.to_string())
    }
}

impl From<yaml_rust2::ScanError> for Error {
    fn from(e: yaml_rust2::ScanError) -> Self {
        Self::new(format!("YAML parse error: {e}"))
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Adds `.context("msg")` to any `Result<T, E: Display>`, wrapping the
/// original error as a structured cause rather than flattening to a string.
pub(crate) trait Context<T> {
    fn context(self, msg: impl fmt::Display) -> Result<T>;
}

impl<T, E: fmt::Display> Context<T> for std::result::Result<T, E> {
    fn context(self, msg: impl fmt::Display) -> Result<T> {
        self.map_err(|e| Error {
            msg: msg.to_string(),
            cause: Some(Box::new(Error::new(e.to_string()))),
        })
    }
}

impl<T> Context<T> for Option<T> {
    fn context(self, msg: impl fmt::Display) -> Result<T> {
        self.ok_or_else(|| Error::new(msg.to_string()))
    }
}

/// Early-exit with a formatted error (replaces `anyhow::bail!`).
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::error::Error::new(format!($($arg)*)))
    };
}

pub(crate) use bail;
