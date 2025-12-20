use std::io;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NsError {
    #[error("IO Error: {0}")]
    Io(#[from] io::Error),

    #[error("IO Error at {path:?}: {source}")]
    IoWithPath { source: io::Error, path: PathBuf },

    #[error("Operation timed out: {0}")]
    Timeout(String),

    #[error("Required tool missing: {0}")]
    MissingBinary(String),

    #[error("Security Violation: {0}")]
    InsecureBinary(String),

    #[error("Invalid Path: {0}")]
    InvalidPath(String),

    #[error("Data Parse Error: {0}")]
    ParseError(String),

    #[error("Privilege Error: {0}")]
    InsufficientPrivileges(String),
}

pub type NsResult<T> = Result<T, NsError>;
