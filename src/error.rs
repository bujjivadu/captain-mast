use thiserror::Error;

pub type Result<T> = std::result::Result<T, MastError>;

#[derive(Debug, Error)]
pub enum MastError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Config parse error at line {line}: {message}")]
    ConfigParse { line: usize, message: String },

    #[error("Config error: {0}")]
    Config(String),

    #[error("Bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),

    #[error("Broker error: {0}")]
    Broker(String),
}
