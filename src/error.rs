#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[cfg(feature = "json")]
    #[error("JSON parsing error: {0}")]
    ParseJson(serde_json::Error),
    #[error("Integer parsing error: {0}")]
    ParseInteger(std::num::ParseIntError),
    #[error("Expiration parsing error: {0}")]
    ParseExpire(String),
    #[error("Solution expired: {0}")]
    VerificationFailedExpired(String),
    #[error("Solution does not match the challenge: {0}")]
    VerificationMismatchChallenge(String),
    #[error("Signature in the solution does not match the challenge: {0}")]
    VerificationMismatchSignature(String),
    #[error("Max number reached: {0}")]
    SolveChallengeMaxNumberReached(String),
    #[error("Wrong challenge input: {0}")]
    WrongChallengeInput(String),
    #[error("Altcha error: {0}")]
    General(String),
    #[error("Error in the randomizer: {0}")]
    RandError(rand::distr::uniform::Error),
}

impl From<rand::distr::uniform::Error> for Error {
    fn from(value: rand::distr::uniform::Error) -> Self {
        Error::RandError(value)
    }
}

#[cfg(feature = "json")]
impl From<serde_json::Error> for Error {
    fn from(other: serde_json::Error) -> Self {
        Self::ParseJson(other)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(other: std::num::ParseIntError) -> Self {
        Self::ParseInteger(other)
    }
}
