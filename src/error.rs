#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "json")]
    ParseJson(serde_json::Error),
    ParseInteger(std::num::ParseIntError),
    ParseExpire(String),
    VerificationFailedExpired(String),
    VerificationMismatchChallenge(String),
    VerificationMismatchSignature(String),
    SolveChallengeMaxNumberReached(String),
    WrongChallengeInput(String),
    General(String),
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
