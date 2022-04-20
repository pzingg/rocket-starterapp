//! Use anyhow errors as valid responses.

use std::fmt;

use rocket::http::Status;
use rocket::request::Request;
use rocket::response;
use rocket::response::Responder;

/// Wrapper around [`anyhow::Error`]
/// with rocket's [responder] implemented
///
/// [anyhow::Error]: https://docs.rs/anyhow/1.0/anyhow/struct.Error.html
/// [responder]: https://api.rocket.rs/v0.5-rc/rocket/response/trait.Responder.html
/// Error that can be convert into `anyhow::Error` can be convert directly to this type.
///
/// Responder part are internally delegated to [rocket::response::Debug] which
/// "debug prints the internal value before responding with a 500 error"
///
/// [rocket::response::Debug]: https://api.rocket.rs/v0.5-rc/rocket/response/struct.Debug.html
#[derive(Debug)]
pub struct Error {
    pub error: anyhow::Error,
    pub status: Status,
}

pub type Result<T = ()> = std::result::Result<T, Error>;

impl<E> From<E> for Error
where
    E: Into<anyhow::Error>,
{
    /// When converting from a generic error, set status to 500
    fn from(error: E) -> Self {
        Error {
            error: error.into(),
            status: Status::InternalServerError,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.error, self.status.code)
    }
}

impl Error {
    /// Constructor for a generic error and an HTTP status
    pub fn with_status<E: Into<anyhow::Error>>(error: E, status: Status) -> Self {
        Self {
            error: error.into(),
            status,
        }
    }
}

impl<'r, 'o: 'r> Responder<'r, 'o> for Error {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'o> {
        // log `self` to your favored error tracker, e.g.
        // sentry::capture_error(&self);

        self.status.respond_to(req)
    }
}

