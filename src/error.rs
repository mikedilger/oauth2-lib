
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::convert::From;
use std::io::Error as IoError;
use std::error::Error as StdError;
use std::fmt;

/// A trait for Errors produced by the consumer of this library
pub trait UserError: StdError { }

/// These are errors returned to the caller
#[derive(Debug)]
pub enum OAuthError<E: UserError> {
    Utf8Error(Utf8Error),
    FromUtf8Error(FromUtf8Error),
    Url(::url::ParseError),
    Io(IoError),
    AuthzBadRequest,
    AuthzMissingClientId,
    AuthzUnknownClient,
    AuthzRedirectUrlNotRegistered,
    AuthzGrantTypeMissing,
    AuthzClientIdMismatch,
    ClientCodeMissing,
    ClientStateMissing,
    ClientNonceMismatch,
    UnexpectedStatusCode,
    UserError(E),
}

impl<E: UserError> fmt::Display for OAuthError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match *self {
            OAuthError::Utf8Error(ref e) => e.fmt(f),
            OAuthError::FromUtf8Error(ref e) => e.fmt(f),
            OAuthError::Url(ref e) => e.fmt(f),
            OAuthError::Io(ref e) => e.fmt(f),
            OAuthError::UserError(ref e) => fmt::Display::fmt(e,f),
            ref e => write!(f, "{}", e.description()),
        }
    }
}

impl<E: UserError> StdError for OAuthError<E> {
    fn description(&self) -> &str {
        match *self {
            OAuthError::Utf8Error(ref e) => e.description(),
            OAuthError::FromUtf8Error(ref e) => e.description(),
            OAuthError::Url(ref e) => e.description(),
            OAuthError::Io(ref e) => e.description(),
            OAuthError::AuthzBadRequest => "Bad Request",
            OAuthError::AuthzMissingClientId => "Missing `client_id`",
            OAuthError::AuthzUnknownClient => "Unknown Client",
            OAuthError::AuthzRedirectUrlNotRegistered => "`redirect_url` Not Registered",
            OAuthError::AuthzGrantTypeMissing => "`grant_type` Missing",
            OAuthError::AuthzClientIdMismatch => "`client_id` mismatch",
            OAuthError::ClientCodeMissing => "`code` Missing",
            OAuthError::ClientStateMissing => "`state` Missing",
            OAuthError::ClientNonceMismatch => "`nonce` Mismatch",
            OAuthError::UnexpectedStatusCode => "Unexpected HTTP Status Code",
            OAuthError::UserError(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            OAuthError::Utf8Error(ref e) => Some(e),
            OAuthError::FromUtf8Error(ref e) => Some(e),
            OAuthError::Url(ref e) => Some(e),
            OAuthError::Io(ref e) => Some(e),
            OAuthError::UserError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl<E: UserError> From<Utf8Error> for OAuthError<E> {
    fn from(e: Utf8Error) -> OAuthError<E> {
        OAuthError::Utf8Error(e)
    }
}

impl<E: UserError> From<FromUtf8Error> for OAuthError<E> {
    fn from(e: FromUtf8Error) -> OAuthError<E> {
        OAuthError::FromUtf8Error(e)
    }
}

impl<E: UserError> From<::url::ParseError> for OAuthError<E> {
    fn from(e: ::url::ParseError) -> OAuthError<E> {
        OAuthError::Url(e)
    }
}

impl<E: UserError> From<IoError> for OAuthError<E> {
    fn from(e: IoError) -> OAuthError<E> {
        OAuthError::Io(e)
    }
}

impl<E: UserError> From<E> for OAuthError<E> {
    fn from(e: E) -> OAuthError<E> {
        OAuthError::UserError(e)
    }
}
