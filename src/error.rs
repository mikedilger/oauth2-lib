
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::convert::From;
use std::io::Error as IoError;
use std::num::ParseIntError;
use std::error::Error as StdError;
use std::fmt;

/// These are errors returned to the caller
#[derive(Debug)]
pub enum OAuthError {
    Utf8Error(Utf8Error),
    FromUtf8Error(FromUtf8Error),
    Url(::url::ParseError),
    Io(IoError),
    ParseInt(ParseIntError),
    AuthzBadRequest,
    AuthzMissingClientId,
    AuthzUnknownClient,
    AuthzRedirectUrlNotRegistered,
    AuthzGrantTypeMissing,
    AuthzClientIdMismatch,
    AuthzGrantNotFound,
    ClientCodeMissing,
    ClientStateMissing,
    ClientNonceMismatch,
    UnexpectedStatusCode,
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match *self {
            OAuthError::Utf8Error(ref e) => e.fmt(f),
            OAuthError::FromUtf8Error(ref e) => e.fmt(f),
            OAuthError::Url(ref e) => e.fmt(f),
            OAuthError::Io(ref e) => e.fmt(f),
            OAuthError::ParseInt(ref e) => e.fmt(f),
            ref e => write!(f, "{}", e.description()),
        }
    }
}

impl StdError for OAuthError {
    fn description(&self) -> &str {
        match *self {
            OAuthError::Utf8Error(ref e) => e.description(),
            OAuthError::FromUtf8Error(ref e) => e.description(),
            OAuthError::Url(ref e) => e.description(),
            OAuthError::Io(ref e) => e.description(),
            OAuthError::ParseInt(ref e) => e.description(),
            OAuthError::AuthzBadRequest => "Bad Request",
            OAuthError::AuthzMissingClientId => "Missing `client_id`",
            OAuthError::AuthzUnknownClient => "Unknown Client",
            OAuthError::AuthzRedirectUrlNotRegistered => "`redirect_url` Not Registered",
            OAuthError::AuthzGrantTypeMissing => "`grant_type` Missing",
            OAuthError::AuthzClientIdMismatch => "`client_id` mismatch",
            OAuthError::AuthzGrantNotFound => "grant not found",
            OAuthError::ClientCodeMissing => "`code` Missing",
            OAuthError::ClientStateMissing => "`state` Missing",
            OAuthError::ClientNonceMismatch => "`nonce` Mismatch",
            OAuthError::UnexpectedStatusCode => "Unexpected HTTP Status Code",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            OAuthError::Utf8Error(ref e) => Some(e),
            OAuthError::FromUtf8Error(ref e) => Some(e),
            OAuthError::Url(ref e) => Some(e),
            OAuthError::Io(ref e) => Some(e),
            OAuthError::ParseInt(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<Utf8Error> for OAuthError {
    fn from(e: Utf8Error) -> OAuthError {
        OAuthError::Utf8Error(e)
    }
}

impl From<FromUtf8Error> for OAuthError {
    fn from(e: FromUtf8Error) -> OAuthError {
        OAuthError::FromUtf8Error(e)
    }
}

impl From<::url::ParseError> for OAuthError {
    fn from(e: ::url::ParseError) -> OAuthError {
        OAuthError::Url(e)
    }
}

impl From<IoError> for OAuthError {
    fn from(e: IoError) -> OAuthError {
        OAuthError::Io(e)
    }
}

impl From<ParseIntError> for OAuthError {
    fn from(e: ParseIntError) -> OAuthError {
        OAuthError::ParseInt(e)
    }
}
