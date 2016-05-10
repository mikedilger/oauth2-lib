
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::convert::From;
use std::io::Error as IoError;
use std::error::Error as StdError;
use std::fmt;

/// These are errors returned to the caller
#[derive(Debug)]
pub enum OauthError {
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
    UnexpectedStatusCode
}

impl fmt::Display for OauthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match *self {
            OauthError::Utf8Error(ref e) => e.fmt(f),
            OauthError::FromUtf8Error(ref e) => e.fmt(f),
            OauthError::Url(ref e) => e.fmt(f),
            OauthError::Io(ref e) => e.fmt(f),
            ref e => write!(f, "{}", e.description()),
        }
    }
}

impl StdError for OauthError {
    fn description(&self) -> &str {
        match *self {
            OauthError::Utf8Error(_) => "UTF-8 Decoding Error",
            OauthError::FromUtf8Error(_) => "UTF-8 Decoding Error",
            OauthError::Url(_) => "URL Format Error",
            OauthError::Io(_) => "I/O Error",
            OauthError::AuthzBadRequest => "Bad Request",
            OauthError::AuthzMissingClientId => "Missing `client_id`",
            OauthError::AuthzUnknownClient => "Unknown Client",
            OauthError::AuthzRedirectUrlNotRegistered => "`redirect_url` Not Registered",
            OauthError::AuthzGrantTypeMissing => "`grant_type` Missing",
            OauthError::AuthzClientIdMismatch => "`client_id` mismatch",
            OauthError::ClientCodeMissing => "`code` Missing",
            OauthError::ClientStateMissing => "`state` Missing",
            OauthError::ClientNonceMismatch => "`nonce` Mismatch",
            OauthError::UnexpectedStatusCode => "Unexpected HTTP Status Code",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            OauthError::Utf8Error(ref e) => Some(e),
            OauthError::FromUtf8Error(ref e) => Some(e),
            OauthError::Url(ref e) => Some(e),
            OauthError::Io(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<Utf8Error> for OauthError {
    fn from(e: Utf8Error) -> OauthError {
        OauthError::Utf8Error(e)
    }
}

impl From<FromUtf8Error> for OauthError {
    fn from(e: FromUtf8Error) -> OauthError {
        OauthError::FromUtf8Error(e)
    }
}

impl From<::url::ParseError> for OauthError {
    fn from(e: ::url::ParseError) -> OauthError {
        OauthError::Url(e)
    }
}

impl From<IoError> for OauthError {
    fn from(e: IoError) -> OauthError {
        OauthError::Io(e)
    }
}
