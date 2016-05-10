
use std::fmt;
use std::fmt::Display;

/// Client Type, either 'confidential' or 'public'.
///
/// See RFC 6749 Section 2.2.   In particular:
/// <ul>
/// <li>If the client cannot be trusted with secrets, it is 'public'.  This usually includes
///     all clients in end-user hands like javascript ones, but strictly speaking it depends
///     on your security model.</li>
/// </ul>
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientType {
    /// Client that can confidentially store secrets
    ConfidentialClient,
    /// Client that is not trusted to confidentially store secrets
    PublicClient,
}

impl Display for ClientType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match *self {
            ClientType::ConfidentialClient => write!(f, "confidential"),
            ClientType::PublicClient => write!(f, "public"),
        }
    }
}
