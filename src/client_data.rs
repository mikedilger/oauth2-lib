
use std::str::Utf8Error;
use url::percent_encoding::{QUERY_ENCODE_SET, percent_encode, percent_decode};
use hyper::header::{Authorization, Basic};
use ClientType;

/// Client data is registered with the Authorization Service prior to the OAuth 2.0
/// protocol commencing.  This can be done with config files for well-known clients.
/// It can be done online as well prior to the OAuth 2.0 protocol proper.
#[derive(Clone, Debug)]
pub struct ClientData {

    /// Client Identifier.  Required.  Must be unique across the Authorization Service and
    /// so is typically issued by the Authorization Service.  Also used to fetch this
    /// entire record.
    pub client_id: String,

    /// Client Type.  Required, even if your implementation only ever uses one type.
    pub client_type: ClientType,

    /// Redirect URL(s) as Strings.  Required for public clients, required if the client has
    /// multiple, otherwise optional but SHOULD be supplied anyway.  The first one is used
    /// if not supplied in the protocol.
    pub redirect_uri: Vec<String>,

    /// Client Credentials, serialized.  Required, but the details are out of scope.
    pub credentials: String,

    /// Authentication Scheme, serialized.  Only required if multiple authentication schemes
    /// are implemented and the server needs to know which one this client is using.
    pub authn_scheme: Option<String>,
}

impl ClientData {
    pub fn http_basic_authentication_generate(&self) -> Authorization<Basic> {

        let username: String = percent_encode(
            self.client_id.as_bytes(), QUERY_ENCODE_SET).collect::<String>();
        let password: String = percent_encode(
            self.credentials.as_bytes(), QUERY_ENCODE_SET).collect::<String>();

        Authorization(
            Basic {
                username: username,
                password: Some(password),
            }
        )
    }

    pub fn http_basic_authentication_deconstruct(basic: Basic)
                                                 -> Result<(String, String), Utf8Error>
    {
        let client_id =
            try!(percent_decode(basic.username.as_bytes()).decode_utf8()).into_owned();
        let authz_credentials = if basic.password.is_none() {
            String::new()
        } else {
            try!(percent_decode(basic.password.unwrap().as_bytes()).decode_utf8()).into_owned()
        };
        Ok((client_id, authz_credentials))
    }
}
