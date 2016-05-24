
use AuthzError;

/// This is the data that the client sends to the authz_server when requesting an
/// authorization grant, as defined in RFC 6749 section 4.1.1
#[derive(Clone, Debug)]
pub struct AuthzRequest {
    /// Some token to distinguish this request
    pub id: Option<String>,

    // We do not support response_type other than "code"
    // pub response_type: String,

    /// client_id as supplied in the request
    pub client_id: String,

    /// redirect_uri as supplied in the request, or None if not supplied
    pub redirect_uri: Option<String>,

    /// scope as supplied in the request
    pub scope: Option<String>,

    /// state as supplied in the request.  We recommend implementations should
    /// error if a state was not supplied in the request.
    pub state: Option<String>,

    /// The authorization code, IF the request has been approved.
    pub authorization_code: Option<String>,

    /// An error, if an error has occurred
    pub error: Option<AuthzError>
}
