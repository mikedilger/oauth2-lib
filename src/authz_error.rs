
use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Deserialize)]
pub enum AuthzErrorCode {
    #[serde(rename="invalid_request")]
    InvalidRequest,
    #[serde(rename="unauthorized_client")]
    UnauthorizedClient,
    #[serde(rename="access_denied")]
    AccessDenied,
    #[serde(rename="unsupported_response_type")]
    UnsupportedResponseType,
    #[serde(rename="invalid_scope")]
    InvalidScope,
    #[serde(rename="server_error")]
    ServerError,
    #[serde(rename="temporarily_unavailable")]
    TemporarilyUnavailable
}

impl From<AuthzErrorCode> for &'static str {
    fn from(e: AuthzErrorCode) -> &'static str {
        match e {
            AuthzErrorCode::InvalidRequest => "invalid_request",
            AuthzErrorCode::UnauthorizedClient => "unauthorized_client",
            AuthzErrorCode::AccessDenied => "access_denied",
            AuthzErrorCode::UnsupportedResponseType => "unsupported_response_type",
            AuthzErrorCode::InvalidScope => "invalid_scope",
            AuthzErrorCode::ServerError => "server_error",
            AuthzErrorCode::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthzError {
    pub error: AuthzErrorCode,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
    pub state: Option<String>,
}

impl AuthzError {
    // AuthzErrors are returned via the return_url query string parameters.
    // This function adds the error fields to the given url
    pub fn put_into_query_string(&self, url: &mut Url) {
        url.query_pairs_mut()
            .append_pair("error", <&'static str as From<AuthzErrorCode>>::from(self.error));
        if self.error_description.is_some() {
            url.query_pairs_mut()
                .append_pair("error_description", self.error_description.as_ref().unwrap());
        }
        if self.error_uri.is_some() {
            url.query_pairs_mut()
                .append_pair("error_uri", self.error_uri.as_ref().unwrap());
        }
        if self.state.is_some() {
            url.query_pairs_mut()
                .append_pair("state", self.state.as_ref().unwrap());
        }
    }
}
