
use std::io::{Write,Read};
use hyper::server::{Request, Response};
use hyper::uri::RequestUri;
use hyper::header::{Authorization, Basic, Location, ContentType, CacheDirective, CacheControl,
                    Pragma};
use hyper::status::StatusCode;
use url::Url;
use {ClientData, OauthError};

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

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum TokenErrorCode {
    #[serde(rename="invalid_request")]
    InvalidRequest,
    #[serde(rename="invalid_client")]
    InvalidClient,
    #[serde(rename="invalid_grant")]
    InvalidGrant,
    #[serde(rename="unauthorized_client")]
    UnauthorizedClient,
    #[serde(rename="unsupported_grant_type")]
    UnsupportedGrantType,
    #[serde(rename="invalid_scope")]
    InvalidScope,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenError {
    pub error: TokenErrorCode,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
}

impl TokenError {
    /// Serde serialization serializes all fields, even the ones that are None.
    /// But the standard suggests they should be left out entirely if they do not
    /// apply.  This function skips fields that are None.  JSON Serde deserializer
    /// will deserialize missing fields as None, so we can use serde for the
    /// reverse.
    pub fn as_json(&self) -> String {
        let mut json_str = format!("{{\r\n  \"error\": \"{}\"",
                                   ::serde_json::to_string(&self.error).unwrap());

        if self.error_description.is_some() {
            json_str.push_str( &*format!(",\r\n  \"error_description\": {}",
                                     self.error_description.as_ref().unwrap()) );
        }
        if self.error_uri.is_some() {
            json_str.push_str( &*format!(",\r\n  \"error_uri\": {}",
                                     self.error_uri.as_ref().unwrap()) );
        }
        json_str.push_str("\r\n}");
        json_str
    }
}

#[derive(Clone, Debug)]
pub struct AuthzRequestData {
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

#[derive(Deserialize, Debug)]
pub struct TokenData {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u32>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

impl TokenData {
    /// Serde serialization serializes all fields, even the ones that are None.
    /// But the standard suggests they should be left out entirely if they do not
    /// apply.  This function skips fields that are None.  JSON Serde deserializer
    /// will deserialize missing fields as None, so we can use serde for the
    /// reverse.
    pub fn as_json(&self) -> String {
        let mut json_str = format!("{{\r\n  \"access_token\": \"{}\",\r\n  \"token_type\": \"{}\"",
                               self.access_token, self.token_type);

        if self.expires_in.is_some() {
            json_str.push_str( &*format!(",\r\n  \"expires_in\": {}",
                                     self.expires_in.as_ref().unwrap()) );
        }
        if self.refresh_token.is_some() {
            json_str.push_str( &*format!(",\r\n  \"refresh_token\": {}",
                                     self.refresh_token.as_ref().unwrap()) );
        }
        if self.scope.is_some() {
            json_str.push_str( &*format!(",\r\n  \"scope\": {}",
                                     self.scope.as_ref().unwrap()) );
        }
        json_str.push_str("\r\n}");
        json_str
    }
}

header! { (WwwAuthenticate, "WWW-Authenticate") => [String] }

macro_rules! token_response_fail {
    ($response:ident, $status_opt:expr, $error:expr, $description:expr, $uri:expr) => {
        {
            *$response.status_mut() = match $status_opt {
                Some(s) => s,
                None => StatusCode::BadRequest
            };
            let error_data = TokenError {
                error: $error,
                error_description: $description.map(|s: &str| s.to_owned()),
                error_uri: $uri,
            };
            let body = error_data.as_json();
            let mut response = $response.start().unwrap();
            response.write_all(body.as_bytes()).unwrap();
            let _ = response.end();
            return;
        }
    };
    ($response:ident, $status_opt:expr, $error:expr, $description:expr) => {
        token_response_fail!($response, $status_opt, $error, $description, None)
    };
    ($response:ident, $status_opt:expr, $error:expr) => {
        token_response_fail!($response, $status_opt, $error, None, None)
    };
}

pub trait AuthzServer
{
    /// Generate a new, unique, `ClientID`
    // This is part of registering a Client, outside of the scope of the RFC proper.
    fn generate_new_client_id(&mut self) -> String;

    /// Register a new client
    // This is part of registering a Client, outside of the scope of the RFC proper.
    fn register_new_client(&mut self, client_data: ClientData) -> bool;

    /// Retrieve client data
    fn fetch_client_data(&self, client_id: String) -> Option<ClientData>;

    /// Store an issued authentication code, along with the client it was issued to and the
    /// redirect_uri that it was issued under.
    fn store_client_authorization(&mut self, code: String, client_id: String,
                                  redirect_url: Option<String>);

    /// Retrieve the data associated with an issued authentication code (the first field is
    /// the client id).
    fn retrieve_client_authorization(&self, code: String) -> Option<(String, Option<String>)>;

    /// Issue token to client, recording the issuance internally.
    fn issue_token_to_client(&mut self, client_id: String) -> TokenData;

    /// Handle an HTTP request at the authorization endpoint
    /// (From a user-agent, redirected by a client)
    ///
    /// This function parses and validates the request.  Then it forms the request data
    /// and returns it to the caller.  The caller should then:
    ///  1) Check if the return value has error set.  If so, call back into
    ///     finish_authz_request() to pass that error on.
    ///  2) Authenticate the user (this may involve multiple HTTP round trips).  If failed,
    ///     set error to AccessDenied and pass on to finish_authz_request().
    ///  3) Authorize the request (generally by asking the user if this is what they want)
    ///     If denied, set error to AccessDenied and pass on to finish_authz_request().
    ///  4) If all went well, set authorization_code and pass on to finish_authz_request().
    ///
    /// Refer to rfc6749 section 3.1 as to the requirements of the URL endpoint that
    /// performs this task (TLS, no fragment, support of GET with POST optional)
    fn handle_authz_request(&self, request: Request) -> Result<AuthzRequestData, OauthError>
    {
        // Get request URI, so we can get parameters out of it's query string
        let uri_string: &String = match request.uri {
            RequestUri::AbsolutePath(ref s) => s,
            _ => {
                // rfc6749, section 4.1.2.1 paragraph 1, instructs us to redirect onwards
                // with error = 'invalid_request', but since we cannot get parameters out
                // of such a bad request, we have to fail early.
                return Err(OauthError::AuthzBadRequest);
            },
        };

        // Get expected (and optional) request parameters
        let mut response_type: Option<String> = None; // required
        let mut client_id: Option<String> = None; // required
        let mut redirect_uri: Option<String> = None; // optional
        let mut scope: Option<String> = None; // optional
        let mut state: Option<String> = None; // recommended, used for CSRF prevention
        let mut error: Option<AuthzError> = None; // Error to pass through, if any

        let url = try!( Url::parse( &*format!("http://DUMMY{}",uri_string)) );
        for (key,val) in url.query_pairs() {
            match &*key {
                "client_id" => client_id = Some(val.into_owned()),
                "response_type" => response_type = Some(val.into_owned()),
                "redirect_uri" => redirect_uri = Some(val.into_owned()),
                "scope" => scope = Some(val.into_owned()),
                "state" => state = Some(val.into_owned()),
                _ => {} // MUST ignore unknown parameters
            }
        }

        // FIXME -- IF redirect_uri IS MISSING
        //       -- IF redirect_uri IS INVALID
        //       -- IF redirect_uri IS MISMATCHED
        //       -- IF client_id IS MISSING
        //       -- IF client_id IS INVALID
        //   Then inform user-agent directly, DO NOT redirect.


        // Require `client_id`
        let client_id = match client_id {
            None => {
                // rfc6749, section 4.1.2.1 paragraph 1: "If the request fails due to a
                // missing, invalid, or mismatching redirection URI, or if the client
                // identifier is missing or invalid, the authorization server SHOULD
                // inform the resource owner of the error and MUST NOT automatically
                // redirect the user-agent to the invalid redirection URI.
                return Err(OauthError::AuthzMissingClientId);
            },
            Some(cid) => cid
        };

        // Verify the `client_id` matches a known client
        // (and fetch client_data for further use later on)
        let client_data = match self.fetch_client_data(client_id.clone()) {
            Some(cd) => cd,
            None => {
                // rfc6749, section 4.1.2.1 paragraph 1: "If the request fails due to a
                // missing, invalid, or mismatching redirection URI, or if the client
                // identifier is missing or invalid, the authorization server SHOULD
                // inform the resource owner of the error and MUST NOT automatically
                // redirect the user-agent to the invalid redirection URI.
                return Err(OauthError::AuthzUnknownClient);
            },
        };

        // Require `response_type` and check it
        match response_type {
            None => error = Some(AuthzError {
                error: AuthzErrorCode::InvalidRequest,
                error_description: Some("Missing `response_type` parameter.".to_owned()),
                error_uri: None,
                state: state.clone(),
            }),
            Some(rt) => if &*rt != "code" {
                error = Some(AuthzError {
                    error: AuthzErrorCode::UnsupportedResponseType,
                    error_description: Some("Respose type must be `code`.".to_owned()),
                    error_uri: None,
                    state: state.clone(),
                });
            }
        }

        // Handle `redirect_uri` if supplied
        let redirect_uri = match redirect_uri {
            None => None,
            Some(ruri) => {
                // Verify redirect_uri specified matches one of the registered
                // redirect URIs.
                let mut found: bool = false;
                for uri in &client_data.redirect_uri {
                    if uri == &*ruri {
                        found = true;
                        break;
                    }
                }
                if found==false {
                    // rfc6749, section 4.1.2.1 paragraph 1: "If the request fails due to a
                    // missing, invalid, or mismatching redirection URI, or if the client
                    // identifier is missing or invalid, the authorization server SHOULD
                    // inform the resource owner of the error and MUST NOT automatically
                    // redirect the user-agent to the invalid redirection URI.
                    return Err(OauthError::AuthzRedirectUrlNotRegistered);
                }
                Some(ruri)
            }
        };

        Ok(AuthzRequestData {
            id: None,
            client_id: client_id,
            redirect_uri: redirect_uri,
            scope: scope,
            state: state,
            authorization_code: None,
            error: error,
        })
    }

    /// This finishes an Authorization Request sequence.  It should be called
    /// after the user-agent end user has been authenticated and has approved
    /// or denied the request.  `data` should have `authorization_code` and
    /// `error` set appropriately.
    fn finish_authz_request(&mut self, mut data: AuthzRequestData, mut response: Response)
                            -> Result<(), OauthError>
    {
        // Start the redirect URL
        let mut url = match data.redirect_uri {
            Some(ref url) => try!(Url::parse(&**url)),
            None => {
                // Look up the client data
                let client_data = match self.fetch_client_data(data.client_id.clone()) {
                    Some(cd) => cd,
                    None => return Err(OauthError::AuthzUnknownClient),
                };
                // Use the first registered redirect_uri
                try!(Url::parse(&client_data.redirect_uri[0]))
            }
        };

        // Make sure authorization_code and error are in sync
        if data.authorization_code.is_none() && data.error.is_none() {
            // Not authorized, but no error set.  Set the error
            data.error = Some(AuthzError {
                error: AuthzErrorCode::UnauthorizedClient,
                error_description: None,
                error_uri: None,
                state: match data.state {
                    None => None,
                    Some(ref state) => Some(state.clone()),
                },
            });
        }
        if data.authorization_code.is_some() && data.error.is_some() {
            // code AND error were specified.  To be safe, drop the code.
            data.authorization_code = None;
        }

        if data.error.is_none() {
            // Remember that we issued this code, so the token endpoint can get and check
            // associated data
            // FIXME: add a timestamp.  We are to expire these after 10 minutes.
            self.store_client_authorization(
                data.authorization_code.as_ref().unwrap().clone(),
                data.client_id.clone(),
                data.redirect_uri.clone());

            // Put the code into the redirect url
            let auth_code = data.authorization_code.unwrap();
            url.query_pairs_mut()
                .append_pair("code", &*auth_code);

            if let Some(ref s) = data.state {
                url.query_pairs_mut()
                    .append_pair("state", s);
            }
        }
        else { //
            // Put error details into redirect url
            data.error.as_ref().unwrap().put_into_query_string(&mut url);
        }

        response.headers_mut().set(Location(url.into_string()));
        *response.status_mut() = StatusCode::Found;
        let streaming_response = response.start().unwrap();
        let _ = streaming_response.end();
        Ok(())
    }

    /// Handle an HTTP request at the token endpoint
    /// (from a client directly, via POST only)
    ///
    /// Refer to rfc6749 section 3.2 as to the requirements of the URL endpoint that
    /// performs this task (TLS, no fragment, must use POST)
    fn handle_token_request(&mut self, mut request: Request, mut response: Response)
    {
        // Start preparing the response, as we set some response data regardless
        // of success or failure.
        response.headers_mut().set(ContentType::json());
        response.headers_mut().set(CacheControl(vec![ CacheDirective::NoStore ]));
        response.headers_mut().set(Pragma::NoCache);

        // Authenticate the client using HTTP Basic Authorization
        let basic: Basic = if let Some(&Authorization(ref basic)) =
            request.headers.get::<Authorization<Basic>>()
        {
            basic.clone()
        } else {
            token_response_fail!(response, None, TokenErrorCode::InvalidClient,
                                 Some("Authorization header missing"));
        };
        let (auth_client_id, authz_credentials): (String, String) =
            match ClientData::http_basic_authentication_deconstruct(basic) {
                Ok(stuff) => stuff,
                Err(_) => token_response_fail!(response, None, TokenErrorCode::InvalidRequest,
                                               Some("Authorization header failed UTF-8 check")),
            };

        let client_data = match self.fetch_client_data(auth_client_id.clone()) {
            Some(cd) => cd,
            None => token_response_fail!(response, None, TokenErrorCode::InvalidClient,
                                         Some("No such client")),
        };
        if authz_credentials != client_data.credentials {
            response.headers_mut().set(WwwAuthenticate("Basic".to_owned()));
            token_response_fail!(response, Some(StatusCode::Unauthorized),
                                 TokenErrorCode::InvalidClient,
                                 Some("Client credentials do not match"));
        }

        // Fail if the request is bad
        match request.uri {
            RequestUri::AbsolutePath(_) => {},
            _ => token_response_fail!(response, None, TokenErrorCode::InvalidRequest,
                                      Some("Only AbsolutePath URLs are allowed")),
        };

        // Read the body as it will contain the url-encoded parameters
        let mut body: Vec<u8> = Vec::new();
        if let Err(_) = request.read_to_end(&mut body) {
            token_response_fail!(response, None, TokenErrorCode::InvalidRequest,
                                 Some("Failed to read request body"));
        }
        let body = match String::from_utf8(body) {
            Ok(b) => b,
            Err(_) => token_response_fail!(response, None, TokenErrorCode::InvalidRequest,
                                           Some("Body did not pass UTF-8 check")),
        };

        // Get expected (and optional) request parameters
        let mut grant_type: Option<String> = None;
        let mut code: Option<String> = None;
        let mut redirect_uri: Option<String> = None;

        let url = match Url::parse( &*format!("http://DUMMY?{}",body)) {
            Ok(url) => url,
            Err(_) => token_response_fail!(response, None, TokenErrorCode::InvalidRequest,
                                           Some("Unable to parse body as www-form-urlencoded")),
        };

        for (key,val) in url.query_pairs() {
            match &*key {
                "grant_type" => grant_type = Some(val.into_owned()),
                "code" => code = Some(val.into_owned()),
                "redirect_uri" => redirect_uri = Some(val.into_owned()),
                _ => {} // MUST ignore unknown parameters
            }
        }

        // Require grant_type = "authorization_code"
        match grant_type {
            None => token_response_fail!(response, None, TokenErrorCode::InvalidRequest,
                                         Some("grant_type parameter must be supplied in body")),
            Some(gt) => if gt != "authorization_code" {
                token_response_fail!(response, None, TokenErrorCode::UnsupportedGrantType);
            }
        }

        // Require code, and retrieve the data we issued with the code
        // This also verifies that the code is valid, and was issued to the
        // client in question.
        let (stored_client_id, stored_redirect_uri_opt) = match code {
            None => token_response_fail!(response, None, TokenErrorCode::InvalidRequest,
                                         Some("code parameter must be supplied in body")),
            Some(c) => match self.retrieve_client_authorization(c) {
                Some(stuff) => stuff,
                None => token_response_fail!(response, None, TokenErrorCode::InvalidGrant,
                                             Some("Invalid authorization code")),
            }
        };

        // Verify the client_id matches
        if stored_client_id != client_data.client_id {
            // FIXME: also delete the stored code and related tokens.
            token_response_fail!(response, None, TokenErrorCode::InvalidGrant,
                                 Some("client_id mismatch"));
        }

        // Verify the redirect_uri matches, if it was used originally
        if stored_redirect_uri_opt.is_some() {
            let stored_redirect_uri = stored_redirect_uri_opt.unwrap();
            match redirect_uri {
                None => token_response_fail!(response, None, TokenErrorCode::InvalidGrant,
                                             Some("redirect_uri parameter must be \
                                                   supplied in body")),
                Some(ru) => if ru != stored_redirect_uri {
                    token_response_fail!(response, None, TokenErrorCode::InvalidGrant,
                                         Some("redirect_uri parameter mismatch"));
                }
            }
        }

        // Issue token
        let token = self.issue_token_to_client(client_data.client_id);

        // JSON-ify the response.
        let body = token.as_json();

        *response.status_mut() = StatusCode::Ok;

        let mut response = response.start().unwrap();
        response.write_all(body.as_bytes()).unwrap();
        let _ = response.end();
    }
}

