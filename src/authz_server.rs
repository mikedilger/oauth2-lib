
use std::io::{Write,Read};
use hyper::server::{Request, Response};
use hyper::uri::RequestUri;
use hyper::header::{Authorization, Basic, Location, ContentType, CacheDirective, CacheControl,
                    Pragma};
use hyper::status::StatusCode;
use url::Url;
use {ClientData, OAuthError, AuthzError, AuthzErrorCode, TokenError, TokenErrorCode,
     AuthzRequest, TokenData, ClientId, RedirectUri};


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

pub trait AuthzServer<C>
{
    /// Fetch data about a registered OAuth 2.0 client (clients are the other websites
    /// which are trying to login to your website on behalf of the user, and should have
    /// been registered with your site ahead of time).
    ///
    /// Should return Ok(Some(ClientData)) if found, Ok(None) if not found, and
    /// Err(OAuthError) on error.
    ///
    /// `context` comes from whatever you pass into `handle_authz_request()`,
    /// `finish_authz_request()` or `handle_token_request()`
    fn fetch_client_data(&self, context: &mut C, client_id: &ClientId)
                         -> Result<Option<ClientData>, OAuthError>;

    /// Retrieve the data associated with an issued authentication code.
    fn retrieve_client_authorization(&self, context: &mut C, code: &str)
                                     -> Result<(ClientId, RedirectUri), OAuthError>;

    /// Issue token to client, recording the issuance internally.
    fn issue_token_to_client(&mut self, context: &mut C, code: &str, client_id: &ClientId)
                             -> Result<TokenData, OAuthError>;

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
    fn handle_authz_request(&self, context: &mut C, uri_string: &str)
                            -> Result<(AuthzRequest, Option<AuthzError>), OAuthError>
    {
        // Get expected (and optional) request parameters
        let mut response_type: Option<String> = None; // required
        let mut client_id: Option<ClientId> = None; // required
        let mut redirect_uri: Option<RedirectUri> = None; // optional
        let mut scope: Option<String> = None; // optional
        let mut state: Option<String> = None; // recommended, used for CSRF prevention
        let url = try!( Url::parse( uri_string) );
        for (key,val) in url.query_pairs() {
            match &*key {
                "client_id" => client_id = Some(ClientId(val.into_owned())),
                "response_type" => response_type = Some(val.into_owned()),
                "redirect_uri" => redirect_uri = Some(RedirectUri(val.into_owned())),
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
                return Err(OAuthError::AuthzMissingClientId);
            },
            Some(cid) => cid
        };

        // Verify the `client_id` matches a known client
        // (and fetch client_data for further use later on)
        if let None = try!(self.fetch_client_data(context, &client_id))
        {
            // rfc6749, section 4.1.2.1 paragraph 1: "If the request fails due to a
            // missing, invalid, or mismatching redirection URI, or if the client
            // identifier is missing or invalid, the authorization server SHOULD
            // inform the resource owner of the error and MUST NOT automatically
            // redirect the user-agent to the invalid redirection URI.
            return Err(OAuthError::AuthzUnknownClient);
        };

        let mut error: Option<AuthzError> = None; // Error to pass through, if any

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

        Ok((AuthzRequest {
            client_id: client_id,
            redirect_uri: redirect_uri,
            scope: scope,
            state: state,
        }, error))
    }

    /// This resolves the redirect_uri by using the one from the request (you should
    /// pass that in from AuthzRequest.redirect_uri) if it is valid, or else using
    /// the first one registered with the client if the request did not specify one.
    fn resolve_redirect_uri(&mut self, context: &mut C, client_id: &ClientId,
                            request_redirect_uri: Option<&RedirectUri>)
                            -> Result<RedirectUri, OAuthError>
    {
        // Look up the client data
        let client_data = match try!(self.fetch_client_data(
            context, client_id))
        {
            Some(cd) => cd,
            None => return Err(OAuthError::AuthzUnknownClient),
        };

        // Get the redirect_uri
        let cru: &RedirectUri = match request_redirect_uri {
            Some(ref uri) => uri,
            None => return Ok(client_data.redirect_uri[0].clone())
        };

        // Verify cru is a valid redirect uri
        for validuri in &client_data.redirect_uri {
            if cru == validuri {
                return Ok(cru.clone())
            }
        }
        // rfc6749, section 4.1.2.1 paragraph 1: "If the request fails due to a
        // missing, invalid, or mismatching redirection URI, or if the client
        // identifier is missing or invalid, the authorization server SHOULD
        // inform the resource owner of the error and MUST NOT automatically
        // redirect the user-agent to the invalid redirection URI.
        Err(OAuthError::AuthzRedirectUrlNotRegistered)
    }

    /// This finishes an Authorization Request sequence if you have granted the
    /// request.  It should be called after the user-agent end user has been
    /// authenticated and has approved or denied the request.
    fn grant_authz_request(&mut self, mut response: Response,
                           redirect_uri: &RedirectUri, authorization_code: String,
                           state: Option<String>) -> Result<(), OAuthError>
    {
        // Start the redirect URL
        let mut url = try!(Url::parse(&***redirect_uri));

        // Put the code into the redirect url
        url.query_pairs_mut()
            .append_pair("code", &*authorization_code);

        // Put the state into the redirect url, if some
        if let Some(ref s) = state {
            url.query_pairs_mut()
                .append_pair("state", s);
        }

        // Do the redirect
        response.headers_mut().set(Location(url.into_string()));
        *response.status_mut() = StatusCode::Found;
        let streaming_response = response.start().unwrap();
        let _ = streaming_response.end();
        Ok(())
    }

    /// This finishes an Authorization Request sequence if you have denied the
    /// request.
    fn deny_authz_request(&mut self, mut response: Response,
                          redirect_uri: &RedirectUri, error: AuthzError)
                          -> Result<(), OAuthError>
    {
        // Start the redirect URL
        let mut url = try!(Url::parse(&***redirect_uri));

        // Put error details into the redirect url
        error.put_into_query_string(&mut url);

        // Do the redirect
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
    fn handle_token_request(&mut self, context: &mut C,
                            mut request: Request, mut response: Response)
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
        let (auth_client_id, authz_credentials): (ClientId, String) =
            match ClientData::http_basic_authentication_deconstruct(basic) {
                Ok(stuff) => stuff,
                Err(_) => token_response_fail!(response, None, TokenErrorCode::InvalidRequest,
                                               Some("Authorization header failed UTF-8 check")),
            };

        let client_data = match self.fetch_client_data(context, &auth_client_id) {
            Err(_) => token_response_fail!(response, None, TokenErrorCode::InvalidClient,
                                           Some("No such client")),
            Ok(v) => match v {
                Some(cd) => cd,
                None => token_response_fail!(response, None, TokenErrorCode::InvalidClient,
                                             Some("No such client")),
            }
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
        let mut redirect_uri: Option<RedirectUri> = None;

        let url = match Url::parse( &*format!("http://DUMMY?{}",body)) {
            Ok(url) => url,
            Err(_) => token_response_fail!(response, None, TokenErrorCode::InvalidRequest,
                                           Some("Unable to parse body as www-form-urlencoded")),
        };

        for (key,val) in url.query_pairs() {
            match &*key {
                "grant_type" => grant_type = Some(val.into_owned()),
                "code" => code = Some(val.into_owned()),
                "redirect_uri" => redirect_uri = Some(RedirectUri(val.into_owned())),
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
        let (stored_client_id, stored_redirect_uri): (ClientId, RedirectUri) = match code {
            None => token_response_fail!(response, None, TokenErrorCode::InvalidRequest,
                                         Some("code parameter must be supplied in body")),
            Some(ref c) => match self.retrieve_client_authorization(context, c)
            {
                Ok(pair) => pair,
                _ => token_response_fail!(response, None, TokenErrorCode::InvalidGrant,
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
        if redirect_uri.is_some() {
            match redirect_uri {
                None => token_response_fail!(response, None, TokenErrorCode::InvalidGrant,
                                             Some("redirect_uri parameter must be \
                                                   supplied in body")),
                Some(ru) => if &ru != &stored_redirect_uri {
                    token_response_fail!(response, None, TokenErrorCode::InvalidGrant,
                                         Some("redirect_uri parameter mismatch"));
                }
            }
        }

        // Issue token
        let token = match self.issue_token_to_client(context, code.as_ref().unwrap(),
                                                     &client_data.client_id) {
            Ok(t) => t,
            Err(_) => token_response_fail!(response, None, TokenErrorCode::InvalidGrant,
                                           None),
        };

        // JSON-ify the response.
        let body = token.as_json();

        *response.status_mut() = StatusCode::Ok;

        let mut response = response.start().unwrap();
        response.write_all(body.as_bytes()).unwrap();
        let _ = response.end();
    }
}

