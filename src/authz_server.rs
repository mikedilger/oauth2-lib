
use std::io::{Write,Read};
use hyper::server::{Request, Response};
use hyper::uri::RequestUri;
use hyper::header::{Authorization, Basic, Location, ContentType, CacheDirective, CacheControl,
                    Pragma};
use hyper::status::StatusCode;
use url::Url;
use {ClientData, OAuthError, UserError, AuthzError, AuthzErrorCode, TokenError, TokenErrorCode,
     AuthzRequestData, TokenData};


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

pub trait AuthzServer<C, E: UserError>
{
    /// Fetch data about a registered OAuth 2.0 client (clients are the other websites
    /// which are trying to login to your website on behalf of the user, and should have
    /// been registered with your site ahead of time).
    ///
    /// Should return Ok(Some(ClientData)) if found, Ok(None) if not found, and
    /// Err(OAuthError<E>) on error.
    ///
    /// `context` comes from whatever you pass into `handle_authz_request()`,
    /// `finish_authz_request()` or `handle_token_request()`
    fn fetch_client_data(&self, context: &mut C, client_id: String)
                         -> Result<Option<ClientData>, OAuthError<E>>;

    /// If an authorization grant has succeeded, this will be called to store

    /// Store an issued authentication code, along with the request data associated with
    /// it (in particular, the client_id it was issued to and the redirect_uri that it was
    /// issued under, and any scope if that applies).
    fn store_client_authorization(&mut self, context: &mut C, data: AuthzRequestData);

    /// Retrieve the data associated with an issued authentication code (the first field is
    /// the client id).
    fn retrieve_client_authorization(&self, context: &mut C, code: String)
                                     -> Option<AuthzRequestData>;

    /// Issue token to client, recording the issuance internally.
    fn issue_token_to_client(&mut self, context: &mut C, code: String, client_id: String)
                             -> TokenData;

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
    fn handle_authz_request(&self, context: &mut C, request: Request)
                            -> Result<AuthzRequestData, OAuthError<E>>
    {
        // Get request URI, so we can get parameters out of it's query string
        let uri_string: &String = match request.uri {
            RequestUri::AbsolutePath(ref s) => s,
            _ => {
                // rfc6749, section 4.1.2.1 paragraph 1, instructs us to redirect onwards
                // with error = 'invalid_request', but since we cannot get parameters out
                // of such a bad request, we have to fail early.
                return Err(OAuthError::AuthzBadRequest);
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
                return Err(OAuthError::AuthzMissingClientId);
            },
            Some(cid) => cid
        };

        // Verify the `client_id` matches a known client
        // (and fetch client_data for further use later on)
        let client_data = match try!(self.fetch_client_data(context, client_id.clone()))
        {
            Some(cd) => cd,
            None => {
                // rfc6749, section 4.1.2.1 paragraph 1: "If the request fails due to a
                // missing, invalid, or mismatching redirection URI, or if the client
                // identifier is missing or invalid, the authorization server SHOULD
                // inform the resource owner of the error and MUST NOT automatically
                // redirect the user-agent to the invalid redirection URI.
                return Err(OAuthError::AuthzUnknownClient);
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
                    return Err(OAuthError::AuthzRedirectUrlNotRegistered);
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
    fn finish_authz_request(&mut self, context: &mut C, mut data: AuthzRequestData,
                            mut response: Response)
                            -> Result<(), OAuthError<E>>
    {
        // Start the redirect URL
        let mut url = match data.redirect_uri {
            Some(ref url) => try!(Url::parse(&**url)),
            None => {
                // Look up the client data
                let client_data = match try!(self.fetch_client_data(
                    context, data.client_id.clone()))
                {
                    Some(cd) => cd,
                    None => return Err(OAuthError::AuthzUnknownClient),
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
                context,
                data.clone());

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
        let (auth_client_id, authz_credentials): (String, String) =
            match ClientData::http_basic_authentication_deconstruct(basic) {
                Ok(stuff) => stuff,
                Err(_) => token_response_fail!(response, None, TokenErrorCode::InvalidRequest,
                                               Some("Authorization header failed UTF-8 check")),
            };

        let client_data = match self.fetch_client_data(context, auth_client_id.clone()) {
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
        let authz_request_data = match code {
            None => token_response_fail!(response, None, TokenErrorCode::InvalidRequest,
                                         Some("code parameter must be supplied in body")),
            Some(ref c) => match self.retrieve_client_authorization(context, c.clone()) {
                Some(stuff) => stuff,
                None => token_response_fail!(response, None, TokenErrorCode::InvalidGrant,
                                             Some("Invalid authorization code")),
            }
        };

        // Verify the client_id matches
        if authz_request_data.client_id != client_data.client_id {
            // FIXME: also delete the stored code and related tokens.
            token_response_fail!(response, None, TokenErrorCode::InvalidGrant,
                                 Some("client_id mismatch"));
        }

        // Verify the redirect_uri matches, if it was used originally
        if authz_request_data.redirect_uri.is_some() {
            match redirect_uri {
                None => token_response_fail!(response, None, TokenErrorCode::InvalidGrant,
                                             Some("redirect_uri parameter must be \
                                                   supplied in body")),
                Some(ru) => if &ru != authz_request_data.redirect_uri.as_ref().unwrap() {
                    token_response_fail!(response, None, TokenErrorCode::InvalidGrant,
                                         Some("redirect_uri parameter mismatch"));
                }
            }
        }

        // Issue token
        let token = self.issue_token_to_client(context, code.unwrap(), client_data.client_id);

        // JSON-ify the response.
        let body = token.as_json();

        *response.status_mut() = StatusCode::Ok;

        let mut response = response.start().unwrap();
        response.write_all(body.as_bytes()).unwrap();
        let _ = response.end();
    }
}

