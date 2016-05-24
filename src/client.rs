
use std::io::Read;
use hyper::server::{Request, Response};
use hyper::uri::RequestUri;
use hyper::status::StatusCode;
use hyper::header::{Location, Authorization, Basic};
use url::Url;
use url::percent_encoding::{QUERY_ENCODE_SET, percent_encode};
use textnonce::TextNonce;
use {ClientData, OAuthError, TokenData, AuthzError};

pub trait Client
{
    /// Get own client data
    fn get_client_data<'a>(&'a self) -> &'a ClientData;

    /// Store a nonce, used to prevent cross-site reqeuest forgery.
    fn store_nonce(&mut self, token: String);

    /// Consume the nonce from storage, and return true if it was found, false if
    /// no such nonce existed.
    fn consume_nonce(&mut self, token: String) -> bool;

    fn generate_nonce(&mut self) -> String {
        let token = TextNonce::new().into_string();
        self.store_nonce(token.clone());
        token
    }

    /// Get the redirect URI for this client
    fn get_redirect_uri<'a>(&'a self) -> &'a str;

    /// This is the starting point for the OAuth sequence.  It redirects the user-agent
    /// to the AuthzServer's authz_request endpoint
    fn start_oauth(&mut self, scope: Option<String>, mut authz_request_url: Url,
                   mut response: Response)
    {
        let client_id = {
            let client_data = self.get_client_data();
            client_data.client_id.clone()
        };
        let state = self.generate_nonce();

        authz_request_url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &*client_id)
            .append_pair("redirect_uri", self.get_redirect_uri())
            .append_pair("state", &*state);

        if let Some(s) = scope {
            authz_request_url.query_pairs_mut()
                .append_pair("scope", &*s);
        }

        response.headers_mut().set(Location(authz_request_url.into_string()));
        *response.status_mut() = StatusCode::Found;
        let streaming_response = response.start().unwrap();
        let _ = streaming_response.end();
    }

    /// Handle an HTTP request to the Redirect URL (from the user-agent)
    ///
    /// Refer to rfc6749 section 3.1.2 as to the requirements of this endpoint
    /// (absolute URI, MUST NOT include fragment, MAY include query, SHOULD use TLS)
    fn handle_redirect_url(&mut self, request: Request, authz_token_url: Url)
                           -> Result<Result<TokenData, AuthzError>, OAuthError>
    {
        // Get request URI, so we can get parameters out of it's query string
        let uri_string: &String = match request.uri {
            RequestUri::AbsolutePath(ref s) => s,
            _ => return Err(OAuthError::AuthzBadRequest),
        };

        // Get expected (and optional) request parameters
        let mut code: Option<String> = None;
        let mut state: Option<String> = None;

        let url = try!( Url::parse( &*format!("http://x{}",uri_string)) );
        for (key,val) in url.query_pairs() {
            match &*key {
                "code" => code = Some(val.into_owned()),
                "state" => state = Some(val.into_owned()),
                _ => {} // MUST ignore unknown parameters
            }
        }

        // Require code
        let code = match code {
            None => return Err(OAuthError::ClientCodeMissing),
            Some(c) => c,
        };

        // Require state
        match state {
            None => return Err(OAuthError::ClientStateMissing),
            Some(s) => {
                if ! self.consume_nonce(s) {
                    return Err(OAuthError::ClientNonceMismatch);
                }
            }
        }

        let client_data = self.get_client_data();

        let client_id = percent_encode(client_data.client_id.as_bytes(),
                                       QUERY_ENCODE_SET).collect::<String>();
        let code = percent_encode(code.as_bytes(),
                                  QUERY_ENCODE_SET).collect::<String>();
        let redirect_uri = percent_encode(self.get_redirect_uri().as_bytes(),
                                          QUERY_ENCODE_SET).collect::<String>();

        let body = format!("grant_type=authorization_code&code={}&redirect_uri={}&client_id={}",
                           code, redirect_uri, client_id);

        let hyper = ::hyper::client::Client::new();
        let mut res = hyper.post(authz_token_url)
            .header(Authorization(Basic {
                username: client_data.client_id.clone(),
                password: Some(client_data.credentials.clone())
            }))
            .body(&*body)
            .send().unwrap();

        let mut body: Vec<u8> = Vec::new();
        try!(res.read_to_end(&mut body));
        let bodystr = try!(String::from_utf8(body));

        match res.status {
            StatusCode::Ok => {
                let token_data: TokenData = ::serde_json::from_str(&bodystr).unwrap();
                return Ok(Ok(token_data));
            },
            StatusCode::BadRequest | StatusCode::Unauthorized => {
                let authz_error: AuthzError = ::serde_json::from_str(&bodystr).unwrap();
                return Ok(Err(authz_error));
            },
            _ => {
                return Err(OAuthError::UnexpectedStatusCode);
            },
        }
    }
}
