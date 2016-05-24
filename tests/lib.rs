
extern crate oauth2;
extern crate hyper;
extern crate url;
extern crate textnonce;

use std::sync::{Arc, Mutex};
use std::collections::{HashMap, HashSet};
use std::error::Error as StdError;
use std::fmt;
use oauth2::{ClientData, AuthzServer, TokenData, Client, ClientType,
             AuthzError, AuthzErrorCode, AuthzRequest, UserError, OAuthError};
use hyper::server::{Handler, Request, Response};
use hyper::status::StatusCode;
use hyper::uri::RequestUri;
use url::Url;
use textnonce::TextNonce;

#[derive(Clone, Copy, PartialEq)]
enum InjectedFailure {
    NotAuthorized,
    NoSuchClient,
}

// Dummied up error type
#[derive(Debug)]
struct MyError(String);
impl StdError for MyError {
    fn description(&self) -> &str {
        "error"
    }
    fn cause(&self) -> Option<&StdError> {
        None
    }
}
impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl UserError for MyError { }

struct MyAuthzServer {
    pub registered_clients: HashMap<String, ClientData>,
    pub client_authorizations: HashMap<String, AuthzRequest>,
    pub failure: Option<InjectedFailure>
}
impl MyAuthzServer {
    pub fn new(client_port: u16, failure: Option<InjectedFailure>) -> MyAuthzServer {
        let mut rc: HashMap<String, ClientData> = HashMap::new();
        rc.insert("1".to_string(),
                  ClientData {
                      client_id: "1".to_string(),
                      client_type: ClientType::ConfidentialClient,
                      redirect_uri: vec![
                          format!("http://127.0.0.1:{}/redirect_uri", client_port) ],
                      credentials: "boo".to_owned(),
                      authn_scheme: None
                  });

        MyAuthzServer {
            registered_clients: rc,
            client_authorizations: HashMap::new(),
            failure: failure
        }
    }
}
impl AuthzServer<(),MyError> for MyAuthzServer {
    fn fetch_client_data(&self, _context: &mut (), client_id: String)
                         -> Result<Option<ClientData>, OAuthError<MyError>>
    {
        if self.failure == Some(InjectedFailure::NoSuchClient) {
            return Ok(None);
        }
        Ok(self.registered_clients.get(&client_id).cloned())
    }

    fn store_client_authorization(&mut self, _context: &mut (), request: AuthzRequest)
        -> Result<(), OAuthError<MyError>>
    {
        let code = request.authorization_code.as_ref().unwrap().clone();
        self.client_authorizations.insert(code, request);
        Ok(())
    }

    fn retrieve_client_authorization(&self, _context: &mut (), code: String)
                                     -> Result<Option<AuthzRequest>, OAuthError<MyError>>
    {
        Ok(self.client_authorizations.get(&code).cloned())
    }

    fn issue_token_to_client(&mut self, _context: &mut (), _code: String, _client_id: String)
                             -> Result<TokenData, OAuthError<MyError>>
    {
        let token = TextNonce::new().into_string();
        // FIXME - save this issuance somewhere and recheck it in test fn
        Ok(TokenData {
            access_token: token,
            token_type: "bearer".to_owned(),
            expires_in: None,
            refresh_token: None,
            scope: None,
        })
    }
}

struct MyAuthzHandler {
    authz_server: Arc<Mutex<MyAuthzServer>>,
}
impl MyAuthzHandler {
    fn handle_fail(&self, mut response: Response, status: Option<StatusCode>) {
        *response.status_mut() = match status {
            Some(s) => s,
            None => StatusCode::BadRequest
        };
        let response = response.start().unwrap();
        let _ = response.end();
        return;
    }
}
impl Handler for MyAuthzHandler {
    fn handle(&self, request: Request, response: Response)
    {
        let pqf = match request.uri {
            RequestUri::AbsolutePath(ref p) => p.clone(),
            _ => return self.handle_fail(response, None),
        };
        let url: Url = Url::parse(&*format!("http://127.0.0.1{}", pqf)).unwrap();

        match url.path() {
            "/authorization" => {
                let mut authz_server = self.authz_server.lock().unwrap();
                match authz_server.handle_authz_request(&mut (), request) {
                    Ok(mut request_data) => {
                        if request_data.error.is_none() {
                            // NOTE: If you are following this test as example code, this is
                            // where the AuthzServer must authenticate the user-agent and also
                            // ask the user if they wish to authorize the request.
                            // For this test, we presume they are authentic, and that they do.

                            if authz_server.failure == Some(InjectedFailure::NotAuthorized) {
                                request_data.authorization_code = None;
                                request_data.error = Some(AuthzError {
                                    error: AuthzErrorCode::AccessDenied,
                                    error_description: None,
                                    error_uri: None,
                                    state: None,
                                });
                            } else {
                                // Set authorization code (will be used by client)
                                request_data.authorization_code = Some("authorized".to_owned());
                            }
                        }
                        let _ = authz_server.finish_authz_request(&mut (), request_data, response);
                    },
                    Err(_) => self.handle_fail(response, None),
                }
            },
            "/token" => {
                let mut authz_server = self.authz_server.lock().unwrap();
                authz_server.handle_token_request(&mut (), request, response);
            },
            _ => self.handle_fail(response, Some(StatusCode::NotFound))
        }
    }
}

struct MyClient {
    client_data: ClientData,
    nonces: HashSet<String>,
    server_port: u16,
}
impl MyClient {
    pub fn new(client_port: u16, server_port: u16) -> MyClient {
        MyClient {
            client_data: ClientData {
                client_id: "1".to_string(),
                client_type: ClientType::ConfidentialClient,
                redirect_uri: vec![
                    format!("http://127.0.0.1:{}/redirect_uri", client_port) ],
                credentials: "boo".to_owned(),
                authn_scheme: None
            },
            nonces: HashSet::new(),
            server_port: server_port,
        }
    }
}
impl Client<MyError> for MyClient {
    fn get_client_data<'a>(&'a self) -> &'a ClientData
    {
        &self.client_data
    }

    fn store_nonce(&mut self, token: String) {
        self.nonces.insert(token);
    }

    fn consume_nonce(&mut self, token: String) -> bool {
        self.nonces.remove(&token)
    }

    fn get_redirect_uri<'a>(&'a self) -> &'a str {
        &self.client_data.redirect_uri[0]
    }
}

struct MyClientHandler {
    client: Arc<Mutex<MyClient>>,
}
impl MyClientHandler {
    fn handle_fail(&self, mut response: Response, status: Option<StatusCode>) {
        *response.status_mut() = match status {
            Some(s) => s,
            None => StatusCode::BadRequest
        };
        let response = response.start().unwrap();
        let _ = response.end();
        return;
    }
}
impl Handler for MyClientHandler {
    fn handle(&self, request: Request, mut response: Response)
    {
        let pqf = match request.uri {
            RequestUri::AbsolutePath(ref p) => p.clone(),
            _ => return self.handle_fail(response, None),
        };

        let mut client = self.client.lock().unwrap();
        let server_port = client.server_port;

        let url: Url = Url::parse(&*format!("http://127.0.0.1:{}", pqf)).unwrap();

        match url.path() {
            "/" => {
                let _ = client.start_oauth(
                    None,
                    Url::parse(&*format!("http://127.0.0.1:{}/authorization", server_port)).unwrap(),
                    response);
            },
            "/redirect_uri" => {
                match client.handle_redirect_url(
                    request,
                    Url::parse(&*format!("http://127.0.0.1:{}/token", server_port)).unwrap())
                {
                    Ok(result) => match result {
                        Ok(_token_data) => {
                            *response.status_mut() = StatusCode::Ok;
                            let response = response.start().unwrap();
                            // FIXME: write some data, so we can test further
                            let _ = response.end();
                        },
                        Err(_error_data) => {
                            *response.status_mut() = StatusCode::InternalServerError;
                            let response = response.start().unwrap();
                            // FIXME: write some data, so we can test further
                            let _ = response.end();
                        },
                    },
                    Err(_e) => self.handle_fail(response, None),
                }
            },
            _ => self.handle_fail(response, Some(StatusCode::NotFound)),
        }
    }
}

fn run_test(server_port: u16, client_port: u16, failure: Option<InjectedFailure>)
         -> ::hyper::client::Response
{
    use hyper::server::Server;
    use hyper::client::Client;

    let server_handler = MyAuthzHandler {
        authz_server: Arc::new( Mutex::new(
            MyAuthzServer::new(client_port, failure) ) ),
    };
    let mut listening_server = match Server::http(("127.0.0.1",server_port)) {
        Ok(s) => s,
        Err(e) => panic!("Unable to start test server: {}", e)
    }.handle(server_handler).unwrap();

    let client_handler = MyClientHandler {
        client: Arc::new( Mutex::new(
            MyClient::new(client_port, server_port) ) ),
    };
    let mut listening_client = match Server::http(("127.0.0.1",client_port)) {
        Ok(c) => c,
        Err(e) => panic!("Unable to start test client: {}", e)
    }.handle(client_handler).unwrap();

    // Browse to client, and be redirected
    let user_agent = Client::new();
    let res = user_agent.get(&format!("http://127.0.0.1:{}",client_port)).send().unwrap();

    // Close down
    let _ = listening_server.close();
    let _ = listening_client.close();

    res
}

#[test]
fn test_success() {
    let res = run_test(12001, 12002, None);
    assert_eq!(res.status, StatusCode::Ok);
}

#[test]
fn test_failure_no_such_client() {
    let res = run_test(12003, 12004, Some(InjectedFailure::NoSuchClient));
    assert_eq!(res.status, StatusCode::BadRequest);
}

#[test]
fn test_failure_not_authorized() {
    let res = run_test(12005, 12006, Some(InjectedFailure::NotAuthorized));
    assert_eq!(res.status, StatusCode::BadRequest);
}
