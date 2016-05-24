/*!
This is an OAuth 2.0 library for the Rust language.  It defines types and traits useful
for implementing an OAuth 2.0 compliant system as specified by RFC 6749.

The current implementation allows you to build the most common and most secure
type of OAuth 2.0 infrastructure, but is not complete, and may not be
absolutely correct.  Please file bug reports or pull requests if you notice
any deviation from RFC 6749, or if you have any other issues.

<h2>Stability Note</h2>

This library is still undergoing heavy upheaval.  I don't
recommend using it yet unless you are a masochist.  -Mike, 25 May 2016

<h2>Applicability</h2>

OAuth 2.0 is a protocol framework that allows an application (the <em>Client</em>, usually a web
site) to obtain limited access to an HTTP service (the <em>Resource Server</em>) on behalf of
a <em>Resource Owner</em> which interacts with the Client via a <em>User-Agent</em> (browser).
This is mediated via an <em>Authorization Server</em> (which could be the Resource Server
itself, or separated from it).

<blockquote>
The term "client" can be confusing here.  The client of the OAuth service is typically a
web site.   The client of that web site is the user-agent (browser).  To minimize
confusion, the user-agent will not be referred to as a client.
</blockquote>

<h2>OAuth is a Framework Only</h2>

OAuth 2.0 is an Authorization Framework.  In order to get something usable, you must supply
the missing pieces.  And there are quite a few missing pieces which you will need to implement
in order to get a working system.  These include:

<ul>
<li>Initial client registration (between the Client and the Authorization
    Server).  Often people just use config files, but this is for you to decide.</li>
<li>Storing state.  Often database tables are used.  Manytimes the Authorization
    Server and Resource Server use the same database, or perhaps are the same
    server.  This is out of scope, and left up to you.</li>
<li>User-Agent authentication and authorization (by the Authorization Server), where you
    should not only authenticate the resource owner, but also ask them if they really want
    to allow the client to have the rights to act on their behalf under the Scope
    requested.</li>
</ul>

<h2>Sample Implementation</h2>

Please see `tests/lib.rs` for a sample implementation.

<h2>Coverage and Standard Support</h2>

We do not (and likely will not) support every standard compliant way to use OAuth 2.0.
But we will try to be as flexible as possible, and extend this library as time and resources
allow.  That being said, the following limitations currently apply:

<ul>
<li>We only explicitly support the "authorization code" grant type, which is the most common
    and most secure.  "Implicit", "resource owner password credentials", and "client
    credentials" grant types are not supported.
<li>The authorization server acts on behalf of the resource server, so virtually we are not
    supporting independent resource servers.
<li>We do not enforce that traffic be protected via TLS, although the standard requires that
    most (and suggests all) traffic be so protected.  This is left up to the user.</li>
<li>All IDs and tokens are taken to be respresented in UTF-8 encodings.  We will not
    work with other encodings.  The standard is silent on most encoding issues.</li>
<li>Refresh tokens are not yet supported</li>
<li>I'm not sure that the HTTP Status Codes returned to the user-agent on various failures
    are appropriate.</li>
<li>FIXME: More limitations will be added to this list as the development progresses.</li>
</ul>
*/

#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate url;
#[macro_use] extern crate hyper;
extern crate textnonce;
extern crate serde_json;

pub mod syntax;
pub mod authz_server;
pub mod authz_request;
pub mod authz_error;
pub mod token_data;
pub mod token_error;
pub mod client;
pub mod client_type;
pub mod client_data;
pub mod error;

pub use authz_server::AuthzServer;
pub use authz_request::AuthzRequest;
pub use authz_error::{AuthzError, AuthzErrorCode};
pub use token_data::TokenData;
pub use token_error::{TokenError, TokenErrorCode};
pub use client::Client;
pub use client_type::ClientType;
pub use client_data::ClientData;
pub use error::{OAuthError, UserError};
