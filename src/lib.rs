/*!
This is an OAuth 2.0 library for the Rust language.  It defines types and traits useful
for implementing an OAuth 2.0 compliant system as specified by RFC 6749.

WARNING: We've just started.  It is practically useless at this point.

<h2>Applicability</h2>

OAuth 2.0 is a protocol framework that allows an application (the <em>Client</em>, usually a web
site) to obtain limited access to an HTTP service (the <em>Resource Server</em>) on behalf of
a <em>Resource Owner</em> which interacts with the Client via a <em>User-Agent</em> (browser).
This is mediated via an <em>Authorization Server</em> (which could be th Resource Server
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
<li>Issuing and receiving HTTP requests (e.g. you'll need to plug in some HTTP
    library, we won't pick one for you).</li>
<li>Storing state.  Often database tables are used.  Manytimes the Authorization
    Server and Resource Server use the same database, or perhaps are the same
    server.  This is out of scope, and left up to you.</li>
<li>Initial client registration (between the Client and the Authorization
    Server).  Often people just use config files, but this is for you to decide.</li>
<li>Client authentication (by the Authorization Server)</li>
<li>User-Agent session management (by the Client).  Usually via a session cookie,
    but we leave this up to you.</li>
<li>User-Agent authentication and authorization (by the Authorization Server)</li>
<li>Perhaps more</li>
</ul>

<h2>Sample Implementation</h2>

FIXME: A sample implementation is intended to be supplied to demonstrate how to use this
library.

<h2>Coverage and Standard Support</h2>

We do not (and likely will not) support every standard compliant way to use OAuth 2.0.
But we do try to be as flexible as possible.  That being said, the following limitations
apply:

<ul>
<li>All HTTP traffic is required to be TLS protected.  All endpoints must use the
    <em>https</em> scheme.  The standard only requires this of most traffic.</li>
<li>All IDs and tokens are taken to be respresented in UTF-8 encodings.  We will not
    work with other encodings.  The standard is silent on most encoding issues.</li>
<li>FIXME: More limitations will be added to this list as the development progresses.</li>
</ul>
*/

#![experimental]

pub mod syntax;
pub mod resource_server;
pub mod authorization_server;
pub mod client;
