
use super::{ClientId,ClientType};
use url::Url;

/// Client data is registered with the Authorization Service out of band
/// prior to the OAuth 2.0 protocol commencing.
pub struct ClientData {

    /// Client Identifier.  Required.  Must be unique across the Authorization Service and
    /// so is typically issued by the Authorization Service.  Also used to fetch this
    /// entire record.
    pub client_id: ClientId,

    /// Client Type.  Required, even if your implementation only ever uses one type.
    pub client_type: ClientType,

    /// Redirect URL(s).  Required for public clients, required if the client has multiple,
    /// otherwise optional, but SHOULD be supplied anyway.</li>
    pub redirect_uri: Vec<Url>,

    /// Client Credentials, serialized.  Required, but the details are out of scope.
    pub credentials: String,

    /// Authentication Scheme, serialized.  Only required if multiple authentication schemes
    /// are implemented and the server needs to know which one this client is using.
    pub authn_scheme: Option<String>,
}

pub trait OAuth2AuthorizationServer
{
    // This is part of registration, outside of the scope of the RFC:
    // fn generate_new_client_id() -> ClientId;

    // This is part of registration, outside of the scope of the RFC:
    // fn store_client_data(client_id: ClientId, client_data: ClientData) -> bool;

    fn fetch_client_data(client_id: ClientId) -> Option<ClientData>;
}
