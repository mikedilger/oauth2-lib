
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
