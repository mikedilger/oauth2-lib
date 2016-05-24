
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
