
use std::ops::Deref;
use std::fmt;

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub struct RedirectUri(pub String);

impl Deref for RedirectUri {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}

impl fmt::Display for RedirectUri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        write!(f, "{}", &self.0)
    }
}
