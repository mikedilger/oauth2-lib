
use std::ops::Deref;
use std::fmt;

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub struct ClientId(pub String);

impl Deref for ClientId {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        write!(f, "{}", &self.0)
    }
}
