
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io::Read;
use hyper::server::request::Request;
use hyper::uri::RequestUri;
use hyper::method::Method;
use hyper::header::ContentType;
use mime::{Mime,TopLevel,SubLevel};
use serde_json::value::Value as JsonValue;
use formdata::FormData;

/// RequestData stores data that was submitted in the HTTP request, either from POST body
/// parameters or GET query parameters, including any uploaded files, organized into maps
/// keyed on the parameter names.
///
/// Fields which have multiple values use U+2028 line separators in their value strings
/// to separate these values
#[derive(Clone, Debug)]
pub struct RequestData {
    pub fields: HashMap<String, String>,
    pub json: Option<JsonValue>,
}

impl RequestData {

    pub fn new() -> RequestData {
        RequestData {
            fields: HashMap::new(),
            files: HashMap::new(),
            json: None,
        }
    }

    /// Extracts RequestData from a hyper Request.
    pub fn from_request(request: &mut Request) -> Result<RequestData, Error> {

        let mut formdata = FormData::new();
        let mut json: Option<JsonValue> = None;

        match request.method {
            Method::Get | Method::Head =>
                // Get query parameters
                formdata.fields = try2!(get_query_parameters(request)),
            _ => {
                let (toplevel,sublevel) = {
                    let content_type: Option<&ContentType> = request.headers.get();
                    if content_type.is_some() {
                        let content_type = content_type.unwrap().clone();
                        let ContentType(Mime(toplevel,sublevel,_)) = content_type;
                        (toplevel,sublevel)
                    } else {
                        (TopLevel::Text, SubLevel::Plain)
                    }
                };
                match (toplevel,sublevel) {
                    (TopLevel::Multipart, SubLevel::FormData) => {
                        // Get parameters from multipart/form-data
                        let boundary = try2!(
                            ::formdata::get_multipart_boundary(&request.headers));
                        formdata = try2!(
                            ::formdata::parse_multipart(request, boundary));
                    },
                    (TopLevel::Application, SubLevel::WwwFormUrlEncoded) => {
                        // Get parameters from application/x-www-form-urlencoded
                        formdata.fields = try2!(get_body_parameters(request));
                    },
                    (TopLevel::Application, SubLevel::Json) => {
                        // Parse body as JSON
                        json = Some(try2!(get_json_from_body(request)));
                    }
                    _ => { }
                }
            }
        }
        let mut request_data = RequestData::from_formdata(formdata);
        request_data.json = json;
        Ok(request_data)
    }

    /// Converts FormData into RequestData.
    ///
    /// Field keys ending in '[]' will be considered arrays, and duplicate entries will
    /// have their values concatenated together with U+2028 line separators; the resultant
    /// map key will not contain the '[]' characters.
    ///
    /// Other than the arrays mentioned above, duplicate entries of fields and files will
    /// supercede and overwrite previous entries.
    ///
    /// FormData's UploadedFile is changed into a LocalFile, in order to add the fields
    /// required to associate the file with a potentially previously stored file.
    fn from_formdata(formdata: FormData) -> RequestData {
        let mut map = RequestData::new();
        for (name,value) in formdata.fields.into_iter() {
            if &name[name.len()-2 ..] == "[]" {
                let key=(&name[..name.len()-2]).to_owned();
                let mut dummy = false; // work around borrow checker else clause
                if let Entry::Occupied(o) = map.fields.entry(key.clone()) {
                    *o.into_mut() = format!("{}\u{2028}{}", o.get(), value);
                    dummy = true;
                }
                if dummy == false {
                    map.fields.insert(key, value);
                }
            }
            else {
                map.fields.insert(name, value);
            }
        }
        for (name,file) in formdata.files.into_iter() {
            let localfile = LocalFile::from_uploaded_file(file);
            map.files.insert(name, localfile);
        }
        map
    }

}

/// Get parameters from URL query string.  This is only appropriate for GET and HEAD.
pub fn get_query_parameters(request: &Request)
                            -> Result<Vec<(String,String)>,Error>
{
    // Parse URI using url library
    let pqf: &String = match request.uri {
        RequestUri::AbsolutePath(ref path) => path,
        _ => return Err(new_error!(Kind::UnsupportedUriFormat,
                                   "non-AbsolutePath format detected"))
    };

    // FIXME: see if there is a way to parse this w/o dummying up a URL
    // (like we could in URL 0.5)
    let url = try2!(::url::Url::parse( &*format!("http://host{}", pqf) ));
    Ok(url.query_pairs()
       .map(|(a,b)| (a.into_owned(), b.into_owned()))
       .collect())
}

/// Get parameters from an HTTP request body.  This is appropriate for everything except GET and
/// HEAD.
pub fn get_body_parameters(request: &mut Request)
                           -> Result<Vec<(String,String)>,Error>
{
    let mut body: Vec<u8> = Vec::new();
    try2!( request.read_to_end(&mut body),
           "Unable to read request body" );

    // FIXME: see if there is a way to parse this w/o dummying up a URL
    // (like we could in URL 0.5)
    let url = try2!(::url::Url::parse( &*format!("http://host?{}",
                                                 try2!(::std::str::from_utf8(&*body))) ));
    Ok(url.query_pairs()
       .map(|(a,b)| (a.into_owned(), b.into_owned()))
       .collect())
}

fn get_json_from_body(request: &mut Request) -> Result<JsonValue, Error>
{
    let mut body: Vec<u8> = Vec::new();
    try2!( request.read_to_end(&mut body),
           "Unable to read request body" );

    ::serde_json::from_str( &*try2!(String::from_utf8(body)) ).map_err(|e| From::from(e))
}
