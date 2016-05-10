//! Syntax validation for OAuth 2.0 elements

pub fn valid_client_id_str<'a>(client_id: &'a str) -> bool {
    str_is_vschar(client_id)
}

pub fn valid_client_secret_str<'a>(client_secret: &'a str) -> bool {
    str_is_vschar(client_secret)
}

pub fn valid_response_type_str<'a>(response_type: &'a str) -> bool {
    for t in response_type.split('\u{0020}') {
        if t.len() == 0 { return false };
        if ! str_is_digit_alpha_under(response_type) { return false };
    }
    true
}

pub fn valid_scope_str<'a>(scope: &'a str) -> bool {
    scope.len() > 0 && str_is_nqchar(scope)
}

pub fn valid_state_str<'a>(state: &'a str) -> bool {
    state.len() > 0 && str_is_vschar(state)
}

// URL parser will handle validity of redirect_uri

pub fn valid_error_str<'a>(error: &'a str) -> bool {
    error.len() > 0 && str_is_nqschar(error)
}

pub fn valid_error_description_str<'a>(error_description: &'a str) -> bool {
    error_description.len() > 0 && str_is_nqschar(error_description)
}

// URL parser will handle validity of error_uri

/// grant_type may also be a URI.  This only checks grant_name variants
pub fn valid_grant_name_str<'a>(grant_type: &'a str) -> bool {
    grant_type.len() > 0 && str_is_name(grant_type)
}

pub fn valid_code_str<'a>(code: &'a str) -> bool {
    code.len() > 0 && str_is_vschar(code)
}

pub fn valid_access_token_str<'a>(access_token: &'a str) -> bool {
    access_token.len() > 0 && str_is_vschar(access_token)
}

/// token_type may also be a URI.  This only checks token_name variants
pub fn valid_token_name_str<'a>(token_type: &'a str) -> bool {
    token_type.len() > 0 && str_is_name(token_type)
}

pub fn valid_expires_in_str<'a>(expires_in: &'a str) -> bool {
    expires_in.len() > 0 && str_is_digits(expires_in)
}

pub fn valid_username_str<'a>(username: &'a str) -> bool {
    str_is_unicodecharnocrlf(username)
}

pub fn valid_password_str<'a>(password: &'a str) -> bool {
    str_is_unicodecharnocrlf(password)
}

pub fn valid_refresh_token_str<'a>(refresh_token: &'a str) -> bool {
    refresh_token.len() > 0 && str_is_vschar(refresh_token)
}


/// Returns true if c is a digit
fn char_is_digit(c: char) -> bool {
    match c {
        '0'...'9' => true,
        _ => false,
    }
}

/// Returns true if str consists entirely of digits
fn str_is_digits<'a>(v: &'a str) -> bool {
    let vec: Vec<char> = v.chars().collect();
    for c in vec.iter() {
        if ! char_is_digit(*c) { return false; };
    }
    true
}

#[test]
fn test_str_is_digits() {
    assert!(str_is_digits("100984"));
    assert!(! str_is_digits("100.984"));
    assert!(! str_is_digits("100_984"));
    assert!(! str_is_digits("deadbeef"));
}

/// Returns true if char meets RFC 6749 Appendix A definition for name-char
fn char_is_name_char(c: char) -> bool {
    match c {
        '-' | '.' | '_' | '0'...'9' | 'A'...'Z' | 'a'...'z' => true,
        _ => false,
    }
}

/// Returns true if str meets RFC 6749 Appendix A definition for name-char
fn str_is_name<'a>(v: &'a str) -> bool {
    let vec: Vec<char> = v.chars().collect();
    for c in vec.iter() {
        if ! char_is_name_char(*c) { return false; };
    }
    true
}

#[test]
fn test_str_is_name() {
    assert!(str_is_name(""));
    assert!(str_is_name("_abc123_ABC"));
    assert!(str_is_name("_abc.123_ABC"));
    assert!(! str_is_name("abc,123_ABC"));
    assert!(! str_is_name("abc 123_ABC"));
}

/// Returns true if char meets RFC 6749 Appendix A definition for:
///    "_" / DIGIT / ALPHA
fn char_is_digit_alpha_under(c: char) -> bool {
    match c {
        '\u{0030}'...'\u{0039}' => true, // digit
        '\u{0041}'...'\u{005A}' => true, // alpha upper
        '\u{0061}'...'\u{007A}' => true, // alpha lower
        '\u{005F}' => true, // underscore
        _ => false
    }
}
/// Returns true if string meets RFC 6749 Appendix A definition for:
///    "_" / DIGIT / ALPHA
fn str_is_digit_alpha_under<'a>(v: &'a str) -> bool {
    let vec: Vec<char> = v.chars().collect();
    for c in vec.iter() {
        if ! char_is_digit_alpha_under(*c) { return false; };
    }
    true
}
#[test]
fn test_str_is_digit_alpha_under() {
    assert!(str_is_digit_alpha_under(""));
    assert!(str_is_digit_alpha_under("_abc123_ABC"));
    assert!(! str_is_digit_alpha_under("_abc.123_ABC"));
    assert!(! str_is_digit_alpha_under("abc 123_ABC"));
}


/// Returns true if char meets RFC 6749 Appendix A definition for VSCHAR
fn char_is_vschar(c: char) -> bool {
    match c {
        '\u{0020}'...'\u{007E}' => true,
        _ => false
    }
}
/// Returns true if string meets RFC 6749 Appendix A definition for VSCHAR
fn str_is_vschar<'a>(v: &'a str) -> bool {
    let vec: Vec<char> = v.chars().collect();
    for c in vec.iter() {
        if ! char_is_vschar(*c) { return false; }
    }
    true
}
#[test]
fn test_str_is_vschar() {
    assert!(str_is_vschar(""));
    assert!(str_is_vschar(" !\"\\~lj"));
    assert!(! str_is_vschar("\u{0009}"));
}

/// Returns true if char meets RFC 6749 Appendix A definition for NQCHAR
fn char_is_nqchar(c: char) -> bool {
    match c {
        '\u{0021}' => true,
        '\u{0023}'...'\u{005B}' => true,
        '\u{005D}'...'\u{007E}' => true,
        _ => false
    }
}
/// Returns true if str meets RFC 6749 Appendix A definition for NQCHAR
fn str_is_nqchar<'a>(v: &'a str) -> bool {
    let vec: Vec<char> = v.chars().collect();
    for c in vec.iter() {
        if ! char_is_nqchar(*c) { return false; }
    }
    true
}
#[test]
fn test_is_nqchar() {
    assert!(str_is_nqchar(""));
    assert!(str_is_nqchar("!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"));

    assert!(! str_is_nqchar("\u{0000}"));
    assert!(! str_is_nqchar("\u{0001}"));
    assert!(! str_is_nqchar("\u{0002}"));
    assert!(! str_is_nqchar("\u{0003}"));
    assert!(! str_is_nqchar("\u{0004}"));
    assert!(! str_is_nqchar("\u{0005}"));
    assert!(! str_is_nqchar("\u{0006}"));
    assert!(! str_is_nqchar("\u{0007}"));
    assert!(! str_is_nqchar("\u{0008}"));
    assert!(! str_is_nqchar("\u{0009}"));
    assert!(! str_is_nqchar("\u{000A}"));
    assert!(! str_is_nqchar("\u{000B}"));
    assert!(! str_is_nqchar("\u{000C}"));
    assert!(! str_is_nqchar("\u{000D}"));
    assert!(! str_is_nqchar("\u{000E}"));
    assert!(! str_is_nqchar("\u{000F}"));
    assert!(! str_is_nqchar("\u{0010}"));
    assert!(! str_is_nqchar("\u{0011}"));
    assert!(! str_is_nqchar("\u{0012}"));
    assert!(! str_is_nqchar("\u{0013}"));
    assert!(! str_is_nqchar("\u{0014}"));
    assert!(! str_is_nqchar("\u{0015}"));
    assert!(! str_is_nqchar("\u{0016}"));
    assert!(! str_is_nqchar("\u{0017}"));
    assert!(! str_is_nqchar("\u{0018}"));
    assert!(! str_is_nqchar("\u{0019}"));
    assert!(! str_is_nqchar("\u{001A}"));
    assert!(! str_is_nqchar("\u{001B}"));
    assert!(! str_is_nqchar("\u{001C}"));
    assert!(! str_is_nqchar("\u{001D}"));
    assert!(! str_is_nqchar("\u{001E}"));
    assert!(! str_is_nqchar("\u{001F}"));
    assert!(! str_is_nqchar("\u{0020}"));
    assert!(! str_is_nqchar("\u{0022}"));
    assert!(! str_is_nqchar("\u{005C}"));
    assert!(! str_is_nqchar("\u{007F}"));
    assert!(! str_is_nqchar("\u{C800}"));
}

/// Returns true if char meets RFC 6749 Appendix A definition for NQSCHAR
fn char_is_nqschar(c: char) -> bool {
    match c {
        '\u{0020}'...'\u{0021}' => true,
        '\u{0023}'...'\u{005B}' => true,
        '\u{005D}'...'\u{007E}' => true,
        _ => false
    }
}
/// Returns true if str meets RFC 6749 Appendix A definition for NQSCHAR
fn str_is_nqschar<'a>(v: &'a str) -> bool {
    let vec: Vec<char> = v.chars().collect();
    for c in vec.iter() {
        if ! char_is_nqschar(*c) { return false; }
    }
    true
}
#[test]
fn test_str_str_is_nqschar() {
    assert!(str_is_nqschar(""));
    assert!(str_is_nqschar(" !#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"));

    assert!(! str_is_nqschar("\u{0000}"));
    assert!(! str_is_nqschar("\u{0001}"));
    assert!(! str_is_nqschar("\u{0002}"));
    assert!(! str_is_nqschar("\u{0003}"));
    assert!(! str_is_nqschar("\u{0004}"));
    assert!(! str_is_nqschar("\u{0005}"));
    assert!(! str_is_nqschar("\u{0006}"));
    assert!(! str_is_nqschar("\u{0007}"));
    assert!(! str_is_nqschar("\u{0008}"));
    assert!(! str_is_nqschar("\u{0009}"));
    assert!(! str_is_nqschar("\u{000A}"));
    assert!(! str_is_nqschar("\u{000B}"));
    assert!(! str_is_nqschar("\u{000C}"));
    assert!(! str_is_nqschar("\u{000D}"));
    assert!(! str_is_nqschar("\u{000E}"));
    assert!(! str_is_nqschar("\u{000F}"));
    assert!(! str_is_nqschar("\u{0010}"));
    assert!(! str_is_nqschar("\u{0011}"));
    assert!(! str_is_nqschar("\u{0012}"));
    assert!(! str_is_nqschar("\u{0013}"));
    assert!(! str_is_nqschar("\u{0014}"));
    assert!(! str_is_nqschar("\u{0015}"));
    assert!(! str_is_nqschar("\u{0016}"));
    assert!(! str_is_nqschar("\u{0017}"));
    assert!(! str_is_nqschar("\u{0018}"));
    assert!(! str_is_nqschar("\u{0019}"));
    assert!(! str_is_nqschar("\u{001A}"));
    assert!(! str_is_nqschar("\u{001B}"));
    assert!(! str_is_nqschar("\u{001C}"));
    assert!(! str_is_nqschar("\u{001D}"));
    assert!(! str_is_nqschar("\u{001E}"));
    assert!(! str_is_nqschar("\u{001F}"));
    assert!(! str_is_nqschar("\u{0022}"));
    assert!(! str_is_nqschar("\u{005C}"));
    assert!(! str_is_nqschar("\u{007F}"));
    assert!(! str_is_nqschar("\u{C800}"));
}

/// Returns true if char meets RFC 6749 Appendix A definition for UNICODECHARNOCRLF
/// (which perhaps confusingly excludes more than just CR and LF)
fn char_is_unicodecharnocrlf(c: char) -> bool {
    match c {
        '\u{0009}' => true,
        '\u{0020}'...'\u{007E}' => true,
        '\u{0080}'...'\u{D7FF}' => true,
        '\u{E000}'...'\u{FFFD}' => true,
        '\u{10000}'...'\u{10FFFF}' => true,
        _ => false
    }
}
/// Returns true if str meets RFC 6749 Appendix A definition for UNICODECHARNOCRLF
/// (which perhaps confusingly excludes more than just CR and LF)
fn str_is_unicodecharnocrlf<'a>(v: &'a str) -> bool {
    let vec: Vec<char> = v.chars().collect();
    for c in vec.iter() {
        if ! char_is_unicodecharnocrlf(*c) { return false; }
    }
    true
}
#[test]
fn test_str_is_unicodecharnocrlf() {
    assert!(str_is_unicodecharnocrlf(""));
    assert!(str_is_unicodecharnocrlf("Hello My 2nd Son"));
    assert!(str_is_unicodecharnocrlf("\u{C800}\u{10FFFC}\u{E005}94"));
    assert!(! str_is_unicodecharnocrlf("Hello My\n 2nd Son"));
    assert!(! str_is_unicodecharnocrlf("Hello My\u{007F} 2nd Son"));
    assert!(! str_is_unicodecharnocrlf("\u{0001}"));
    assert!(! str_is_unicodecharnocrlf("\u{0019}"));
}

// All ascii chars:
// ascii = "\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\u0008\u0009\u000A\u000B\u000C\u000D\u000E\u000F\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001A\u001B\u001C\u001D\u001E\u001F !\u0022#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\u005C]^_`abcdefghijklmnopqrstuvwxyz{|}~\u007F";
