//! Syntax validation for OAuth 2.0 elements

#![experimental]

pub fn valid_client_id_str<'a>(client_id: &'a str) -> bool {
    str_is_vschar(client_id)
}

pub fn valid_client_secret_str<'a>(client_secret: &'a str) -> bool {
    str_is_vschar(client_secret)
}

pub fn valid_response_type_str<'a>(response_type: &'a str) -> bool {
    for t in response_type.split('\u0020') {
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
        '0'..'9' => true,
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
        '-' | '.' | '_' | '0'..'9' | 'A'..'Z' | 'a'..'z' => true,
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
            '\u0030'..'\u0039' => true, // digit
            '\u0041'..'\u005A' => true, // alpha upper
            '\u0061'..'\u007A' => true, // alpha lower
            '\u005F' => true, // underscore
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
        '\u0020'..'\u007E' => true,
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
    assert!(! str_is_vschar("\u0009"));
}

/// Returns true if char meets RFC 6749 Appendix A definition for NQCHAR
fn char_is_nqchar(c: char) -> bool {
    match c {
        '\u0021' => true,
        '\u0023'..'\u005B' => true,
        '\u005D'..'\u007E' => true,
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

    assert!(! str_is_nqchar("\u0000"));
    assert!(! str_is_nqchar("\u0001"));
    assert!(! str_is_nqchar("\u0002"));
    assert!(! str_is_nqchar("\u0003"));
    assert!(! str_is_nqchar("\u0004"));
    assert!(! str_is_nqchar("\u0005"));
    assert!(! str_is_nqchar("\u0006"));
    assert!(! str_is_nqchar("\u0007"));
    assert!(! str_is_nqchar("\u0008"));
    assert!(! str_is_nqchar("\u0009"));
    assert!(! str_is_nqchar("\u000A"));
    assert!(! str_is_nqchar("\u000B"));
    assert!(! str_is_nqchar("\u000C"));
    assert!(! str_is_nqchar("\u000D"));
    assert!(! str_is_nqchar("\u000E"));
    assert!(! str_is_nqchar("\u000F"));
    assert!(! str_is_nqchar("\u0010"));
    assert!(! str_is_nqchar("\u0011"));
    assert!(! str_is_nqchar("\u0012"));
    assert!(! str_is_nqchar("\u0013"));
    assert!(! str_is_nqchar("\u0014"));
    assert!(! str_is_nqchar("\u0015"));
    assert!(! str_is_nqchar("\u0016"));
    assert!(! str_is_nqchar("\u0017"));
    assert!(! str_is_nqchar("\u0018"));
    assert!(! str_is_nqchar("\u0019"));
    assert!(! str_is_nqchar("\u001A"));
    assert!(! str_is_nqchar("\u001B"));
    assert!(! str_is_nqchar("\u001C"));
    assert!(! str_is_nqchar("\u001D"));
    assert!(! str_is_nqchar("\u001E"));
    assert!(! str_is_nqchar("\u001F"));
    assert!(! str_is_nqchar("\u0020"));
    assert!(! str_is_nqchar("\u0022"));
    assert!(! str_is_nqchar("\u005C"));
    assert!(! str_is_nqchar("\u007F"));
    assert!(! str_is_nqchar("\uC800"));
}

/// Returns true if char meets RFC 6749 Appendix A definition for NQSCHAR
fn char_is_nqschar(c: char) -> bool {
    match c {
        '\u0020'..'\u0021' => true,
        '\u0023'..'\u005B' => true,
        '\u005D'..'\u007E' => true,
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

    assert!(! str_is_nqschar("\u0000"));
    assert!(! str_is_nqschar("\u0001"));
    assert!(! str_is_nqschar("\u0002"));
    assert!(! str_is_nqschar("\u0003"));
    assert!(! str_is_nqschar("\u0004"));
    assert!(! str_is_nqschar("\u0005"));
    assert!(! str_is_nqschar("\u0006"));
    assert!(! str_is_nqschar("\u0007"));
    assert!(! str_is_nqschar("\u0008"));
    assert!(! str_is_nqschar("\u0009"));
    assert!(! str_is_nqschar("\u000A"));
    assert!(! str_is_nqschar("\u000B"));
    assert!(! str_is_nqschar("\u000C"));
    assert!(! str_is_nqschar("\u000D"));
    assert!(! str_is_nqschar("\u000E"));
    assert!(! str_is_nqschar("\u000F"));
    assert!(! str_is_nqschar("\u0010"));
    assert!(! str_is_nqschar("\u0011"));
    assert!(! str_is_nqschar("\u0012"));
    assert!(! str_is_nqschar("\u0013"));
    assert!(! str_is_nqschar("\u0014"));
    assert!(! str_is_nqschar("\u0015"));
    assert!(! str_is_nqschar("\u0016"));
    assert!(! str_is_nqschar("\u0017"));
    assert!(! str_is_nqschar("\u0018"));
    assert!(! str_is_nqschar("\u0019"));
    assert!(! str_is_nqschar("\u001A"));
    assert!(! str_is_nqschar("\u001B"));
    assert!(! str_is_nqschar("\u001C"));
    assert!(! str_is_nqschar("\u001D"));
    assert!(! str_is_nqschar("\u001E"));
    assert!(! str_is_nqschar("\u001F"));
    assert!(! str_is_nqschar("\u0022"));
    assert!(! str_is_nqschar("\u005C"));
    assert!(! str_is_nqschar("\u007F"));
    assert!(! str_is_nqschar("\uC800"));
}

/// Returns true if char meets RFC 6749 Appendix A definition for UNICODECHARNOCRLF
/// (which perhaps confusingly excludes more than just CR and LF)
fn char_is_unicodecharnocrlf(c: char) -> bool {
    match c {
        '\u0009' => true,
        '\u0020'..'\u007E' => true,
        '\u0080'..'\uD7FF' => true,
        '\uE000'..'\uFFFD' => true,
        '\U00010000'..'\U0010FFFF' => true,
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
    assert!(str_is_unicodecharnocrlf("\uC800\U0010FFFC\uE00594"));
    assert!(! str_is_unicodecharnocrlf("Hello My\n 2nd Son"));
    assert!(! str_is_unicodecharnocrlf("Hello My\u007F 2nd Son"));
    assert!(! str_is_unicodecharnocrlf("\u0001"));
    assert!(! str_is_unicodecharnocrlf("\u0019"));
}

// All ascii chars:
// ascii = "\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\u0008\u0009\u000A\u000B\u000C\u000D\u000E\u000F\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001A\u001B\u001C\u001D\u001E\u001F !\u0022#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\u005C]^_`abcdefghijklmnopqrstuvwxyz{|}~\u007F";
