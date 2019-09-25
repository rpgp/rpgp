use std::str;

use crate::email::mime;
use crate::email::types::Email;
use crate::errors::Result;

pub fn parse(msg: &[u8]) -> Result<Email<'_>> {
    let (rest, headers) = mime::parse(msg)?;

    Ok(Email {
        header: headers,
        body: str::from_utf8(rest)?.trim(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            parse(b"MIME-Version: 1.0\r\nMy Body").unwrap(),
            Email {
                header: vec![("MIME-Version".to_string(), "1.0".to_string())],
                body: "My Body",
            },
        );
        assert_eq!(
            parse(b"MIME-Version: 1.0\r\n\r\nMy Body\r\n").unwrap(),
            Email {
                header: vec![("MIME-Version".to_string(), "1.0".to_string())],
                body: "My Body",
            },
        );
    }
}
