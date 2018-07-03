use std::str;

use super::mime;
use email::types::Email;
use nom::IResult;

pub fn parse(msg: &[u8]) -> IResult<&[u8], Email> {
    let res = mime::parse(msg);

    match res {
        Ok((rest, headers)) => Ok((
            &b""[..],
            Email {
                header: headers,
                body: str::from_utf8(rest).unwrap().trim(),
            },
        )),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            parse(b"MIME-Version: 1.0\r\nMy Body"),
            Ok((
                &b""[..],
                Email {
                    header: vec![("MIME-Version".to_string(), "1.0".to_string())],
                    body: "My Body",
                },
            ))
        );
        assert_eq!(
            parse(b"MIME-Version: 1.0\r\n\r\nMy Body\r\n"),
            Ok((
                &b""[..],
                Email {
                    header: vec![("MIME-Version".to_string(), "1.0".to_string())],
                    body: "My Body",
                },
            ))
        );
    }
}
