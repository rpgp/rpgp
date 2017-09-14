use nom::IResult;
use types::Email;
use std::str;
use header;

pub fn parse(msg: &[u8]) -> IResult<&[u8], Email> {
    let res = header::parse(msg);

    match res {
        IResult::Done(rest, headers) => {
            IResult::Done(
                &b""[..],
                Email {
                    header: headers,
                    body: str::from_utf8(rest).unwrap().trim(),
                },
            )
        }
        IResult::Incomplete(needed) => IResult::Incomplete(needed),
        IResult::Error(err) => IResult::Error(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            parse(b"MIME-Version: 1.0\r\nMy Body"),
            IResult::Done(
                &b""[..],
                Email {
                    header: vec![("MIME-Version".to_string(), "1.0".to_string())],
                    body: "My Body",
                },
            )
        );
        assert_eq!(
            parse(b"MIME-Version: 1.0\r\n\r\nMy Body\r\n"),
            IResult::Done(
                &b""[..],
                Email {
                    header: vec![("MIME-Version".to_string(), "1.0".to_string())],
                    body: "My Body",
                },
            )
        );
    }
}
