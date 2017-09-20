use nom::{self, IResult, AsChar, crlf, space};
use std::ops::{Range, RangeFrom, RangeTo};
use std::str;
use types::ParseResult;

use util::collect_into_string;

#[inline]
fn is_name_token(chr: u8) -> bool {
    (chr > 32 && chr < 58) || (chr > 58 && chr < 127)
}

#[inline]
fn is_body_token(chr: char) -> bool {
    chr != '\r' && chr != '\n' && chr != ' ' && chr != '\t' && (chr as u8) < 128
}

/// Recognizes one or more body tokens
fn body_token<T>(input: T) -> IResult<T, T>
where
    T: nom::Slice<Range<usize>> + nom::Slice<RangeFrom<usize>> + nom::Slice<RangeTo<usize>>,
    T: nom::InputIter + nom::InputLength,
    <T as nom::InputIter>::Item: AsChar,
{
    let input_length = input.input_len();
    if input_length == 0 {
        return IResult::Incomplete(nom::Needed::Unknown);
    }

    for (idx, item) in input.iter_indices() {
        let item = item.as_char();
        if !is_body_token(item) {
            if idx == 0 {
                return IResult::Error(error_position!(nom::ErrorKind::AlphaNumeric, input));
            } else {
                return IResult::Done(input.slice(idx..), input.slice(0..idx));
            }
        }
    }
    IResult::Done(input.slice(input_length..), input)
}

named!(field_name<String>, map!(
    take_while1!(is_name_token),
    |n| str::from_utf8(n).unwrap().to_string()
));

named!(sep<()>, do_parse!(
    char!(':') >>
    many0!(space) >>
    ()
));

named!(field_body<String>, map!(
    many0!(alt_complete!(
        body_token | do_parse!(
            crlf >>
            many1!(space) >> 
           (&b" "[..])    
        ) | space
    )),
    collect_into_string
));

named!(header<Vec<(String, String)>>, many0!(
    terminated!(
        separated_pair!(
            field_name,
            sep,
            field_body
        ),
        alt_complete!(crlf | eof!())
    )
));

pub fn parse(msg: &[u8]) -> ParseResult {
    header(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(parse(b"MIME-Version: 1.0\r\n"), IResult::Done(&b""[..], vec![("MIME-Version".to_string(), "1.0".to_string())]));

        // spaces in the value
        assert_eq!(parse(b"MyHeader: 1.0  2.0\r\n"), IResult::Done(&b""[..], vec![("MyHeader".to_string(), "1.0  2.0".to_string())]));
        // line breaks in the value
        assert_eq!(parse(b"MyHeader: hello\r\n world\r\n foo\r\n"), IResult::Done(&b""[..], vec![("MyHeader".to_string(), "hello world foo".to_string())]));

        // no space after :
        assert_eq!(parse(b"MIME-Version:1.0\r\n"), IResult::Done(&b""[..], vec![("MIME-Version".to_string(), "1.0".to_string())]));

        assert_eq!(parse(b"MIME-Version: 1.0\r\nSubject: Daily schedule on Monday, September 4, 2017\r\n"), IResult::Done(&b""[..], vec![("MIME-Version".to_string(), "1.0".to_string()), ("Subject".to_string(), "Daily schedule on Monday, September 4, 2017".to_string())]));

        let raw = [
            "MIME-Version: 1.0",
            "From: Microsoft Outlook Calendar",
            "To: Friedel Ziegelmayer <outlook_57FECB636A413BC1@outlook.com>",
            "Subject: Daily schedule on Monday, September 4, 2017",
            "Thread-Topic: Daily schedule on Monday, September 4, 2017",
            "Thread-Index: AQHTJSBvMuakG0Ruy0uDR85wGR/zrg==",
            "Date: Mon, 4 Sep 2017 03:52:15 +0200",
            "Message-ID: <VI1P190MB0478680417513ABE9BA388C6BE910@VI1P190MB0478.EURP190.PROD.OUTLOOK.COM>",
            "Reply-To: \"no-reply@microsoft.com\" <no-reply@microsoft.com>",
            "Content-Language: en-US",
            "X-MS-Has-Attach: yes",
            "X-MS-Exchange-Organization-SCL: -1",
            "X-MS-TNEF-Correlator:",
            "X-MS-Exchange-Organization-RecordReviewCfmType: 0",
            "Content-Type: multipart/related;\r\n boundary=\"_002_VI1P190MB0478680417513ABE9BA388C6BE910VI1P190MB0478EURP_\";\r\n type=\"text/html\"",
        ].join("\r\n");

        let result = parse(raw.as_bytes());
        if let IResult::Done(rest, headers) = result {
            assert_eq!(rest, &b""[..]);
            assert_eq!(headers.len(), 15);

            assert_eq!(headers[0], ("MIME-Version".to_string(), "1.0".to_string()));
            assert_eq!(headers[1], ("From".to_string(), "Microsoft Outlook Calendar".to_string()));
            assert_eq!(headers[2], ("To".to_string(), "Friedel Ziegelmayer <outlook_57FECB636A413BC1@outlook.com>".to_string()));
            assert_eq!(headers[3], ("Subject".to_string(), "Daily schedule on Monday, September 4, 2017".to_string()));
            assert_eq!(headers[4], ("Thread-Topic".to_string(), "Daily schedule on Monday, September 4, 2017".to_string()));
            assert_eq!(headers[5], ("Thread-Index".to_string(), "AQHTJSBvMuakG0Ruy0uDR85wGR/zrg==".to_string()));
            assert_eq!(headers[6], ("Date".to_string(), "Mon, 4 Sep 2017 03:52:15 +0200".to_string()));
            assert_eq!(headers[7], ("Message-ID".to_string(), "<VI1P190MB0478680417513ABE9BA388C6BE910@VI1P190MB0478.EURP190.PROD.OUTLOOK.COM>".to_string()));
            assert_eq!(headers[8], ("Reply-To".to_string(), "\"no-reply@microsoft.com\" <no-reply@microsoft.com>".to_string()));
            assert_eq!(headers[9], ("Content-Language".to_string(), "en-US".to_string()));
            assert_eq!(headers[10], ("X-MS-Has-Attach".to_string(), "yes".to_string()));
            assert_eq!(headers[11], ("X-MS-Exchange-Organization-SCL".to_string(), "-1".to_string()));
            assert_eq!(headers[12], ("X-MS-TNEF-Correlator".to_string(), "".to_string()));
            assert_eq!(headers[13], ("X-MS-Exchange-Organization-RecordReviewCfmType".to_string(), "0".to_string()));
            assert_eq!(headers[14], ("Content-Type".to_string(), "multipart/related; boundary=\"_002_VI1P190MB0478680417513ABE9BA388C6BE910VI1P190MB0478EURP_\"; type=\"text/html\"".to_string()));
        } else {
            panic!("failed to parse\n{}\n: {:?}", raw, result);
        }
    }

    #[test]
    fn test_collect_into_string() {
        assert_eq!(collect_into_string(vec![b"hello", b" ", b"world"]), "hello world");
    }
}
