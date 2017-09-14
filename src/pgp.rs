use nom::{self, IResult, digit, line_ending, alphanumeric, not_line_ending};
use std::str;
use openssl::rsa::Rsa;
// use openssl::bn::BigNum;
use header::collect_into_string;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ArmorHeader {
    PublicKey,
    PrivateKey,
    Message,
    MultiPartMessage(usize, usize),
    Signature,
}

named!(armor_header_sep, tag!("-----"));

named!(armor_header_type<ArmorHeader>, alt_complete!(
    map!(
        tag!("BEGIN PGP PUBLIC KEY BLOCK"),
        |_| ArmorHeader::PublicKey
    ) |
    map!(
        tag!("BEGIN PGP PRIVATE KEY BLOCK"),
        |_| ArmorHeader::PrivateKey
    ) |
    do_parse!(
           tag!("BEGIN PGP MESSAGE, PART ") >>
        x: map_res!(digit, str::from_utf8) >>
        y: opt!(map_res!(preceded!(tag!("/"), digit), str::from_utf8)) >>
        ({
            // unwraps are safe, as the parser already determined that this is a digit.
            
            let x: usize = x.parse().unwrap();
            let y: usize = y.map(|s| s.parse().unwrap()).unwrap_or(0);
            
            ArmorHeader::MultiPartMessage(x, y)
        })    
    ) |
    map!(
        tag!("BEGIN PGP MESSAGE"),
        |_| ArmorHeader::Message
    ) |
    map!(
        tag!("BEGIN PGP SIGNATURE"),
        |_| ArmorHeader::Signature
    )
));

named!(
    armor_header_line<ArmorHeader>,
    do_parse!(
         armor_header_sep  >>
    typ: armor_header_type >>
         armor_header_sep  >>
         line_ending       >>
    (typ)
)
);

named!(armor_headers<Vec<(&str, &str)>>, separated_list_complete!(
    line_ending, 
    separated_pair!(
        map_res!(take_until!(": "), str::from_utf8),
        tag!(": "),
        map_res!(not_line_ending, str::from_utf8)
    )
));

named!(armor_header<(ArmorHeader, Vec<(&str, &str)>)>, do_parse!(
    typ:     armor_header_line >>
    headers: armor_headers     >>
    ((typ, headers))
));

// named!(
//     pgpkey<ArmorHeader>,
//     do_parse!(
//         header: armor_header >>
//         (header)
// )
// );

pub fn parse(msg: &[u8]) -> IResult<&[u8], Rsa> {
    // let res = pgpkey(msg);
    // if let IResult::Done(_, inner) = res {
    //     println!("res: {:?}", inner);
    // }

    IResult::Incomplete(nom::Needed::Size(10))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_armor_header_line() {
        assert_eq!(armor_header_line(&b"-----BEGIN PGP MESSAGE-----\n"[..]), IResult::Done(&b""[..], ArmorHeader::Message));

        assert_eq!(armor_header_line(&b"-----BEGIN PGP MESSAGE, PART 3/14-----\n"[..]), IResult::Done(&b""[..], ArmorHeader::MultiPartMessage(3, 14)));

        assert_eq!(armor_header_line(&b"-----BEGIN PGP MESSAGE, PART 14-----\n"[..]), IResult::Done(&b""[..], ArmorHeader::MultiPartMessage(14, 0)));
    }

    #[test]
    fn test_armor_headers() {
        assert_eq!(armor_headers(&b"Version: 12\r\nspecial-stuff: cool12.0\r\nsome:colon: with:me"[..]), IResult::Done(&b""[..], vec![("Version", "12"), ("special-stuff", "cool12.0"), ("some:colon", "with:me")]));
    }

    #[test]
    fn test_armor_header() {
        assert_eq!(armor_header(&b"-----BEGIN PGP MESSAGE-----\nVersion: 1.0\nMode: Test"[..]), IResult::Done(&b""[..], (ArmorHeader::Message, vec![("Version", "1.0"), ("Mode", "Test")])));
    }

    #[test]
    fn test_parse() {
        let raw = include_bytes!("../tests/opengpg-interop/testcases/keys/gnupg-v1-003.asc");
        let res = parse(raw);
        if let IResult::Done(rest, key) = res {
        } else {
            panic!("failed to parse: {:?}", res);
        }
    }
}
