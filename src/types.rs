use nom::IResult;

pub type Headers = Vec<(String, String)>;

pub type ParseResult<'a> = IResult<&'a [u8], Headers>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Email<'a> {
    pub header: Headers,
    pub body: &'a str,
}
