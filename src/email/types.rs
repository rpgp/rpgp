pub type Headers = Vec<(String, String)>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Email<'a> {
    pub header: Headers,
    pub body: &'a str,
}
