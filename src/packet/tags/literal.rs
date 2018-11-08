use std::str;

use nom::{be_u8, rest};

#[derive(Debug)]
pub struct LiteralData {
    pub mode: u8,
    pub name: String,
    pub created: Vec<u8>,
    pub data: Vec<u8>,
}

named!(pub parser<LiteralData>, do_parse!(
           mode: be_u8
    >> name_len: be_u8
    >>     name: map_res!(take!(name_len), str::from_utf8)
    >>  created: take!(4)
    >>     data: rest
    >> (LiteralData {
        mode,
        created: created.to_vec(),
        name: name.to_string(),
        data: data.to_vec(),
    })
));
