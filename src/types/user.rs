use packet::{Signature, UserAttribute, UserId};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedUser {
    pub id: UserId,
    pub signatures: Vec<Signature>,
}

impl SignedUser {
    pub fn new(id: UserId, signatures: Vec<Signature>) -> Self {
        SignedUser { id, signatures }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedUserAttribute {
    pub attr: UserAttribute,
    pub signatures: Vec<Signature>,
}

impl SignedUserAttribute {
    pub fn new(attr: UserAttribute, signatures: Vec<Signature>) -> Self {
        SignedUserAttribute { attr, signatures }
    }
}
