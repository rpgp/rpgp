#![feature(test)]

extern crate pgp;
extern crate test;

#[cfg(feature = "profile")]
extern crate gperftools;

mod key;
mod message;
