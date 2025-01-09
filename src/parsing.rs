//! Parsing functions to parse data using [Buf].

use bytes::{Buf, Bytes};

use crate::errors::Result;

pub fn read_u8<B: Buf>(mut buf: B) -> Result<u8> {
    ensure!(buf.remaining() >= 1, "need at least 1 byte");
    Ok(buf.get_u8())
}

pub fn read_be_u16<B: Buf>(mut buf: B) -> Result<u16> {
    ensure!(buf.remaining() >= 2, "need at least 2 bytes");
    Ok(buf.get_u16())
}

pub fn take_array<B: Buf, const C: usize>(mut buf: B) -> Result<[u8; C]> {
    ensure!(buf.remaining() >= C, "need at least {} bytes", C);
    let mut arr = [0u8; C];
    buf.copy_to_slice(&mut arr);
    Ok(arr)
}

pub fn take<B: Buf>(size: usize, mut buf: B) -> Result<Bytes> {
    ensure!(buf.remaining() >= size, "need at least {} bytes", size);
    Ok(buf.copy_to_bytes(size))
}
