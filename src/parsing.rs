//! Parsing functions to parse data using [Buf].

use bytes::{Buf, Bytes};

use crate::errors::Result;

pub trait BufParsing: Buf {
    fn read_u8(&mut self) -> Result<u8> {
        ensure!(self.remaining() >= 1, "need at least 1 byte");
        Ok(self.get_u8())
    }

    fn read_be_u16(&mut self) -> Result<u16> {
        ensure!(self.remaining() >= 2, "need at least 2 bytes");
        Ok(self.get_u16())
    }

    fn take_array<const C: usize>(&mut self) -> Result<[u8; C]> {
        ensure!(self.remaining() >= C, "need at least {} bytes", C);
        let mut arr = [0u8; C];
        self.copy_to_slice(&mut arr);
        Ok(arr)
    }

    fn read_take(&mut self, size: usize) -> Result<Bytes> {
        ensure!(self.remaining() >= size, "need at least {} bytes", size);
        Ok(self.copy_to_bytes(size))
    }

    fn rest(&mut self) -> Bytes {
        let len = self.remaining();
        self.copy_to_bytes(len)
    }
}

impl<B: Buf> BufParsing for B {}
