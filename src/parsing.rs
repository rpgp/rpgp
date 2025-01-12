//! Parsing functions to parse data using [Buf].

use bytes::{Buf, Bytes};

use crate::errors::Result;

pub trait BufParsing: Buf + Sized {
    fn read_u8(&mut self) -> Result<u8> {
        self.ensure_remaining(1)?;
        Ok(self.get_u8())
    }

    fn read_be_u16(&mut self) -> Result<u16> {
        self.ensure_remaining(2)?;
        Ok(self.get_u16())
    }

    fn read_le_u16(&mut self) -> Result<u16> {
        self.ensure_remaining(2)?;
        Ok(self.get_u16_le())
    }

    fn read_be_u32(&mut self) -> Result<u32> {
        self.ensure_remaining(4)?;
        Ok(self.get_u32())
    }

    fn read_array<const C: usize>(&mut self) -> Result<[u8; C]> {
        self.ensure_remaining(C)?;
        let mut arr = [0u8; C];
        self.copy_to_slice(&mut arr);
        Ok(arr)
    }

    fn read_take(&mut self, size: usize) -> Result<Bytes> {
        self.ensure_remaining(size)?;
        Ok(self.copy_to_bytes(size))
    }

    fn rest(&mut self) -> Bytes {
        let len = self.remaining();
        self.copy_to_bytes(len)
    }

    fn ensure_remaining(&self, size: usize) -> Result<()> {
        ensure!(
            self.remaining() >= size,
            "need at least {} bytes, got {}",
            size,
            self.remaining()
        );
        Ok(())
    }

    fn read_tag(&mut self, tag: &[u8]) -> Result<()> {
        let read = self.read_take(tag.len())?;
        ensure_eq!(tag, read, "invalid tag");
        Ok(())
    }
}

impl<B: Buf> BufParsing for B {}
