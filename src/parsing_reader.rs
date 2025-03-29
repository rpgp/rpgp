use std::cmp;
use std::io::{BufRead, Read, Result};

use bytes::{BufMut, BytesMut};

pub trait BufReadParsing: BufRead + Sized {
    fn read_u8(&mut self) -> Result<u8> {
        let arr = self.read_array::<1>()?;
        Ok(arr[0])
    }

    fn read_be_u16(&mut self) -> Result<u16> {
        let arr = self.read_array::<2>()?;

        Ok(u16::from_be_bytes(arr))
    }

    #[allow(dead_code)]
    fn read_le_u16(&mut self) -> Result<u16> {
        let arr = self.read_array::<2>()?;

        Ok(u16::from_le_bytes(arr))
    }

    fn read_be_u32(&mut self) -> Result<u32> {
        let arr = self.read_array::<4>()?;

        Ok(u32::from_be_bytes(arr))
    }

    fn has_remaining(&mut self) -> Result<bool> {
        let has_remaining = !self.fill_buf()?.is_empty();
        Ok(has_remaining)
    }

    fn read_array<const C: usize>(&mut self) -> Result<[u8; C]> {
        let mut arr = [0u8; C];
        let mut read = 0;

        while read < arr.len() {
            let buf = self.fill_buf()?;
            if buf.is_empty() {
                break;
            }

            let available = (arr.len() - read).min(buf.len());
            arr[read..read + available].copy_from_slice(&buf[..available]);
            read += available;
            self.consume(available);
        }
        if read != arr.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "no more data available",
            ));
        }

        Ok(arr)
    }

    fn take_bytes(&mut self, size: usize) -> Result<BytesMut> {
        // Do not allocate everything upfront, only as data is actually available
        // to avoid OOM due to buggy sizes.
        let mut arr = BytesMut::with_capacity(size.min(1024));

        while arr.len() < size {
            let buf = self.fill_buf()?;
            if buf.is_empty() {
                break;
            }

            let available = (size - arr.len()).min(buf.len());
            arr.extend_from_slice(&buf[..available]);
            self.consume(available);
        }

        if arr.len() != size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "no more data available",
            ));
        }

        Ok(arr)
    }

    fn read_take(&mut self, limit: usize) -> Take<'_, Self> {
        Take { inner: self, limit }
    }

    fn rest(&mut self) -> Result<BytesMut> {
        let out = BytesMut::new();
        let mut writer = out.writer();
        std::io::copy(self, &mut writer)?;
        Ok(writer.into_inner())
    }

    /// Drain the data in this reader, to make sure all is consumed.
    /// Returns how many bytes have been drained
    fn drain(&mut self) -> Result<u64> {
        let mut out = std::io::sink();
        let copied = std::io::copy(self, &mut out)?;
        Ok(copied)
    }

    fn read_tag<const C: usize>(&mut self, tag: &[u8; C]) -> Result<()> {
        let found_tag = self.read_array::<C>()?;
        if tag != &found_tag {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "expected {}, found {}",
                    hex::encode(tag),
                    hex::encode(found_tag)
                ),
            ));
        }
        Ok(())
    }
}

impl<B: BufRead> BufReadParsing for B {}

/// Reader adapter which limits the bytes read from an underlying reader.
///
/// This struct is generally created by calling [`take`] on a reader.
/// Please see the documentation of [`take`] for more details.
///
/// [`take`]: Read::take
#[derive(Debug)]
pub struct Take<'a, T> {
    inner: &'a mut T,
    limit: usize,
}

impl<T: Read> Read for Take<'_, T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Don't call into inner reader at all at EOF because it may still block
        if self.limit == 0 {
            return Ok(0);
        }

        let max = cmp::min(buf.len(), self.limit);
        let n = self.inner.read(&mut buf[..max])?;
        assert!(n <= self.limit, "number of read bytes exceeds limit");
        self.limit -= n;
        Ok(n)
    }
}

impl<T: BufRead> BufRead for Take<'_, T> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        // Don't call into inner reader at all at EOF because it may still block
        if self.limit == 0 {
            return Ok(&[]);
        }

        let buf = self.inner.fill_buf()?;
        let cap = cmp::min(buf.len(), self.limit);
        Ok(&buf[..cap])
    }

    fn consume(&mut self, amt: usize) {
        // Don't let callers reset the limit by passing an overlarge value
        let amt = cmp::min(amt, self.limit);
        self.limit -= amt;
        self.inner.consume(amt);
    }
}
