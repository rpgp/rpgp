use std::io::{BufRead, Result};

use bytes::BytesMut;

pub trait BufReadParsing: BufRead {
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
            dbg!(&arr, read, C);
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "no more data available",
            ));
        }

        Ok(arr)
    }

    fn read_take(&mut self, size: usize) -> Result<BytesMut> {
        let mut arr = BytesMut::zeroed(size);
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
            dbg!(&arr, read, size);
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "no more data available",
            ));
        }

        Ok(arr)
    }

    // fn rest(&mut self) -> Bytes {
    //     let len = self.remaining();
    //     self.copy_to_bytes(len)
    // }

    // fn read_tag(&mut self, tag: &[u8]) -> Result<()> {
    //     self.ensure_remaining(tag.len())?;
    //     let read = self.copy_to_bytes(tag.len());
    //     if tag != read {
    //         return Err(Error::TagMissmatch {
    //             context: "todo",
    //             expected: tag.to_vec(),
    //             found: read,
    //             backtrace: snafu::GenerateImplicitData::generate(),
    //         });
    //     }
    //     Ok(())
    // }
}

impl<B: BufRead> BufReadParsing for B {}
