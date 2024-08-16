//! # Line ending normalization module
//!
//! This crate provides a `normalize` method that takes an u8 iterator and returns
//! a new one with newlines normalized to a single style.
//!
//! Based on <https://github.com/derekdreery/normalize-line-endings>.

use std::iter::Peekable;

use crate::line_writer::LineBreak;

/// This struct wraps an u8 iterator to normalize line endings.
pub struct Normalized<I>
where
    I: Iterator<Item = u8>,
{
    line_break: LineBreak,
    iter: Peekable<I>,
    prev_was_cr: bool,
}

impl<I: Iterator<Item = u8>> Normalized<I> {
    /// Take a u8 iterator and return similar iterator with normalized line endings
    ///
    /// # Example
    /// ```
    /// use std::iter::FromIterator;
    ///
    /// use pgp::line_writer::LineBreak;
    /// use pgp::normalize_lines::Normalized;
    ///
    /// let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";
    /// assert_eq!(
    ///     &String::from_utf8(Normalized::new(input.bytes(), LineBreak::Lf).collect()).unwrap(),
    ///     "This is a string \n with \n some \n\n random newlines\n\n\n"
    /// );
    /// ```
    pub fn new(iter: I, line_break: LineBreak) -> Normalized<I> {
        Normalized {
            iter: iter.peekable(),
            prev_was_cr: false,
            line_break,
        }
    }
}

impl<I: Iterator<Item = u8>> Iterator for Normalized<I> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        match self.iter.peek() {
            Some(b'\n') => {
                match self.line_break {
                    LineBreak::Lf => {
                        if self.prev_was_cr {
                            // we already inserted a \n
                            let _ = self.iter.next();
                        }

                        self.iter.next()
                    }
                    LineBreak::Cr => {
                        // skip \n
                        let _ = self.iter.next();

                        if self.prev_was_cr {
                            self.prev_was_cr = false;
                            self.next()
                        } else {
                            Some(b'\r')
                        }
                    }
                    LineBreak::Crlf => {
                        if self.prev_was_cr {
                            self.prev_was_cr = false;
                            self.iter.next()
                        } else {
                            self.prev_was_cr = true;
                            Some(b'\r')
                        }
                    }
                }
            }
            Some(b'\r') => match self.line_break {
                LineBreak::Lf => {
                    self.prev_was_cr = true;
                    let _ = self.iter.next();
                    Some(b'\n')
                }
                LineBreak::Cr => {
                    self.prev_was_cr = true;
                    self.iter.next()
                }
                LineBreak::Crlf => {
                    if self.prev_was_cr {
                        self.prev_was_cr = false;
                        Some(b'\n')
                    } else {
                        self.prev_was_cr = true;
                        self.iter.next()
                    }
                }
            },
            _ => match self.line_break {
                LineBreak::Lf | LineBreak::Cr => {
                    self.prev_was_cr = false;
                    self.iter.next()
                }
                LineBreak::Crlf => {
                    let res = if self.prev_was_cr {
                        Some(b'\n')
                    } else {
                        self.iter.next()
                    };
                    self.prev_was_cr = false;
                    res
                }
            },
        }
    }
}

// tests
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn normalized_lf() {
        let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";
        assert_eq!(
            &String::from_utf8(Normalized::new(input.bytes(), LineBreak::Lf).collect()).unwrap(),
            "This is a string \n with \n some \n\n random newlines\n\n\n"
        );
    }

    #[test]
    fn normalized_cr() {
        let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";
        assert_eq!(
            &String::from_utf8(Normalized::new(input.bytes(), LineBreak::Cr).collect()).unwrap(),
            "This is a string \r with \r some \r\r random newlines\r\r\r"
        );
    }

    #[test]
    fn normalized_crlf() {
        let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";
        assert_eq!(
            &String::from_utf8(Normalized::new(input.bytes(), LineBreak::Crlf).collect()).unwrap(),
            "This is a string \r\n with \r\n some \r\n\r\n random newlines\r\n\r\n\r\n"
        );
    }
}
