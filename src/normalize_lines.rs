//! Normalize line endings
//!
//! This crate provides a `normalize` method that takes a char iterator and returns
//! a new one with `\n` for all line endings
//!
//! Based on https://github.com/derekdreery/normalize-line-endings.

use line_writer::LineBreak;
use std::iter::Peekable;

/// This struct wraps a `std::io::Chars` to normalize line endings.
///
/// Implements `Iterator<Item=char>` so can be used in place
pub struct Normalized<I>
where
    I: Iterator<Item = char>,
{
    line_break: LineBreak,
    iter: Peekable<I>,
    prev_was_cr: bool,
}

impl<I: Iterator<Item = char>> Normalized<I> {
    /// Take a Chars and return similar struct with normalized line endings
    ///
    /// # Example
    /// ```
    /// use std::iter::FromIterator;
    /// use pgp::normalize_lines::Normalized;
    /// use pgp::line_writer::LineBreak;
    ///
    /// let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";
    /// assert_eq!(
    ///     &String::from_iter(Normalized::new(input.chars(), LineBreak::Lf)),
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

impl<I: Iterator<Item = char>> Iterator for Normalized<I> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        match self.iter.peek() {
            Some('\n') => {
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
                            Some('\r')
                        }
                    }
                    LineBreak::Crlf => {
                        if self.prev_was_cr {
                            self.prev_was_cr = false;
                            self.iter.next()
                        } else {
                            self.prev_was_cr = true;
                            Some('\r')
                        }
                    }
                }
            }
            Some('\r') => match self.line_break {
                LineBreak::Lf => {
                    self.prev_was_cr = true;
                    let _ = self.iter.next();
                    Some('\n')
                }
                LineBreak::Cr => {
                    self.prev_was_cr = true;
                    self.iter.next()
                }
                LineBreak::Crlf => {
                    if self.prev_was_cr {
                        self.prev_was_cr = false;
                        Some('\n')
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
                    if self.prev_was_cr {
                        self.prev_was_cr = false;
                        Some('\n')
                    } else {
                        self.prev_was_cr = false;
                        self.iter.next()
                    }
                }
            },
        }
    }
}

// tests
#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::FromIterator;

    use line_writer::LineBreak;

    #[test]
    fn normalized_lf() {
        let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";
        assert_eq!(
            &String::from_iter(Normalized::new(input.chars(), LineBreak::Lf)),
            "This is a string \n with \n some \n\n random newlines\n\n\n"
        );
    }

    #[test]
    fn normalized_cr() {
        let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";
        assert_eq!(
            &String::from_iter(Normalized::new(input.chars(), LineBreak::Cr)),
            "This is a string \r with \r some \r\r random newlines\r\r\r"
        );
    }

    #[test]
    fn normalized_crlf() {
        let input = "This is a string \n with \r some \n\r\n random newlines\r\r\n\n";
        assert_eq!(
            &String::from_iter(Normalized::new(input.chars(), LineBreak::Crlf)),
            "This is a string \r\n with \r\n some \r\n\r\n random newlines\r\n\r\n\r\n"
        );
    }
}
