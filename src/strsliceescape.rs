
use std::str;

pub trait StrSliceEscape<'a> {
    fn escape_default_except_lf(&self) -> ~str;
}

impl<'a> StrSliceEscape<'a> for &'a str {
    fn escape_default_except_lf(&self) -> ~str {
        let mut out = str::with_capacity(self.len());
        for c in self.chars() {
            out.push_char(match c {
                '\r' | '\n' | '\t' | '\x20' .. '\x7e' => c,
                _ => '?'
            })
        }
        out
    }
}
