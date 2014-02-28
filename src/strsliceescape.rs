
use std::char;
use std::str;

pub trait StrSliceEscape<'a> {
    fn escape_default_except_lf(&self) -> ~str;
}

impl<'a> StrSliceEscape<'a> for &'a str {
    fn escape_default_except_lf(&self) -> ~str {
        let mut out = str::with_capacity(self.len());
        for c in self.chars() {
            match c {
                '\r' => { out.push_char('\\'); out.push_char('r'); }
                '\\' => { out.push_char('\\'); out.push_char('\\'); }
                '\'' => { out.push_char('\\'); out.push_char('\''); }
                '"'  => { out.push_char('\\'); out.push_char('"'); }
                '\n' | '\t' | '\x20' .. '\x7e' => { out.push_char(c); }
                _ => char::escape_unicode(c, |c| { out.push_char(c); })
            }
        }
        out
    }
}
