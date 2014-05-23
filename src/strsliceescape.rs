
pub trait StrSliceEscape<'a> {
    fn escape_default_except_lf(&self) -> StrBuf;
}

impl<'a> StrSliceEscape<'a> for &'a StrBuf {
    fn escape_default_except_lf(&self) -> StrBuf {
        let mut out = StrBuf::with_capacity(self.len());
        for c in self.as_slice().chars() {
            out.push_char(match c {
                '\r' | '\n' | '\t' | '\x20' .. '\x7e' => c,
                _ => '?'
            })
        }
        out.into_strbuf()
    }
}
