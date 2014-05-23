
pub trait StrSliceEscape {
    fn escape_default_except_lf(&self) -> StrBuf;
}

impl StrSliceEscape for StrBuf {
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
