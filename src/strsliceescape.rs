pub trait StrSliceEscape {
    fn escape_default_except_lf(&self) -> String;
}

impl StrSliceEscape for String {
    fn escape_default_except_lf(&self) -> String {
        let mut out = String::with_capacity(self.len());
        for c in self.chars() {
            out.push(match c {
                '\r' | '\n' | '\t' | '\x20'...'\x7e' => c,
                _ => '?',
            })
        }
        out
    }
}
