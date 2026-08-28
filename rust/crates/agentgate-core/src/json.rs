//! A minimal JSON reader and writer, sufficient for the JSON Lines contract in
//! SPEC.md section 2 and no more.
//!
//! Hand-written rather than pulled from crates.io so that the build needs no
//! network access. It parses exactly one shape -- a flat object whose values we
//! read as strings -- and rejects everything else rather than guessing.

/// Append `s` to `out` as a quoted, escaped JSON string.
pub fn escape_into(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) == 0x08 => out.push_str("\\b"),
            c if (c as u32) == 0x0c => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                let v = c as u32;
                for shift in [12, 8, 4, 0] {
                    let nib = (v >> shift) & 0xF;
                    out.push(char::from_digit(nib, 16).unwrap());
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The fields we need from one input record.
#[derive(Debug, Default, Clone)]
pub struct Record {
    pub id: Option<String>,
    pub cmd: Option<String>,
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let c = self.peek();
        if c.is_some() {
            self.i += 1;
        }
        c
    }
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')) {
            self.i += 1;
        }
    }
}

/// Parse one JSON object line into a [`Record`].
///
/// Returns `None` when the line is not a JSON object. Unknown keys are skipped
/// so that added fields never break us (SPEC.md section 2.1).
pub fn parse_record(line: &str) -> Option<Record> {
    let mut c = Cursor { b: line.as_bytes(), i: 0 };
    c.skip_ws();
    if c.bump() != Some(b'{') {
        return None;
    }
    let mut rec = Record::default();
    c.skip_ws();
    if c.peek() == Some(b'}') {
        return Some(rec);
    }
    loop {
        c.skip_ws();
        let key = parse_string(&mut c)?;
        c.skip_ws();
        if c.bump() != Some(b':') {
            return None;
        }
        c.skip_ws();
        let value = parse_value(&mut c)?;
        match key.as_str() {
            "id" => rec.id = value,
            "cmd" => rec.cmd = value,
            _ => {}
        }
        c.skip_ws();
        match c.bump() {
            Some(b',') => continue,
            Some(b'}') => break,
            _ => return None,
        }
    }
    Some(rec)
}

/// Parse any JSON value. Strings come back as `Some(text)`; other well-formed
/// values we do not need come back as `None` inside the outer `Some`.
fn parse_value(c: &mut Cursor) -> Option<Option<String>> {
    match c.peek()? {
        b'"' => Some(Some(parse_string(c)?)),
        b'{' | b'[' => {
            skip_composite(c)?;
            Some(None)
        }
        b't' => expect_word(c, b"true").map(|_| None),
        b'f' => expect_word(c, b"false").map(|_| None),
        b'n' => expect_word(c, b"null").map(|_| None),
        _ => {
            let start = c.i;
            while let Some(ch) = c.peek() {
                if ch.is_ascii_digit() || matches!(ch, b'-' | b'+' | b'.' | b'e' | b'E') {
                    c.i += 1;
                } else {
                    break;
                }
            }
            if c.i == start {
                None
            } else {
                Some(None)
            }
        }
    }
}

fn expect_word(c: &mut Cursor, w: &[u8]) -> Option<()> {
    if c.b.len() >= c.i + w.len() && &c.b[c.i..c.i + w.len()] == w {
        c.i += w.len();
        Some(())
    } else {
        None
    }
}

/// Skip a nested object or array without interpreting it.
fn skip_composite(c: &mut Cursor) -> Option<()> {
    let open = c.bump()?;
    let close = if open == b'{' { b'}' } else { b']' };
    let mut depth = 1usize;
    while depth > 0 {
        match c.peek()? {
            b'"' => {
                parse_string(c)?;
                continue;
            }
            ch if ch == open => depth += 1,
            ch if ch == close => depth -= 1,
            _ => {}
        }
        c.i += 1;
    }
    Some(())
}

fn parse_string(c: &mut Cursor) -> Option<String> {
    if c.bump() != Some(b'"') {
        return None;
    }
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        match c.bump()? {
            b'"' => break,
            b'\\' => match c.bump()? {
                b'"' => bytes.push(b'"'),
                b'\\' => bytes.push(b'\\'),
                b'/' => bytes.push(b'/'),
                b'b' => bytes.push(0x08),
                b'f' => bytes.push(0x0c),
                b'n' => bytes.push(b'\n'),
                b'r' => bytes.push(b'\r'),
                b't' => bytes.push(b'\t'),
                b'u' => {
                    let hi = parse_hex4(c)?;
                    let ch = if (0xD800..0xDC00).contains(&hi) {
                        if c.bump() != Some(b'\\') || c.bump() != Some(b'u') {
                            return None;
                        }
                        let lo = parse_hex4(c)?;
                        if !(0xDC00..0xE000).contains(&lo) {
                            return None;
                        }
                        let cp = 0x10000 + (((hi - 0xD800) as u32) << 10) + (lo - 0xDC00) as u32;
                        char::from_u32(cp)?
                    } else {
                        char::from_u32(hi as u32)?
                    };
                    let mut buf = [0u8; 4];
                    bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                _ => return None,
            },
            ch => bytes.push(ch),
        }
    }
    String::from_utf8(bytes).ok()
}

fn parse_hex4(c: &mut Cursor) -> Option<u16> {
    let mut v: u16 = 0;
    for _ in 0..4 {
        let d = c.bump()?;
        let n = match d {
            b'0'..=b'9' => d - b'0',
            b'a'..=b'f' => d - b'a' + 10,
            b'A'..=b'F' => d - b'A' + 10,
            _ => return None,
        };
        v = v.checked_mul(16)?.checked_add(n as u16)?;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_id_and_cmd() {
        let r = parse_record(r#"{"id":"a","cmd":"ls -la"}"#).unwrap();
        assert_eq!(r.id.as_deref(), Some("a"));
        assert_eq!(r.cmd.as_deref(), Some("ls -la"));
    }

    #[test]
    fn ignores_unknown_fields_including_nested() {
        let line = r#"{"extra":{"a":[1,2,{"b":"}"}]},"id":"x","cmd":"ls","n":-1.5e3}"#;
        let r = parse_record(line).unwrap();
        assert_eq!(r.id.as_deref(), Some("x"));
        assert_eq!(r.cmd.as_deref(), Some("ls"));
    }

    #[test]
    fn decodes_escapes_and_unicode() {
        let r = parse_record(r#"{"id":"1","cmd":"a\nb\t\"c\" é 😀"}"#).unwrap();
        assert_eq!(r.cmd.unwrap(), "a\nb\t\"c\" \u{e9} \u{1f600}");
    }

    #[test]
    fn rejects_non_objects() {
        assert!(parse_record("[1,2]").is_none());
        assert!(parse_record("not json").is_none());
        assert!(parse_record(r#"{"id":"a""#).is_none());
    }

    #[test]
    fn empty_object_is_valid_but_empty() {
        let r = parse_record("{}").unwrap();
        assert!(r.id.is_none() && r.cmd.is_none());
    }

    #[test]
    fn escape_handles_quotes_and_controls() {
        let mut s = String::new();
        escape_into("a\"b\\c\nd\u{1}", &mut s);
        assert_eq!(s, "\"a\\\"b\\\\c\\nd\\u0001\"");
    }
}
