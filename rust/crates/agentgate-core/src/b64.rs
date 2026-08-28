//! Base64 decoding, used to resolve encoded payloads back to plaintext so the
//! analyzer can inspect what would actually execute.
//!
//! Standard alphabet only. Whitespace is skipped, since shell payloads are
//! routinely line-wrapped. Output is capped at [`crate::limits::MAX_B64_OUTPUT`].

use crate::limits::MAX_B64_OUTPUT;

fn value_of(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode `s` as base64, returning `None` when it is not valid base64, decodes
/// to non-UTF-8 bytes, or would exceed the output cap.
///
/// Returning `None` is not a failure the caller may ignore: per the fail-closed
/// principle it escalates to `OBFUSCATION`/`ASK` rather than to `ALLOW`.
pub fn decode(s: &str) -> Option<String> {
    let mut out: Vec<u8> = Vec::new();
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    let mut padding = 0usize;
    let mut symbols = 0usize;

    for &c in s.as_bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            padding += 1;
            continue;
        }
        // A symbol after padding has started is malformed.
        if padding > 0 {
            return None;
        }
        let v = value_of(c)?;
        acc = (acc << 6) | v as u32;
        nbits += 6;
        symbols += 1;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((acc >> nbits) & 0xFF) as u8);
            if out.len() > MAX_B64_OUTPUT {
                return None;
            }
        }
    }

    if symbols == 0 {
        return None;
    }
    // A valid stream has 0, 2 or 3 symbols in its final partial group.
    if symbols % 4 == 1 {
        return None;
    }
    if padding > 2 {
        return None;
    }
    // Leftover bits must be zero in a well-formed stream.
    if nbits > 0 && (acc & ((1 << nbits) - 1)) != 0 {
        return None;
    }
    String::from_utf8(out).ok()
}

/// True when `s` plausibly *is* a base64 payload rather than ordinary text.
///
/// Used to decide whether decoding is worth attempting; a false positive here
/// costs only a failed decode, never a wrong verdict.
pub fn looks_like_base64(s: &str) -> bool {
    let t: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if t.len() < 8 {
        return false;
    }
    let body_len = t.iter().take_while(|b| **b != b'=').count();
    t.iter().all(|b| value_of(*b).is_some() || *b == b'=') && body_len >= 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_corpus_payload() {
        assert_eq!(decode("cm0gLXJmIC8K").unwrap(), "rm -rf /\n");
    }

    #[test]
    fn handles_padding_and_whitespace() {
        assert_eq!(decode("aGVsbG8=").unwrap(), "hello");
        assert_eq!(decode("aGVs\nbG8=").unwrap(), "hello");
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode("!!!!").is_none());
        assert!(decode("").is_none());
        assert!(decode("a").is_none());
        assert!(decode("aGVsbG8=x").is_none());
    }

    #[test]
    fn rejects_non_utf8_output() {
        // 0xFF 0xFE is not valid UTF-8.
        assert!(decode("//4=").is_none());
    }

    #[test]
    fn detector_ignores_short_and_punctuated_text() {
        assert!(looks_like_base64("cm0gLXJmIC8K"));
        assert!(!looks_like_base64("rm -rf /"));
        assert!(!looks_like_base64("abc"));
    }
}
