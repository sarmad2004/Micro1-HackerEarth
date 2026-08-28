//! The JSON Lines driver shared by both binaries.
//!
//! Both tiers read the same input and write the same output shape, so the
//! stream loop lives here once. Keeping it shared means a difference between
//! the two binaries can only come from the analyzer, never from framing.

use std::io::{BufRead, Write};

use crate::limits::MAX_LINE_BYTES;
use crate::{json, render_record, Rule, Verdict};

/// Run `analyze` over every record on `input`, writing results to `output`.
///
/// Never aborts on bad input: a malformed record produces a `MALFORMED_INPUT`
/// verdict and the stream continues, so one bad line cannot deny an agent its
/// verdicts for every other line.
pub fn run<R: BufRead, W: Write>(
    mut input: R,
    output: &mut W,
    analyze: fn(&str) -> Verdict,
) -> std::io::Result<()> {
    let mut raw: Vec<u8> = Vec::new();
    let mut lineno: u64 = 0;

    loop {
        raw.clear();
        let n = input.read_until(b'\n', &mut raw)?;
        if n == 0 {
            break;
        }
        lineno += 1;

        while matches!(raw.last(), Some(b'\n') | Some(b'\r')) {
            raw.pop();
        }
        if raw.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }

        let fallback_id = lineno.to_string();

        if raw.len() > MAX_LINE_BYTES {
            emit(output, &fallback_id, &Verdict::of(Rule::MalformedInput, "input line exceeds maximum length"))?;
            continue;
        }

        let line = match std::str::from_utf8(&raw) {
            Ok(s) => s,
            Err(_) => {
                emit(output, &fallback_id, &Verdict::of(Rule::MalformedInput, "input line is not valid UTF-8"))?;
                continue;
            }
        };

        let rec = match json::parse_record(line) {
            Some(r) => r,
            None => {
                emit(output, &fallback_id, &Verdict::of(Rule::MalformedInput, "line is not a JSON object"))?;
                continue;
            }
        };

        let id = rec.id.clone().unwrap_or(fallback_id);
        match rec.cmd {
            Some(cmd) => {
                let v = analyze(&cmd);
                emit(output, &id, &v)?;
            }
            None => emit(output, &id, &Verdict::of(Rule::MalformedInput, "record has no \"cmd\" field"))?,
        }
    }
    output.flush()
}

fn emit<W: Write>(output: &mut W, id: &str, v: &Verdict) -> std::io::Result<()> {
    let mut line = render_record(id, v);
    line.push('\n');
    output.write_all(line.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy;

    fn drive(input: &str) -> String {
        let mut out: Vec<u8> = Vec::new();
        run(std::io::Cursor::new(input.as_bytes().to_vec()), &mut out, policy::analyze).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn one_output_record_per_input_record() {
        let got = drive("{\"id\":\"a\",\"cmd\":\"ls\"}\n{\"id\":\"b\",\"cmd\":\"rm -rf /\"}\n");
        assert_eq!(got.lines().count(), 2);
        assert!(got.lines().next().unwrap().contains("\"decision\":\"ALLOW\""));
        assert!(got.lines().nth(1).unwrap().contains("\"decision\":\"DENY\""));
    }

    #[test]
    fn blank_lines_are_skipped_not_reported() {
        let got = drive("\n\n{\"id\":\"a\",\"cmd\":\"ls\"}\n   \n");
        assert_eq!(got.lines().count(), 1);
    }

    #[test]
    fn malformed_lines_do_not_stop_the_stream() {
        let got = drive("not json\n{\"id\":\"a\",\"cmd\":\"ls\"}\n{\"id\":\"c\"}\n");
        let lines: Vec<&str> = got.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("MALFORMED_INPUT"));
        assert!(lines[0].contains("\"id\":\"1\""));
        assert!(lines[1].contains("\"decision\":\"ALLOW\""));
        assert!(lines[2].contains("MALFORMED_INPUT"));
        assert!(lines[2].contains("\"id\":\"c\""));
    }

    #[test]
    fn missing_trailing_newline_is_fine() {
        let got = drive("{\"id\":\"a\",\"cmd\":\"ls\"}");
        assert_eq!(got.lines().count(), 1);
    }

    #[test]
    fn crlf_endings_are_handled() {
        let got = drive("{\"id\":\"a\",\"cmd\":\"ls\"}\r\n");
        assert_eq!(got.lines().count(), 1);
        assert!(got.contains("\"decision\":\"ALLOW\""));
    }

    #[test]
    fn output_key_order_is_fixed() {
        let got = drive("{\"cmd\":\"ls\",\"id\":\"z\"}\n");
        assert_eq!(got.trim(), "{\"id\":\"z\",\"decision\":\"ALLOW\",\"rule\":\"OK\",\"detail\":\"no rule matched\"}");
    }
}
