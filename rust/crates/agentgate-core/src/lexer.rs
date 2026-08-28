//! Shell tokenizer implementing POSIX quoting and expansion syntax.
//!
//! The tokenizer preserves *structure* that a substring scan destroys: it knows
//! that `r''m` is the single word `rm`, that the `rm -rf /` inside
//! `echo 'rm -rf /'` is inert data, and that `${IFS}` is an expansion which
//! will later split a word into fields.
//!
//! It is a single left-to-right pass, linear in input length, and iterative
//! everywhere except bounded nesting inside substitutions.

use crate::limits::{MAX_CMD_BYTES, MAX_TOKENS};

/// One piece of a word. A word is a sequence of segments concatenated without
/// separators; `a"b"$c` is `[Lit("a"), Lit("b"), Var("c")]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// Literal text, from unquoted, single-quoted or double-quoted input.
    Lit(String),
    /// A parameter expansion, `$NAME` or `${NAME}`.
    Var { name: String, quoted: bool },
    /// A command substitution, `$(...)` or backticks; holds the inner source.
    CmdSub { src: String, quoted: bool },
    /// An arithmetic expansion, `$((...))`.
    Arith { quoted: bool },
    /// A process substitution, `<(...)` or `>(...)`; holds the inner source.
    /// The inner command runs, so the analyzer descends into it.
    ProcSub { src: String },
}

/// A shell word: the segments it is built from, plus whether any part of it was
/// quoted (which suppresses field splitting).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Word {
    pub segs: Vec<Segment>,
    pub quoted: bool,
}

impl Word {
    /// The word's text if every segment is a literal, else `None`.
    pub fn literal(&self) -> Option<String> {
        let mut s = String::new();
        for seg in &self.segs {
            match seg {
                Segment::Lit(t) => s.push_str(t),
                _ => return None,
            }
        }
        Some(s)
    }

    pub fn has_expansion(&self) -> bool {
        self.segs.iter().any(|s| !matches!(s, Segment::Lit(_)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirOp {
    /// `<`
    In,
    /// `>`
    Out,
    /// `>>`
    Append,
    /// `<<<`
    HereString,
    /// `<<`
    HereDoc,
    /// `>&` or `&>`
    DupOut,
    /// `<&`
    DupIn,
    /// `<>`
    ReadWrite,
    /// `>|`
    Clobber,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    Word(Word),
    /// `;`
    Semi,
    /// `&`
    Amp,
    /// `&&`
    AndIf,
    /// `||`
    OrIf,
    /// `|`
    Pipe,
    /// A literal newline, which separates commands like `;`.
    Newline,
    LParen,
    RParen,
    LBrace,
    RBrace,
    Redir { fd: Option<i32>, op: RedirOp },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexError {
    pub message: String,
}

impl LexError {
    fn new(m: &str) -> Self {
        LexError { message: m.to_string() }
    }
}

struct WordBuf {
    segs: Vec<Segment>,
    cur: String,
    started: bool,
    quoted: bool,
}

impl WordBuf {
    fn new() -> Self {
        WordBuf { segs: Vec::new(), cur: String::new(), started: false, quoted: false }
    }
    fn push_char(&mut self, c: char) {
        self.cur.push(c);
        self.started = true;
    }
    fn push_str(&mut self, s: &str) {
        self.cur.push_str(s);
        self.started = true;
    }
    fn flush_lit(&mut self) {
        if !self.cur.is_empty() {
            self.segs.push(Segment::Lit(std::mem::take(&mut self.cur)));
        }
    }
    fn push_seg(&mut self, s: Segment) {
        self.flush_lit();
        self.segs.push(s);
        self.started = true;
    }
    fn take(&mut self) -> Option<Word> {
        self.flush_lit();
        if !self.started {
            self.segs.clear();
            self.quoted = false;
            return None;
        }
        let w = Word { segs: std::mem::take(&mut self.segs), quoted: self.quoted };
        self.started = false;
        self.quoted = false;
        Some(w)
    }
}

/// Tokenize `src` into a flat token stream.
pub fn tokenize(src: &str) -> Result<Vec<Tok>, LexError> {
    if src.len() > MAX_CMD_BYTES {
        return Err(LexError::new("command exceeds maximum length"));
    }
    let b: Vec<char> = src.chars().collect();
    let mut i = 0usize;
    let n = b.len();
    let mut toks: Vec<Tok> = Vec::new();
    let mut wb = WordBuf::new();

    macro_rules! flush_word {
        () => {
            if let Some(w) = wb.take() {
                toks.push(Tok::Word(w));
                if toks.len() > MAX_TOKENS {
                    return Err(LexError::new("token limit exceeded"));
                }
            }
        };
    }

    while i < n {
        let c = b[i];

        // Comment: only when it starts a word.
        if c == '#' && !wb.started {
            while i < n && b[i] != '\n' {
                i += 1;
            }
            continue;
        }

        if c == '\n' {
            flush_word!();
            toks.push(Tok::Newline);
            i += 1;
            continue;
        }

        if c == ' ' || c == '\t' || c == '\r' {
            flush_word!();
            i += 1;
            continue;
        }

        // Line continuation.
        if c == '\\' && i + 1 < n && b[i + 1] == '\n' {
            i += 2;
            continue;
        }

        // Backslash escape: the next character is literal.
        if c == '\\' {
            if i + 1 >= n {
                return Err(LexError::new("trailing backslash"));
            }
            wb.push_char(b[i + 1]);
            wb.quoted = true;
            i += 2;
            continue;
        }

        if c == '\'' {
            let mut j = i + 1;
            let mut s = String::new();
            loop {
                if j >= n {
                    return Err(LexError::new("unterminated single quote"));
                }
                if b[j] == '\'' {
                    break;
                }
                s.push(b[j]);
                j += 1;
            }
            wb.push_str(&s);
            wb.started = true;
            wb.quoted = true;
            i = j + 1;
            continue;
        }

        if c == '"' {
            i = lex_double_quoted(&b, i + 1, &mut wb)?;
            wb.quoted = true;
            continue;
        }

        if c == '`' {
            let (src_inner, next) = read_backtick(&b, i + 1)?;
            wb.push_seg(Segment::CmdSub { src: src_inner, quoted: false });
            i = next;
            continue;
        }

        if c == '$' {
            match lex_dollar(&b, i, false, &mut wb)? {
                Some(next) => {
                    i = next;
                    continue;
                }
                None => {
                    wb.push_char('$');
                    i += 1;
                    continue;
                }
            }
        }

        // Process substitution `<( … )` / `>( … )` is a word, not a redirect:
        // the shell replaces it with a /dev/fd path and runs the inner command.
        if (c == '<' || c == '>') && i + 1 < n && b[i + 1] == '(' {
            let (src, next) = read_paren_sub(&b, i + 2)?;
            wb.push_seg(Segment::ProcSub { src });
            i = next;
            continue;
        }

        // Redirections, possibly with a leading file descriptor already
        // accumulated as digits in the current word.
        if c == '<' || c == '>' {
            let fd = take_fd(&mut wb);
            if fd.is_none() {
                flush_word!();
            }
            let (op, next) = read_redir_op(&b, i)?;
            toks.push(Tok::Redir { fd, op });
            i = next;
            continue;
        }

        // `&>` is a bash redirection; a bare `&` is a control operator.
        if c == '&' {
            if i + 1 < n && b[i + 1] == '>' {
                flush_word!();
                let mut next = i + 2;
                if next < n && b[next] == '>' {
                    next += 1;
                }
                toks.push(Tok::Redir { fd: None, op: RedirOp::DupOut });
                i = next;
                continue;
            }
            flush_word!();
            if i + 1 < n && b[i + 1] == '&' {
                toks.push(Tok::AndIf);
                i += 2;
            } else {
                toks.push(Tok::Amp);
                i += 1;
            }
            continue;
        }

        if c == '|' {
            flush_word!();
            if i + 1 < n && b[i + 1] == '|' {
                toks.push(Tok::OrIf);
                i += 2;
            } else {
                toks.push(Tok::Pipe);
                i += 1;
            }
            continue;
        }

        if c == ';' {
            flush_word!();
            toks.push(Tok::Semi);
            i += 1;
            continue;
        }

        if c == '(' {
            flush_word!();
            toks.push(Tok::LParen);
            i += 1;
            continue;
        }

        if c == ')' {
            flush_word!();
            toks.push(Tok::RParen);
            i += 1;
            continue;
        }

        // `{` and `}` are operators only when they stand alone as a word,
        // so that brace expansion like `file{1,2}.txt` stays a single word.
        if c == '{' && !wb.started && i + 1 < n && is_blank(b[i + 1]) {
            toks.push(Tok::LBrace);
            i += 1;
            continue;
        }
        if c == '}' && !wb.started {
            let follows_end = i + 1 >= n || is_blank(b[i + 1]) || matches!(b[i + 1], ';' | '&' | ')' | '|');
            if follows_end {
                toks.push(Tok::RBrace);
                i += 1;
                continue;
            }
        }

        wb.push_char(c);
        i += 1;
    }

    flush_word!();
    Ok(toks)
}

fn is_blank(c: char) -> bool {
    c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

/// If the pending word is entirely ASCII digits, consume it as a redirect fd.
fn take_fd(wb: &mut WordBuf) -> Option<i32> {
    if !wb.segs.is_empty() || wb.cur.is_empty() || wb.quoted {
        return None;
    }
    if !wb.cur.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let fd = wb.cur.parse::<i32>().ok()?;
    wb.cur.clear();
    wb.started = false;
    Some(fd)
}

fn read_redir_op(b: &[char], i: usize) -> Result<(RedirOp, usize), LexError> {
    let n = b.len();
    let c = b[i];
    let next = |k: usize| -> Option<char> { b.get(k).copied() };
    if c == '>' {
        return Ok(match next(i + 1) {
            Some('>') => (RedirOp::Append, i + 2),
            Some('&') => (RedirOp::DupOut, i + 2),
            Some('|') => (RedirOp::Clobber, i + 2),
            _ => (RedirOp::Out, i + 1),
        });
    }
    // c == '<'
    if next(i + 1) == Some('<') {
        if next(i + 2) == Some('<') {
            return Ok((RedirOp::HereString, i + 3));
        }
        return Ok((RedirOp::HereDoc, i + 2));
    }
    if next(i + 1) == Some('&') {
        return Ok((RedirOp::DupIn, i + 2));
    }
    if next(i + 1) == Some('>') {
        return Ok((RedirOp::ReadWrite, i + 2));
    }
    let _ = n;
    Ok((RedirOp::In, i + 1))
}

/// Lex the body of a double-quoted string starting at `i` (just past the `"`).
fn lex_double_quoted(b: &[char], mut i: usize, wb: &mut WordBuf) -> Result<usize, LexError> {
    let n = b.len();
    wb.started = true;
    loop {
        if i >= n {
            return Err(LexError::new("unterminated double quote"));
        }
        let c = b[i];
        if c == '"' {
            return Ok(i + 1);
        }
        if c == '\\' {
            if i + 1 >= n {
                return Err(LexError::new("unterminated double quote"));
            }
            let e = b[i + 1];
            // Inside double quotes a backslash only escapes these.
            if matches!(e, '"' | '\\' | '$' | '`' | '\n') {
                if e != '\n' {
                    wb.push_char(e);
                }
                i += 2;
                continue;
            }
            wb.push_char('\\');
            i += 1;
            continue;
        }
        if c == '`' {
            let (src, next) = read_backtick(b, i + 1)?;
            wb.push_seg(Segment::CmdSub { src, quoted: true });
            i = next;
            continue;
        }
        if c == '$' {
            match lex_dollar(b, i, true, wb)? {
                Some(next) => {
                    i = next;
                    continue;
                }
                None => {
                    wb.push_char('$');
                    i += 1;
                    continue;
                }
            }
        }
        wb.push_char(c);
        i += 1;
    }
}

/// Lex a `$`-expansion at `i`. Returns the index just past it, or `None` when
/// the `$` is a literal dollar sign.
fn lex_dollar(
    b: &[char],
    i: usize,
    quoted: bool,
    wb: &mut WordBuf,
) -> Result<Option<usize>, LexError> {
    let n = b.len();
    let c1 = match b.get(i + 1) {
        Some(c) => *c,
        None => return Ok(None),
    };

    // $((...)) arithmetic
    if c1 == '(' && b.get(i + 2) == Some(&'(') {
        let mut depth = 1i32;
        let mut j = i + 3;
        while j < n {
            if b[j] == '(' {
                depth += 1;
            } else if b[j] == ')' {
                depth -= 1;
                if depth == 0 {
                    // Expect the second closing paren.
                    if b.get(j + 1) == Some(&')') {
                        wb.push_seg(Segment::Arith { quoted });
                        return Ok(Some(j + 2));
                    }
                }
            }
            j += 1;
        }
        return Err(LexError::new("unterminated arithmetic expansion"));
    }

    // $(...) command substitution
    if c1 == '(' {
        let (src, next) = read_paren_sub(b, i + 2)?;
        wb.push_seg(Segment::CmdSub { src, quoted });
        return Ok(Some(next));
    }

    // ${NAME}
    if c1 == '{' {
        let mut j = i + 2;
        let mut name = String::new();
        while j < n && b[j] != '}' {
            name.push(b[j]);
            j += 1;
        }
        if j >= n {
            return Err(LexError::new("unterminated parameter expansion"));
        }
        wb.push_seg(Segment::Var { name, quoted });
        return Ok(Some(j + 1));
    }

    // $NAME
    if c1.is_ascii_alphabetic() || c1 == '_' {
        let mut j = i + 1;
        let mut name = String::new();
        while j < n && (b[j].is_ascii_alphanumeric() || b[j] == '_') {
            name.push(b[j]);
            j += 1;
        }
        wb.push_seg(Segment::Var { name, quoted });
        return Ok(Some(j));
    }

    // Special parameters: $?, $$, $!, $0-$9, $@, $*, $#
    if matches!(c1, '?' | '$' | '!' | '@' | '*' | '#') || c1.is_ascii_digit() {
        wb.push_seg(Segment::Var { name: c1.to_string(), quoted });
        return Ok(Some(i + 2));
    }

    Ok(None)
}

/// Read a `$( ... )` body, honouring nesting and quotes, returning the inner
/// source and the index just past the closing paren.
fn read_paren_sub(b: &[char], start: usize) -> Result<(String, usize), LexError> {
    let n = b.len();
    let mut depth = 1i32;
    let mut j = start;
    let mut out = String::new();
    while j < n {
        let c = b[j];
        match c {
            '\\' if j + 1 < n => {
                out.push(c);
                out.push(b[j + 1]);
                j += 2;
                continue;
            }
            '\'' => {
                out.push(c);
                j += 1;
                while j < n && b[j] != '\'' {
                    out.push(b[j]);
                    j += 1;
                }
                if j >= n {
                    return Err(LexError::new("unterminated quote in substitution"));
                }
                out.push('\'');
                j += 1;
                continue;
            }
            '"' => {
                out.push(c);
                j += 1;
                while j < n && b[j] != '"' {
                    if b[j] == '\\' && j + 1 < n {
                        out.push(b[j]);
                        j += 1;
                    }
                    out.push(b[j]);
                    j += 1;
                }
                if j >= n {
                    return Err(LexError::new("unterminated quote in substitution"));
                }
                out.push('"');
                j += 1;
                continue;
            }
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((out, j + 1));
                }
            }
            _ => {}
        }
        out.push(c);
        j += 1;
    }
    Err(LexError::new("unterminated command substitution"))
}

/// Read a backtick substitution body.
fn read_backtick(b: &[char], start: usize) -> Result<(String, usize), LexError> {
    let n = b.len();
    let mut j = start;
    let mut out = String::new();
    while j < n {
        if b[j] == '\\' && j + 1 < n {
            out.push(b[j + 1]);
            j += 2;
            continue;
        }
        if b[j] == '`' {
            return Ok((out, j + 1));
        }
        out.push(b[j]);
        j += 1;
    }
    Err(LexError::new("unterminated backtick substitution"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(src: &str) -> Vec<String> {
        tokenize(src)
            .unwrap()
            .into_iter()
            .filter_map(|t| match t {
                Tok::Word(w) => Some(w.literal().unwrap_or_else(|| "<expand>".into())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn splits_plain_words() {
        assert_eq!(words("ls -la /tmp"), vec!["ls", "-la", "/tmp"]);
    }

    #[test]
    fn collapses_quote_splicing() {
        // The evasion that defeats substring matching.
        assert_eq!(words("r''m -rf /"), vec!["rm", "-rf", "/"]);
        assert_eq!(words("\"rm\" -rf /"), vec!["rm", "-rf", "/"]);
        assert_eq!(words("r\\m -rf /"), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn single_quotes_are_literal() {
        assert_eq!(words("echo 'rm -rf /'"), vec!["echo", "rm -rf /"]);
    }

    #[test]
    fn comments_are_stripped() {
        assert_eq!(words("ls # rm -rf /"), vec!["ls"]);
        assert_eq!(words("# whole line"), Vec::<String>::new());
    }

    #[test]
    fn operators_become_tokens() {
        let t = tokenize("a && b || c | d ; e & f").unwrap();
        assert!(t.contains(&Tok::AndIf));
        assert!(t.contains(&Tok::OrIf));
        assert!(t.contains(&Tok::Pipe));
        assert!(t.contains(&Tok::Semi));
        assert!(t.contains(&Tok::Amp));
    }

    #[test]
    fn redirects_capture_fd_and_op() {
        let t = tokenize("cmd 2> err.log").unwrap();
        assert!(t.contains(&Tok::Redir { fd: Some(2), op: RedirOp::Out }));
        let t = tokenize("cmd >> out.log").unwrap();
        assert!(t.contains(&Tok::Redir { fd: None, op: RedirOp::Append }));
        let t = tokenize("sh <<< 'payload'").unwrap();
        assert!(t.contains(&Tok::Redir { fd: None, op: RedirOp::HereString }));
    }

    #[test]
    fn expansions_are_segments_not_text() {
        let t = tokenize("rm${IFS}-rf${IFS}/").unwrap();
        match &t[0] {
            Tok::Word(w) => {
                assert!(w.has_expansion());
                assert!(w.literal().is_none());
            }
            _ => panic!("expected a word"),
        }
    }

    #[test]
    fn command_substitution_keeps_inner_source() {
        let t = tokenize("$(echo rm) -rf /").unwrap();
        match &t[0] {
            Tok::Word(w) => match &w.segs[0] {
                Segment::CmdSub { src, .. } => assert_eq!(src, "echo rm"),
                other => panic!("expected CmdSub, got {other:?}"),
            },
            _ => panic!("expected a word"),
        }
    }

    #[test]
    fn brace_group_and_subshell_tokens() {
        let t = tokenize("{ rm -rf / ; }").unwrap();
        assert_eq!(t[0], Tok::LBrace);
        assert_eq!(*t.last().unwrap(), Tok::RBrace);
        let t = tokenize("( rm -rf / )").unwrap();
        assert_eq!(t[0], Tok::LParen);
    }

    #[test]
    fn brace_expansion_stays_one_word() {
        assert_eq!(words("cp file{1,2}.txt dst/"), vec!["cp", "file{1,2}.txt", "dst/"]);
    }

    #[test]
    fn fork_bomb_tokenizes_structurally() {
        let t = tokenize(":(){ :|:& };:").unwrap();
        assert_eq!(t[0], Tok::Word(Word { segs: vec![Segment::Lit(":".into())], quoted: false }));
        assert_eq!(t[1], Tok::LParen);
        assert_eq!(t[2], Tok::RParen);
        assert_eq!(t[3], Tok::LBrace);
    }

    #[test]
    fn unterminated_constructs_error_rather_than_panic() {
        assert!(tokenize("rm -rf \"").is_err());
        assert!(tokenize("echo 'abc").is_err());
        assert!(tokenize("$(rm -rf /").is_err());
        assert!(tokenize("echo `hi").is_err());
        assert!(tokenize("echo \\").is_err());
    }

    #[test]
    fn process_substitution_is_a_word_not_a_redirect() {
        let t = tokenize("diff <(sort a.txt) <(sort b.txt)").unwrap();
        let words: Vec<&Tok> = t.iter().filter(|k| matches!(k, Tok::Word(_))).collect();
        assert_eq!(words.len(), 3);
        assert!(!t.iter().any(|k| matches!(k, Tok::Redir { .. })));
        match &t[1] {
            Tok::Word(w) => match &w.segs[0] {
                Segment::ProcSub { src } => assert_eq!(src, "sort a.txt"),
                other => panic!("expected ProcSub, got {other:?}"),
            },
            _ => panic!("expected a word"),
        }
    }

    #[test]
    fn newlines_separate_commands() {
        let t = tokenize("ls\nrm -rf /").unwrap();
        assert!(t.contains(&Tok::Newline));
    }

    #[test]
    fn oversized_input_is_rejected() {
        let big = "a".repeat(MAX_CMD_BYTES + 1);
        assert!(tokenize(&big).is_err());
    }
}
