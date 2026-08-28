//! Builds an AST from the token stream.
//!
//! The grammar is deliberately smaller than real POSIX shell. It captures
//! everything that determines *what will execute* -- command boundaries,
//! pipelines, subshells, brace groups, function definitions, assignments and
//! redirections -- and ignores everything that does not, such as the difference
//! between `;` and `&&`. For a safety analysis both branches of `&&` may run, so
//! collapsing them is the conservative choice.

use crate::lexer::{RedirOp, Tok, Word};
use crate::limits::MAX_NEST_DEPTH;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub fd: Option<i32>,
    pub op: RedirOp,
    pub target: Word,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SimpleCmd {
    /// Leading `NAME=value` assignments.
    pub assigns: Vec<(String, Word)>,
    /// The command name and its arguments.
    pub words: Vec<Word>,
    pub redirects: Vec<Redirect>,
}

impl SimpleCmd {
    pub fn is_empty(&self) -> bool {
        self.words.is_empty() && self.redirects.is_empty() && self.assigns.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmd {
    Simple(SimpleCmd),
    /// A subshell `( ... )` or brace group `{ ...; }`.
    Nested(Script),
    /// `name() { ... }`
    FuncDef { name: String, body: Script },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pipeline {
    pub cmds: Vec<Cmd>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Script {
    pub pipelines: Vec<Pipeline>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
}

impl ParseError {
    fn new(m: &str) -> Self {
        ParseError { message: m.to_string() }
    }
}

struct P<'a> {
    t: &'a [Tok],
    i: usize,
}

impl<'a> P<'a> {
    fn peek(&self) -> Option<&'a Tok> {
        self.t.get(self.i)
    }
    fn bump(&mut self) -> Option<&'a Tok> {
        let t = self.t.get(self.i);
        if t.is_some() {
            self.i += 1;
        }
        t
    }
    fn at_separator(&self) -> bool {
        matches!(self.peek(), Some(Tok::Semi) | Some(Tok::Amp) | Some(Tok::Newline) | Some(Tok::AndIf) | Some(Tok::OrIf))
    }
    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Some(Tok::Newline)) {
            self.i += 1;
        }
    }
}

/// Parse a token stream into a [`Script`].
pub fn parse(toks: &[Tok]) -> Result<Script, ParseError> {
    let mut p = P { t: toks, i: 0 };
    let s = parse_script(&mut p, 0, &[])?;
    if p.i < p.t.len() {
        return Err(ParseError::new("unexpected trailing token"));
    }
    Ok(s)
}

/// Parse commands until end of input or one of `stop`.
fn parse_script(p: &mut P, depth: u32, stop: &[Tok]) -> Result<Script, ParseError> {
    if depth > MAX_NEST_DEPTH {
        return Err(ParseError::new("nesting too deep"));
    }
    let mut script = Script::default();
    loop {
        p.skip_newlines();
        match p.peek() {
            None => break,
            Some(t) if stop.contains(t) => break,
            _ => {}
        }
        let pipe = parse_pipeline(p, depth)?;
        if pipe.cmds.is_empty() {
            return Err(ParseError::new("empty command"));
        }
        script.pipelines.push(pipe);
        if p.at_separator() {
            p.bump();
            continue;
        }
        match p.peek() {
            None => break,
            Some(t) if stop.contains(t) => break,
            Some(_) => return Err(ParseError::new("unexpected token after command")),
        }
    }
    Ok(script)
}

fn parse_pipeline(p: &mut P, depth: u32) -> Result<Pipeline, ParseError> {
    let mut pl = Pipeline::default();
    loop {
        let c = parse_command(p, depth)?;
        match c {
            Some(c) => pl.cmds.push(c),
            None => {
                // An empty stage is an error only when a pipe demanded one.
                if !pl.cmds.is_empty() {
                    return Err(ParseError::new("empty pipeline stage"));
                }
                return Ok(pl);
            }
        }
        if matches!(p.peek(), Some(Tok::Pipe)) {
            p.bump();
            p.skip_newlines();
            continue;
        }
        return Ok(pl);
    }
}

fn parse_command(p: &mut P, depth: u32) -> Result<Option<Cmd>, ParseError> {
    match p.peek() {
        Some(Tok::LParen) => {
            p.bump();
            let inner = parse_script(p, depth + 1, &[Tok::RParen])?;
            if !matches!(p.bump(), Some(Tok::RParen)) {
                return Err(ParseError::new("unclosed subshell"));
            }
            Ok(Some(Cmd::Nested(inner)))
        }
        Some(Tok::LBrace) => {
            p.bump();
            let inner = parse_script(p, depth + 1, &[Tok::RBrace])?;
            if !matches!(p.bump(), Some(Tok::RBrace)) {
                return Err(ParseError::new("unclosed brace group"));
            }
            Ok(Some(Cmd::Nested(inner)))
        }
        _ => parse_simple(p, depth),
    }
}

/// True when a literal word is a shell reserved word, which we skip so that
/// `if rm -rf /; then ...` still surfaces the `rm` command.
fn is_reserved(w: &Word) -> bool {
    match w.literal() {
        Some(l) => crate::tables::is_reserved_word(&l),
        None => false,
    }
}

/// Split `NAME=value` into its parts when the word begins with an assignment.
fn try_split_assignment(w: &Word) -> Option<(String, Word)> {
    use crate::lexer::Segment;
    if w.segs.is_empty() {
        return None;
    }
    let first = match &w.segs[0] {
        Segment::Lit(t) => t,
        _ => return None,
    };
    let eq = first.find('=')?;
    let name = &first[..eq];
    if name.is_empty() {
        return None;
    }
    let mut chars = name.chars();
    let c0 = chars.next()?;
    if !(c0.is_ascii_alphabetic() || c0 == '_') {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let mut segs: Vec<Segment> = Vec::new();
    let rest = &first[eq + 1..];
    if !rest.is_empty() {
        segs.push(Segment::Lit(rest.to_string()));
    }
    segs.extend(w.segs[1..].iter().cloned());
    Some((name.to_string(), Word { segs, quoted: w.quoted }))
}

fn parse_simple(p: &mut P, depth: u32) -> Result<Option<Cmd>, ParseError> {
    let mut cmd = SimpleCmd::default();
    let mut saw_any = false;

    loop {
        match p.peek() {
            Some(Tok::Word(w)) => {
                // Function definition: NAME ( ) body
                if cmd.words.is_empty()
                    && matches!(p.t.get(p.i + 1), Some(Tok::LParen))
                    && matches!(p.t.get(p.i + 2), Some(Tok::RParen))
                {
                    let name = match w.literal() {
                        Some(l) => l,
                        None => return Err(ParseError::new("dynamic function name")),
                    };
                    p.i += 3;
                    p.skip_newlines();
                    let body = match parse_command(p, depth + 1)? {
                        Some(Cmd::Nested(s)) => s,
                        Some(other) => Script { pipelines: vec![Pipeline { cmds: vec![other] }] },
                        None => return Err(ParseError::new("function without a body")),
                    };
                    return Ok(Some(Cmd::FuncDef { name, body }));
                }

                if cmd.words.is_empty() && is_reserved(w) {
                    p.bump();
                    saw_any = true;
                    continue;
                }

                if cmd.words.is_empty() {
                    if let Some((name, value)) = try_split_assignment(w) {
                        cmd.assigns.push((name, value));
                        p.bump();
                        saw_any = true;
                        continue;
                    }
                }

                cmd.words.push(w.clone());
                p.bump();
                saw_any = true;
            }
            Some(Tok::Redir { fd, op }) => {
                let (fd, op) = (*fd, *op);
                p.bump();
                let target = match p.peek() {
                    Some(Tok::Word(w)) => {
                        let w = w.clone();
                        p.bump();
                        w
                    }
                    _ => return Err(ParseError::new("redirection without a target")),
                };
                cmd.redirects.push(Redirect { fd, op, target });
                saw_any = true;
            }
            _ => break,
        }
    }

    if !saw_any {
        return Ok(None);
    }
    if cmd.is_empty() {
        // Only reserved words were consumed, e.g. a bare `fi`.
        return Ok(Some(Cmd::Simple(cmd)));
    }
    Ok(Some(Cmd::Simple(cmd)))
}

/// Convenience: tokenize and parse in one step.
pub fn parse_source(src: &str) -> Result<Script, ParseError> {
    let toks = crate::lexer::tokenize(src).map_err(|e| ParseError { message: e.message })?;
    parse(&toks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_cmd_name(s: &Script) -> String {
        match &s.pipelines[0].cmds[0] {
            Cmd::Simple(c) => c.words[0].literal().unwrap(),
            _ => panic!("expected a simple command"),
        }
    }

    #[test]
    fn parses_a_simple_command() {
        let s = parse_source("ls -la").unwrap();
        assert_eq!(s.pipelines.len(), 1);
        assert_eq!(first_cmd_name(&s), "ls");
    }

    #[test]
    fn separators_split_pipelines() {
        let s = parse_source("ls; rm -rf /").unwrap();
        assert_eq!(s.pipelines.len(), 2);
        let s = parse_source("ls\nrm -rf /").unwrap();
        assert_eq!(s.pipelines.len(), 2);
        let s = parse_source("true && rm -rf /").unwrap();
        assert_eq!(s.pipelines.len(), 2);
    }

    #[test]
    fn pipeline_stages_are_grouped() {
        let s = parse_source("curl http://x | sh").unwrap();
        assert_eq!(s.pipelines.len(), 1);
        assert_eq!(s.pipelines[0].cmds.len(), 2);
    }

    #[test]
    fn assignments_are_separated_from_words() {
        let s = parse_source("R=rm; $R -rf /").unwrap();
        match &s.pipelines[0].cmds[0] {
            Cmd::Simple(c) => {
                assert_eq!(c.assigns.len(), 1);
                assert_eq!(c.assigns[0].0, "R");
                assert_eq!(c.assigns[0].1.literal().unwrap(), "rm");
                assert!(c.words.is_empty());
            }
            _ => panic!("expected simple"),
        }
    }

    #[test]
    fn subshell_and_group_nest() {
        let s = parse_source("( rm -rf / )").unwrap();
        assert!(matches!(s.pipelines[0].cmds[0], Cmd::Nested(_)));
        let s = parse_source("{ rm -rf / ; }").unwrap();
        assert!(matches!(s.pipelines[0].cmds[0], Cmd::Nested(_)));
    }

    #[test]
    fn function_definition_captures_body() {
        let s = parse_source(":(){ :|:& };:").unwrap();
        match &s.pipelines[0].cmds[0] {
            Cmd::FuncDef { name, body } => {
                assert_eq!(name, ":");
                assert_eq!(body.pipelines[0].cmds.len(), 2);
            }
            other => panic!("expected FuncDef, got {other:?}"),
        }
    }

    #[test]
    fn redirects_attach_to_their_command() {
        let s = parse_source("echo hi > /dev/sda").unwrap();
        match &s.pipelines[0].cmds[0] {
            Cmd::Simple(c) => {
                assert_eq!(c.redirects.len(), 1);
                assert_eq!(c.redirects[0].target.literal().unwrap(), "/dev/sda");
            }
            _ => panic!("expected simple"),
        }
    }

    #[test]
    fn reserved_words_do_not_hide_commands() {
        let s = parse_source("if rm -rf /; then ls; fi").unwrap();
        assert_eq!(first_cmd_name(&s), "rm");
    }

    #[test]
    fn empty_and_malformed_inputs() {
        assert_eq!(parse_source("").unwrap().pipelines.len(), 0);
        assert_eq!(parse_source("   ").unwrap().pipelines.len(), 0);
        assert_eq!(parse_source("# comment").unwrap().pipelines.len(), 0);
        assert!(parse_source(";;;").is_err());
        assert!(parse_source("ls |").is_err());
        assert!(parse_source("( ls").is_err());
        assert!(parse_source("cat >").is_err());
    }

    #[test]
    fn trailing_separator_is_fine() {
        assert_eq!(parse_source("ls;").unwrap().pipelines.len(), 1);
        assert_eq!(parse_source("ls &").unwrap().pipelines.len(), 1);
    }
}
