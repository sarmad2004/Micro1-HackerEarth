//! Resource bounds from SPEC.md section 7. A hostile input must never be able
//! to exhaust the gate, so every unbounded loop in the analyzer is capped here.

/// Longest accepted input line, in bytes.
pub const MAX_LINE_BYTES: usize = 1 << 20; // 1 MiB
/// Longest command we will attempt to analyze, in bytes.
pub const MAX_CMD_BYTES: usize = 256 * 1024;
/// Maximum nesting of command substitution, `-c` payloads and base64 decodes.
pub const MAX_RECURSION_DEPTH: u32 = 8;
/// Maximum tokens produced for one command.
pub const MAX_TOKENS: usize = 100_000;
/// Maximum plaintext size produced by a base64 decode.
pub const MAX_B64_OUTPUT: usize = 64 * 1024;
/// Maximum nesting of `(` / `{` groups the parser will descend into.
pub const MAX_NEST_DEPTH: u32 = 64;
