# Parser intermediate representation

The scanner parses supported source into a framework-neutral `ParsedFile` before applying
cross-cutting checks. The contract lives in `packages/parsers` and never executes target code.

## Analysis modes

- `ast`: JavaScript and TypeScript use the TypeScript Compiler API. Python uses the pure-TypeScript
  parser in `packages/parsers/src/python.ts`, which tokenizes indentation-based blocks and f-strings
  and parses into the same call/import/operation/flow IR. Calls, imports, environment reads,
  capabilities, and same-file secret-to-network flows are represented structurally.
- `structured`: JSON, JSONL, YAML, TOML, and Markdown produce typed documents, MCP tool definitions,
  front matter, links, code blocks, commands, hidden instructions, and parse diagnostics.
- `conservative`: POSIX shell and PowerShell currently emit token-based operations plus an explicit
  `CONSERVATIVE_ANALYSIS` warning. The scanner creates `AS-SC-901`; it does not claim that AST-level
  analysis completed.

## Main nodes

`OperationNode` describes a permission-relevant action, including kind, symbol, scope, and source
location. `CallNode` and `ImportNode` preserve code structure. `ToolDefinition` normalizes MCP-like
tool declarations. `SecretFlow` connects an environment source to a network sink and records the
identifiers through which the value moved.

Fatal diagnostics generate `AS-SC-900` and make a scan partial. Python parse failures use the stable
`PY_SYNTAX` code and still return the partial IR collected before the failure. Conservative fallback
generates `AS-SC-901` without marking the file as a parser crash. Rule regexes remain a fallback for
formats without AST analysis and for content-level indicators such as hidden instructions.

## Byte-order marks

`normalizeByteOrderMark` replaces a single leading BOM with a space before analysis. Replacing rather
than removing keeps every reported index, line, and column aligned with the original file. Only the
first character is affected, so an invisible character anywhere else still reaches the
hidden-instruction detectors. The scanner applies the same normalization before rule matching so a
legal BOM cannot raise a false `AS-SC-026`, while component hashes still cover the real file bytes.

## Failure containment

`parseSource` never throws. Any parser exception is converted into an `error` diagnostic:
`PARSER_RESOURCE_EXHAUSTED` when a `RangeError` indicates stack exhaustion on pathologically nested
input, otherwise `PARSER_FAILED`. Both become `AS-SC-900` and mark the scan partial, so a hostile file
that defeats a parser can never produce a falsely clean result.

This boundary is enforced by `packages/parsers/src/fuzz.test.ts`, a deterministic seeded fuzzer that
mutates a multi-language corpus and asserts the parser never throws, never reports a source location
outside the input, and always labels degraded analysis. Failures print the seed, iteration, and input
so a case can be replayed and promoted to a regression test.

## Current data-flow boundary

The v0.2 analysis is intra-file and lexical. For JavaScript/TypeScript it follows variable
declarations, assignments, nested call arguments, object literals, and shorthand properties. For
Python it follows the same shapes plus imports (`import os`, `from os import environ`, aliases), dict
and list literals, f-string interpolation, and receiver chains such as `open(...).write(...)`. It
does not yet resolve callbacks, class fields, aliases across modules, or runtime reflection. Evidence
metadata states `ast-data-flow` when the stronger path is available.
