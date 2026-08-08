import type {
  CallNode, ImportNode, OperationKind, OperationNode, ParseDiagnostic, ParsedFile, SecretFlow,
  SourceLocation
} from './index.js';

/**
 * Pure-TypeScript Python parser producing the common AgentShield intermediate representation.
 *
 * Python is indentation-based, so this module implements its own tokenizer (INDENT/DEDENT, logical
 * lines, line continuation, strings including f-strings and triple quotes) followed by a recursive
 * descent parser. The analyzer mirrors the JavaScript/TypeScript AST path: it tracks intra-file
 * environment-to-network data flow, records calls, imports, and permission-relevant operations, and
 * never executes the target.
 *
 * The parser never throws to its caller. Structural problems produce a stable `error` diagnostic so
 * the scanner raises AS-SC-900 instead of silently under-reporting; expression nesting is depth
 * limited so hostile input cannot exhaust the stack inside this module.
 */

const PY_KEYWORDS = new Set([
  'False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await', 'break', 'class', 'continue',
  'def', 'del', 'elif', 'else', 'except', 'finally', 'for', 'from', 'global', 'if', 'import', 'in',
  'is', 'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return', 'try', 'while', 'with',
  'yield', 'match', 'case'
]);

const MULTI_CHAR_OPS = [
  '**=', '//=', '>>=', '<<=', '==', '!=', '<=', '>=', ':=', '->', '+=', '-=', '*=', '/=', '%=',
  '&=', '|=', '^=', '@=', '...', '**', '//', '<<', '>>'
];
const AUG_ASSIGN_OPS = new Set(['+=', '-=', '*=', '/=', '//=', '%=', '**=', '&=', '|=', '^=', '<<=', '>>=', '@=']);
const SINGLE_CHAR_OPS = new Set('()[]{}.,:;+-*/%@&|^~<>=!');
const OPEN_BRACKETS = new Set(['(', '[', '{']);
const CLOSE_BRACKETS = new Set([')', ']', '}']);

interface PyToken {
  kind: 'name' | 'number' | 'string' | 'op' | 'newline' | 'indent' | 'dedent' | 'end';
  text: string;
  index: number;
  end: number;
  value?: string;
  fstring?: boolean;
  fstringNames?: string[];
  fstringExpressions?: string[];
}

interface PyExpr {
  kind: string;
  index: number;
  end: number;
  [key: string]: unknown;
}

interface PyArg {
  expr: PyExpr;
  keyword?: string;
}

interface PyImportName {
  dotted: string;
  alias?: string;
}

interface PyStmt {
  kind: 'expr' | 'assign' | 'augassign' | 'import' | 'fromimport' | 'simple' | 'block';
  index: number;
  end: number;
  body?: PyStmt[];
  targets?: PyExpr[];
  value?: PyExpr;
  target?: PyExpr;
  op?: string;
  names?: PyImportName[];
  module?: string;
}

interface PyTaint {
  sourceName: string;
  source: SourceLocation;
  through: string[];
}

interface PyContext {
  content: string;
  imports: ImportNode[];
  calls: CallNode[];
  operations: OperationNode[];
  flows: SecretFlow[];
  taints: Map<string, PyTaint>;
  moduleAliases: Map<string, string>;
  fromAliases: Map<string, string>;
}

class PyParseError extends Error {
  constructor(
    message: string,
    public readonly index: number
  ) {
    super(message);
  }
}

function locationAt(content: string, index: number): SourceLocation {
  const safeIndex = Math.max(0, Math.min(index, content.length));
  const before = content.slice(0, safeIndex);
  const line = before.split('\n').length;
  return { index: safeIndex, line, column: safeIndex - before.lastIndexOf('\n') };
}

function isNameStart(ch: string): boolean {
  return /[A-Za-z_]/.test(ch) || ch.charCodeAt(0) > 127;
}

function isNameChar(ch: string): boolean {
  return /[A-Za-z0-9_]/.test(ch) || ch.charCodeAt(0) > 127;
}

function isDigit(ch: string): boolean {
  return ch >= '0' && ch <= '9';
}

function extractFStringParts(raw: string): { names: string[]; expressions: string[] } {
  const names: string[] = [];
  const expressions: string[] = [];
  let depth = 0;
  let expr = '';
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i]!;
    if (c === '{') {
      if (raw[i + 1] === '{') { i++; continue; }
      depth++;
      if (depth === 1) expr = '';
      else expr += c;
      continue;
    }
    if (c === '}') {
      if (raw[i + 1] === '}') { i++; continue; }
      depth--;
      if (depth === 0) {
        expressions.push(expr);
        for (const name of extractIdentifiers(expr)) if (!names.includes(name)) names.push(name);
      } else {
        expr += c;
      }
      continue;
    }
    if (depth > 0) expr += c;
  }
  return { names, expressions };
}

function extractIdentifiers(text: string): string[] {
  const out: string[] = [];
  const cleaned = text.replace(/['"][^'"]*['"]/g, ' ');
  const re = /[A-Za-z_][A-Za-z0-9_]*/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(cleaned)) !== null) {
    if (!PY_KEYWORDS.has(match[0]) && !out.includes(match[0])) out.push(match[0]);
  }
  return out;
}

interface LexStringResult {
  token: PyToken;
  end: number;
}

function lexString(content: string, i: number, diagnostics: ParseDiagnostic[]): LexStringResult | undefined {
  const n = content.length;
  let j = i;
  let prefix = '';
  if (j < n && /[rRbBuUfF]/.test(content[j]!)) {
    const two = content.slice(j, j + 2);
    if (/^(rb|br|rf|fr|Rb|bR|rF|fR|RB|BR|RF|FR)$/.test(two)) {
      prefix = two;
      j += 2;
    } else {
      prefix = content[j]!;
      j += 1;
    }
    if (j >= n || (content[j] !== "'" && content[j] !== '"')) return undefined;
  }
  const quote = content[j];
  if (quote !== "'" && quote !== '"') return undefined;
  const triple = content[j + 1] === quote && content[j + 2] === quote;
  const quoteLen = triple ? 3 : 1;
  let k = j + quoteLen;
  let raw = '';
  let closed = false;
  while (k < n) {
    const c = content[k]!;
    if (c === '\\') {
      if (k + 1 >= n) {
        k++;
        break;
      }
      raw += content[k + 1]!;
      k += 2;
      continue;
    }
    if (triple) {
      if (content.slice(k, k + 3) === quote.repeat(3)) {
        closed = true;
        k += 3;
        break;
      }
      raw += c;
      k++;
    } else {
      if (c === quote) {
        closed = true;
        k++;
        break;
      }
      if (c === '\n' || c === '\r') break;
      raw += c;
      k++;
    }
  }
  if (!closed) {
    let e = i;
    while (e < n && content[e] !== '\n' && content[e] !== '\r') e++;
    diagnostics.push({
      code: 'PY_STRING',
      message: 'Unterminated string literal',
      severity: 'error',
      location: locationAt(content, i)
    });
    return { token: { kind: 'string', text: content.slice(i, e), index: i, end: e, value: raw }, end: e };
  }
  const isF = prefix.toLowerCase().includes('f');
  const parts = isF ? extractFStringParts(raw) : { names: [] as string[], expressions: [] as string[] };
  return {
    token: {
      kind: 'string',
      text: content.slice(i, k),
      index: i,
      end: k,
      value: raw,
      fstring: isF,
      fstringNames: parts.names,
      fstringExpressions: parts.expressions
    },
    end: k
  };
}

function lexNumber(content: string, i: number): { end: number; text: string } {
  const n = content.length;
  let j = i;
  const c0 = content[j]!;
  if (c0 === '0' && (content[j + 1] === 'x' || content[j + 1] === 'X' || content[j + 1] === 'b' || content[j + 1] === 'B' || content[j + 1] === 'o' || content[j + 1] === 'O')) {
    j += 2;
    while (j < n && /[0-9a-fA-F_]/.test(content[j]!)) j++;
  } else {
    while (j < n && /[0-9_]/.test(content[j]!)) j++;
    if (content[j] === '.') {
      j++;
      while (j < n && /[0-9_]/.test(content[j]!)) j++;
    }
    if (content[j] === 'e' || content[j] === 'E') {
      j++;
      if (content[j] === '+' || content[j] === '-') j++;
      while (j < n && /[0-9_]/.test(content[j]!)) j++;
    }
  }
  if (content[j] === 'j' || content[j] === 'J') j++;
  return { end: j, text: content.slice(i, j) };
}

function tokenizePython(content: string): { tokens: PyToken[]; diagnostics: ParseDiagnostic[] } {
  const tokens: PyToken[] = [];
  const diagnostics: ParseDiagnostic[] = [];
  const indentStack: number[] = [0];
  const n = content.length;
  let i = 0;
  let parenDepth = 0;
  let lineStart = true;
  let lineHasToken = false;
  let continued = false;

  while (i < n) {
    const ch = content[i]!;

    if (ch === '\n' || ch === '\r') {
      const nl = ch === '\r' && content[i + 1] === '\n' ? 2 : 1;
      i += nl;
      if (parenDepth === 0 && !continued) {
        if (lineHasToken) {
          tokens.push({ kind: 'newline', text: '\n', index: i - nl, end: i });
          lineHasToken = false;
        }
        lineStart = true;
      }
      continued = false;
      continue;
    }

    if (lineStart && parenDepth === 0) {
      if (continued) {
        while (i < n && (content[i] === ' ' || content[i] === '\t')) i++;
        continued = false;
        lineStart = false;
        continue;
      }
      let col = 0;
      let j = i;
      while (j < n && (content[j] === ' ' || content[j] === '\t')) {
        col += content[j] === '\t' ? 8 : 1;
        j++;
      }
      let k = j;
      while (k < n && content[k] !== '\n' && content[k] !== '\r' && content[k] !== '#') k++;
      if (content.slice(j, k).trim() === '') {
        i = j;
        while (i < n && content[i] !== '\n' && content[i] !== '\r') i++;
        continue;
      }
      const top = indentStack[indentStack.length - 1]!;
      if (col > top) {
        indentStack.push(col);
        tokens.push({ kind: 'indent', text: '', index: j, end: j });
      } else if (col < top) {
        while (indentStack.length > 1 && col < indentStack[indentStack.length - 1]!) {
          indentStack.pop();
          tokens.push({ kind: 'dedent', text: '', index: j, end: j });
        }
        if (indentStack[indentStack.length - 1] !== col) {
          diagnostics.push({
            code: 'PY_INDENT',
            message: `Inconsistent indentation (expected column ${indentStack[indentStack.length - 1]}, found ${col})`,
            severity: 'error',
            location: locationAt(content, j)
          });
          indentStack.push(col);
        }
      }
      i = j;
      lineStart = false;
      continue;
    }

    if (ch === ' ' || ch === '\t') {
      i++;
      continue;
    }
    if (ch === '#') {
      while (i < n && content[i] !== '\n' && content[i] !== '\r') i++;
      continue;
    }
    if (ch === '\\') {
      if (content[i + 1] === '\n' || (content[i + 1] === '\r' && content[i + 2] === '\n')) {
        i += content[i + 1] === '\r' ? 3 : 2;
        continued = true;
        lineStart = true;
        continue;
      }
      tokens.push({ kind: 'op', text: '\\', index: i, end: i + 1 });
      i++;
      lineHasToken = true;
      continue;
    }

    if (ch === "'" || ch === '"' || /[rRbBuUfF]/.test(ch)) {
      const str = lexString(content, i, diagnostics);
      if (str) {
        tokens.push(str.token);
        i = str.end;
        lineHasToken = true;
        continue;
      }
    }

    if (isNameStart(ch)) {
      let j = i + 1;
      while (j < n && isNameChar(content[j]!)) j++;
      tokens.push({ kind: 'name', text: content.slice(i, j), index: i, end: j });
      i = j;
      lineHasToken = true;
      continue;
    }

    if (isDigit(ch) || (ch === '.' && isDigit(content[i + 1] ?? ''))) {
      const number = lexNumber(content, i);
      tokens.push({ kind: 'number', text: number.text, index: i, end: number.end });
      i = number.end;
      lineHasToken = true;
      continue;
    }

    let op = '';
    for (const candidate of MULTI_CHAR_OPS) {
      if (content.startsWith(candidate, i)) {
        op = candidate;
        break;
      }
    }
    if (!op && SINGLE_CHAR_OPS.has(ch)) op = ch;
    if (!op) {
      tokens.push({ kind: 'op', text: ch, index: i, end: i + 1 });
      i++;
      lineHasToken = true;
      continue;
    }
    if (OPEN_BRACKETS.has(op)) parenDepth++;
    else if (CLOSE_BRACKETS.has(op)) parenDepth = Math.max(0, parenDepth - 1);
    tokens.push({ kind: 'op', text: op, index: i, end: i + op.length });
    i += op.length;
    lineHasToken = true;
  }

  while (indentStack.length > 1) {
    indentStack.pop();
    tokens.push({ kind: 'dedent', text: '', index: n, end: n });
  }
  tokens.push({ kind: 'end', text: '', index: n, end: n });
  return { tokens, diagnostics };
}

const MAX_EXPRESSION_DEPTH = 400;

class PyParser {
  private pos = 0;
  private depth = 0;

  constructor(
    private readonly tokens: PyToken[],
    private readonly content: string
  ) {}

  private peek(offset = 0): PyToken {
    return this.tokens[Math.min(this.pos + offset, this.tokens.length - 1)]!;
  }

  private next(): PyToken {
    const token = this.peek();
    if (token.kind !== 'end') this.pos++;
    return token;
  }

  private isOp(text: string, offset = 0): boolean {
    const token = this.peek(offset);
    return token.kind === 'op' && token.text === text;
  }

  private isName(text: string, offset = 0): boolean {
    const token = this.peek(offset);
    return token.kind === 'name' && token.text === text;
  }

  private atLineEnd(): boolean {
    const token = this.peek();
    return (
      token.kind === 'newline' ||
      token.kind === 'end' ||
      token.kind === 'dedent' ||
      (token.kind === 'op' && [')', ']', '}', ';'].includes(token.text))
    );
  }

  private expectOp(text: string): PyToken {
    if (!this.isOp(text)) throw new PyParseError(`Expected '${text}'`, this.peek().index);
    return this.next();
  }

  private enterDepth(): void {
    if (++this.depth > MAX_EXPRESSION_DEPTH) {
      throw new PyParseError('Expression nesting is too deep', this.peek().index);
    }
  }

  private exitDepth(): void {
    this.depth--;
  }

  parseModule(): PyStmt[] {
    const body: PyStmt[] = [];
    while (this.peek().kind !== 'end') {
      const token = this.peek();
      if (token.kind === 'newline' || token.kind === 'indent' || token.kind === 'dedent') {
        this.next();
        continue;
      }
      const stmt = this.parseStatement();
      if (stmt) body.push(stmt);
    }
    return body;
  }

  private parseStatement(): PyStmt | null {
    if (this.isName('match')) return this.parseMatch();
    if (this.isName('case')) return this.parseCase();
    if (this.isName('if')) return this.parseIf();
    if (this.isName('while')) return this.parseWhile();
    if (this.isName('for')) return this.parseFor();
    if (this.isName('def')) return this.parseDef();
    if (this.isName('class')) return this.parseClass();
    if (this.isName('with')) return this.parseWith();
    if (this.isName('try')) return this.parseTry();
    if (this.isName('async')) {
      this.next();
      if (this.isName('def')) return this.parseDef();
      if (this.isName('for')) return this.parseFor();
      if (this.isName('with')) return this.parseWith();
      throw new PyParseError('Expected def/for/with after async', this.peek().index);
    }
    if (this.isOp('@')) {
      const decorators: PyExpr[] = [];
      while (this.isOp('@')) {
        this.next();
        decorators.push(this.parsePostfix());
        if (this.peek().kind === 'newline') this.next();
      }
      const stmt = this.parseStatement();
      if (stmt && stmt.kind === 'block' && stmt.body) {
        const wrapped: PyStmt[] = decorators.map((expr) => ({
          kind: 'expr' as const, value: expr, index: expr.index, end: expr.end
        }));
        return { kind: 'block', body: [...wrapped, ...stmt.body], index: stmt.index, end: stmt.end };
      }
      return stmt;
    }
    return this.parseSimpleStatement();
  }

  private parseSuite(): PyStmt[] {
    this.expectOp(':');
    if (this.peek().kind === 'newline') {
      this.next();
      if (this.peek().kind !== 'indent') throw new PyParseError('Expected an indented block', this.peek().index);
      this.next();
      const body: PyStmt[] = [];
      while (this.peek().kind !== 'dedent' && this.peek().kind !== 'end') {
        if (this.peek().kind === 'newline') {
          this.next();
          continue;
        }
        const stmt = this.parseStatement();
        if (stmt) body.push(stmt);
      }
      if (this.peek().kind === 'dedent') this.next();
      return body;
    }
    const stmt = this.parseSimpleStatement();
    return stmt ? [stmt] : [];
  }

  private parseBlock(header: PyExpr[], body: PyStmt[], index: number): PyStmt {
    const wrapped: PyStmt[] = header.map((expr) => ({
      kind: 'expr' as const, value: expr, index: expr.index, end: expr.end
    }));
    return {
      kind: 'block',
      body: [...wrapped, ...body],
      index,
      end: body.length ? body[body.length - 1]!.end : (header[header.length - 1]?.end ?? index)
    };
  }

  private parseMatch(): PyStmt {
    const start = this.next().index;
    const subject = this.parseExpression();
    const body = this.parseSuite();
    return this.parseBlock([subject], body, start);
  }

  private parseCase(): PyStmt {
    const start = this.next().index;
    let depth = 0;
    while (this.peek().kind !== 'end') {
      const token = this.peek();
      if (token.kind === 'op' && OPEN_BRACKETS.has(token.text)) depth++;
      else if (token.kind === 'op' && CLOSE_BRACKETS.has(token.text)) depth = Math.max(0, depth - 1);
      else if (token.kind === 'op' && token.text === ':' && depth === 0) break;
      this.next();
    }
    const body = this.parseSuite();
    return this.parseBlock([], body, start);
  }

  private parseIf(): PyStmt {
    const start = this.next().index;
    const test = this.parseExpression();
    const body = this.parseSuite();
    const statements: PyStmt[] = [{ kind: 'expr', value: test, index: test.index, end: test.end }, ...body];
    while (this.isName('elif')) {
      this.next();
      const elifTest = this.parseExpression();
      const elifBody = this.parseSuite();
      statements.push(
        { kind: 'expr', value: elifTest, index: elifTest.index, end: elifTest.end },
        ...elifBody
      );
    }
    if (this.isName('else')) {
      this.next();
      statements.push(...this.parseSuite());
    }
    return { kind: 'block', body: statements, index: start, end: statements[statements.length - 1]!.end };
  }

  private parseWhile(): PyStmt {
    const start = this.next().index;
    const test = this.parseExpression();
    const body = this.parseSuite();
    const statements: PyStmt[] = [{ kind: 'expr', value: test, index: test.index, end: test.end }, ...body];
    if (this.isName('else')) {
      this.next();
      statements.push(...this.parseSuite());
    }
    return { kind: 'block', body: statements, index: start, end: statements[statements.length - 1]!.end };
  }

  private skipToIn(): void {
    let depth = 0;
    while (this.peek().kind !== 'end') {
      const token = this.peek();
      if (token.kind === 'op' && OPEN_BRACKETS.has(token.text)) depth++;
      else if (token.kind === 'op' && CLOSE_BRACKETS.has(token.text)) depth = Math.max(0, depth - 1);
      else if (token.kind === 'name' && token.text === 'in' && depth === 0) return;
      this.next();
    }
  }

  private parseFor(): PyStmt {
    const start = this.next().index;
    this.skipToIn();
    if (!this.isName('in')) throw new PyParseError('Expected in in for statement', this.peek().index);
    this.next();
    const iterable = this.parseTestList();
    const body = this.parseSuite();
    const statements: PyStmt[] = [{ kind: 'expr', value: iterable, index: iterable.index, end: iterable.end }, ...body];
    if (this.isName('else')) {
      this.next();
      statements.push(...this.parseSuite());
    }
    return { kind: 'block', body: statements, index: start, end: statements[statements.length - 1]!.end };
  }

  private parseWith(): PyStmt {
    const start = this.next().index;
    const items: PyExpr[] = [];
    for (;;) {
      const expr = this.parseExpression();
      items.push(expr);
      if (this.isName('as')) {
        this.next();
        if (this.peek().kind === 'name') this.next();
      }
      if (this.isOp(',')) {
        this.next();
        continue;
      }
      break;
    }
    const body = this.parseSuite();
    return this.parseBlock(items, body, start);
  }

  private parseTry(): PyStmt {
    const start = this.next().index;
    const body = this.parseSuite();
    const statements: PyStmt[] = [...body];
    while (this.isName('except')) {
      this.next();
      if (!this.isOp(':')) {
        const excType = this.parseExpression();
        statements.push({ kind: 'expr', value: excType, index: excType.index, end: excType.end });
        if (this.isName('as')) {
          this.next();
          if (this.peek().kind === 'name') this.next();
        }
      }
      statements.push(...this.parseSuite());
    }
    if (this.isName('else')) {
      this.next();
      statements.push(...this.parseSuite());
    }
    if (this.isName('finally')) {
      this.next();
      statements.push(...this.parseSuite());
    }
    return { kind: 'block', body: statements, index: start, end: statements[statements.length - 1]!.end };
  }

  private parseDottedName(): string {
    let text = this.expectName().text;
    while (this.isOp('.')) {
      this.next();
      text += `.${this.expectName().text}`;
    }
    return text;
  }

  private expectName(): PyToken {
    const token = this.peek();
    if (token.kind !== 'name') throw new PyParseError('Expected a name', token.index);
    return this.next();
  }

  private parseDef(): PyStmt {
    const start = this.next().index;
    this.expectName();
    this.expectOp('(');
    const defaults: PyExpr[] = [];
    if (!this.isOp(')')) {
      for (;;) {
        if (this.isOp('*') || this.isOp('**') || this.isOp('/')) {
          this.next();
          continue;
        }
        if (this.peek().kind === 'name') {
          this.next();
          if (this.isOp(':')) {
            this.next();
            this.parseExpression();
          }
          if (this.isOp('=')) {
            this.next();
            defaults.push(this.parseExpression());
          }
        }
        if (this.isOp(',')) {
          this.next();
          if (this.isOp(')')) break;
          continue;
        }
        break;
      }
    }
    this.expectOp(')');
    if (this.isOp('->')) {
      this.next();
      this.parseExpression();
    }
    const body = this.parseSuite();
    return this.parseBlock(defaults, body, start);
  }

  private parseClass(): PyStmt {
    const start = this.next().index;
    this.expectName();
    const bases: PyExpr[] = [];
    if (this.isOp('(')) {
      this.next();
      while (!this.isOp(')')) {
        bases.push(this.parseExpression());
        if (this.isOp(',')) {
          this.next();
          continue;
        }
        break;
      }
      this.expectOp(')');
    }
    const body = this.parseSuite();
    return this.parseBlock(bases, body, start);
  }

  private parseSimpleStatement(): PyStmt | null {
    const statements: PyStmt[] = [];
    for (;;) {
      const stmt = this.parseSmallStatement();
      if (stmt) statements.push(stmt);
      if (this.isOp(';')) {
        this.next();
        continue;
      }
      break;
    }
    if (this.peek().kind === 'newline') this.next();
    if (statements.length === 1) return statements[0]!;
    if (statements.length === 0) return null;
    return {
      kind: 'block',
      body: statements,
      index: statements[0]!.index,
      end: statements[statements.length - 1]!.end
    };
  }

  private parseSmallStatement(): PyStmt | null {
    if (this.isName('import')) return this.parseImport();
    if (this.isName('from')) return this.parseFromImport();
    const token = this.peek();
    if (token.kind === 'name') {
      if (token.text === 'return' || token.text === 'yield' || token.text === 'raise') {
        this.next();
        if (this.isName('from')) this.next();
        if (this.atLineEnd()) return { kind: 'simple', index: token.index, end: token.end };
        const value = this.parseTestList();
        return { kind: 'expr', value, index: token.index, end: value.end };
      }
      if (token.text === 'pass' || token.text === 'break' || token.text === 'continue') {
        this.next();
        return { kind: 'simple', index: token.index, end: token.end };
      }
      if (token.text === 'global' || token.text === 'nonlocal') {
        this.next();
        this.parseDottedName();
        while (this.isOp(',')) {
          this.next();
          this.parseDottedName();
        }
        return { kind: 'simple', index: token.index, end: this.peek().index };
      }
      if (token.text === 'del') {
        this.next();
        this.parseExpression();
        while (this.isOp(',')) {
          this.next();
          this.parseExpression();
        }
        return { kind: 'simple', index: token.index, end: this.peek().index };
      }
      if (token.text === 'assert') {
        this.next();
        const value = this.parseExpression();
        if (this.isOp(',')) {
          this.next();
          this.parseExpression();
        }
        return { kind: 'expr', value, index: token.index, end: value.end };
      }
    }
    return this.parseExprStatement();
  }

  private parseImport(): PyStmt {
    const start = this.next().index;
    const names: PyImportName[] = [];
    for (;;) {
      const dotted = this.parseDottedName();
      let alias: string | undefined;
      if (this.isName('as')) {
        this.next();
        alias = this.expectName().text;
      }
      names.push({ dotted, alias });
      if (this.isOp(',')) {
        this.next();
        continue;
      }
      break;
    }
    return { kind: 'import', names, index: start, end: this.peek().index };
  }

  private parseFromImport(): PyStmt {
    const start = this.next().index;
    const module = this.parseDottedName();
    if (!this.isName('import')) throw new PyParseError('Expected import', this.peek().index);
    this.next();
    const names: PyImportName[] = [];
    if (this.isOp('*')) {
      this.next();
    } else if (this.isOp('(')) {
      this.next();
      while (!this.isOp(')')) {
        const name = this.expectName().text;
        let alias: string | undefined;
        if (this.isName('as')) {
          this.next();
          alias = this.expectName().text;
        }
        names.push({ dotted: name, alias });
        if (this.isOp(',')) {
          this.next();
          continue;
        }
        break;
      }
      this.expectOp(')');
    } else {
      for (;;) {
        const name = this.expectName().text;
        let alias: string | undefined;
        if (this.isName('as')) {
          this.next();
          alias = this.expectName().text;
        }
        names.push({ dotted: name, alias });
        if (this.isOp(',')) {
          this.next();
          continue;
        }
        break;
      }
    }
    return { kind: 'fromimport', module, names, index: start, end: this.peek().index };
  }

  private parseExprStatement(): PyStmt | null {
    const first = this.parseTestList();
    if (this.isOp('=')) {
      const targets: PyExpr[] = [first];
      while (this.isOp('=')) {
        this.next();
        targets.push(this.parseTestList());
      }
      const value = targets.pop()!;
      return { kind: 'assign', targets, value, index: first.index, end: value.end };
    }
    if (this.peek().kind === 'op' && AUG_ASSIGN_OPS.has(this.peek().text)) {
      const op = this.next().text;
      const value = this.parseTestList();
      return { kind: 'augassign', target: first, op, value, index: first.index, end: value.end };
    }
    return { kind: 'expr', value: first, index: first.index, end: first.end };
  }

  private parseTestList(): PyExpr {
    const first = this.parseExpression();
    if (!this.isOp(',')) return first;
    const items: PyExpr[] = [first];
    while (this.isOp(',')) {
      this.next();
      if (this.atLineEnd() || this.isOp(']') || this.isOp(')') || this.isOp('}')) break;
      items.push(this.parseExpression());
    }
    return { kind: 'tuple', items, index: first.index, end: items[items.length - 1]!.end };
  }

  private parseExpression(): PyExpr {
    if (this.isName('lambda')) {
      const start = this.next().index;
      while (!this.isOp(':')) {
        if (this.peek().kind === 'end' || this.peek().kind === 'newline') break;
        this.next();
      }
      if (this.isOp(':')) this.next();
      const body = this.parseExpression();
      return { kind: 'lambda', index: start, end: body.end };
    }
    let expr = this.parseOrTest();
    if (this.isOp(':=')) {
      this.next();
      const right = this.parseExpression();
      expr = { kind: 'binop', op: ':=', left: expr, right, index: expr.index, end: right.end };
    }
    if (this.isName('if')) {
      this.next();
      const test = this.parseOrTest();
      if (!this.isName('else')) throw new PyParseError('Expected else', this.peek().index);
      this.next();
      const orelse = this.parseExpression();
      return { kind: 'ifexp', test, body: expr, orelse, index: expr.index, end: orelse.end };
    }
    return expr;
  }

  private parseOrTest(): PyExpr {
    const first = this.parseAndTest();
    if (!this.isName('or')) return first;
    const values: PyExpr[] = [first];
    while (this.isName('or')) {
      this.next();
      values.push(this.parseAndTest());
    }
    return { kind: 'boolop', op: 'or', values, index: first.index, end: values[values.length - 1]!.end };
  }

  private parseAndTest(): PyExpr {
    const first = this.parseNotTest();
    if (!this.isName('and')) return first;
    const values: PyExpr[] = [first];
    while (this.isName('and')) {
      this.next();
      values.push(this.parseNotTest());
    }
    return { kind: 'boolop', op: 'and', values, index: first.index, end: values[values.length - 1]!.end };
  }

  private parseNotTest(): PyExpr {
    if (this.isName('not')) {
      const start = this.next().index;
      const operand = this.parseNotTest();
      return { kind: 'unary', op: 'not', operand, index: start, end: operand.end };
    }
    return this.parseComparison();
  }

  private parseComparison(): PyExpr {
    let left = this.parseBitOr();
    const ops: string[] = [];
    const comparators: PyExpr[] = [];
    for (;;) {
      const token = this.peek();
      let op: string | undefined;
      if (token.kind === 'op' && ['==', '!=', '<', '>', '<=', '>='].includes(token.text)) {
        op = token.text;
        this.next();
      } else if (token.kind === 'name' && token.text === 'in') {
        op = 'in';
        this.next();
      } else if (token.kind === 'name' && token.text === 'is') {
        op = 'is';
        this.next();
        if (this.isName('not')) {
          this.next();
          op = 'is not';
        }
      } else if (token.kind === 'name' && token.text === 'not' && this.isName('in', 1)) {
        op = 'not in';
        this.next();
        this.next();
      } else {
        break;
      }
      ops.push(op);
      comparators.push(this.parseBitOr());
    }
    if (!ops.length) return left;
    left = { kind: 'compare', left, ops, comparators, index: left.index, end: comparators[comparators.length - 1]!.end };
    return left;
  }

  private parseLeftAssoc(ops: string[], nextLevel: () => PyExpr): PyExpr {
    let left = nextLevel();
    for (;;) {
      const token = this.peek();
      if (token.kind !== 'op' || !ops.includes(token.text)) return left;
      this.next();
      const right = nextLevel();
      left = { kind: 'binop', op: token.text, left, right, index: left.index, end: right.end };
    }
  }

  private parseBitOr(): PyExpr {
    return this.parseLeftAssoc(['|'], () => this.parseBitXor());
  }
  private parseBitXor(): PyExpr {
    return this.parseLeftAssoc(['^'], () => this.parseBitAnd());
  }
  private parseBitAnd(): PyExpr {
    return this.parseLeftAssoc(['&'], () => this.parseShift());
  }
  private parseShift(): PyExpr {
    return this.parseLeftAssoc(['<<', '>>'], () => this.parseArith());
  }
  private parseArith(): PyExpr {
    return this.parseLeftAssoc(['+', '-'], () => this.parseTerm());
  }
  private parseTerm(): PyExpr {
    return this.parseLeftAssoc(['*', '/', '//', '%', '@'], () => this.parseFactor());
  }

  private parseFactor(): PyExpr {
    const token = this.peek();
    if (token.kind === 'op' && ['+', '-', '~'].includes(token.text)) {
      this.next();
      const operand = this.parseFactor();
      return { kind: 'unary', op: token.text, operand, index: token.index, end: operand.end };
    }
    return this.parsePower();
  }

  private parsePower(): PyExpr {
    const base = this.parsePostfix();
    if (this.isOp('**')) {
      this.next();
      const exponent = this.parseFactor();
      return { kind: 'binop', op: '**', left: base, right: exponent, index: base.index, end: exponent.end };
    }
    return base;
  }

  private parsePostfix(): PyExpr {
    this.enterDepth();
    try {
      let expr = this.parseAtom();
      for (;;) {
        if (this.isOp('(')) {
          this.next();
          const args = this.parseArgList();
          const close = this.expectOp(')');
          expr = { kind: 'call', callee: expr, args, index: expr.index, end: close.end };
          continue;
        }
        if (this.isOp('[')) {
          this.next();
          const indexExpr = this.parseIndex();
          const close = this.expectOp(']');
          expr = { kind: 'subscript', object: expr, indexExpr, index: expr.index, end: close.end };
          continue;
        }
        if (this.isOp('.') && this.peek(1).kind === 'name') {
          this.next();
          const name = this.next();
          expr = { kind: 'attr', object: expr, name: name.text, index: expr.index, end: name.end };
          continue;
        }
        break;
      }
      return expr;
    } finally {
      this.exitDepth();
    }
  }

  private parseArgList(): PyArg[] {
    const args: PyArg[] = [];
    if (this.isOp(')')) return args;
    for (;;) {
      if (this.isOp('*') || this.isOp('**')) {
        const star = this.next();
        const value = this.parseExpression();
        args.push({ expr: { kind: 'starred', value, index: star.index, end: value.end } });
      } else if (this.peek().kind === 'name' && this.isOp('=', 1)) {
        const name = this.next();
        this.next();
        const value = this.parseExpression();
        args.push({ expr: value, keyword: name.text });
      } else {
        args.push({ expr: this.parseExpression() });
      }
      if (this.isOp(',')) {
        this.next();
        if (this.isOp(')')) break;
        continue;
      }
      break;
    }
    return args;
  }

  private parseIndex(): PyExpr | null {
    if (this.isOp(':')) {
      this.parseSlice();
      return null;
    }
    const first = this.parseExpression();
    if (this.isOp(':')) {
      this.parseSlice();
      return null;
    }
    return first;
  }

  private parseSlice(): void {
    if (!this.isOp(']') && !this.isOp(':')) this.parseExpression();
    if (this.isOp(':')) {
      this.next();
      if (!this.isOp(']')) this.parseExpression();
    }
  }

  private parseAtom(): PyExpr {
    const token = this.peek();
    if (token.kind === 'name') {
      this.next();
      return { kind: 'name', name: token.text, index: token.index, end: token.end };
    }
    if (token.kind === 'number') {
      this.next();
      return { kind: 'num', text: token.text, index: token.index, end: token.end };
    }
    if (token.kind === 'string') {
      let value = token.value ?? '';
      let fstring = Boolean(token.fstring);
      const names = [...(token.fstringNames ?? [])];
      const expressions = [...(token.fstringExpressions ?? [])];
      let end = token.end;
      this.next();
      while (this.peek().kind === 'string') {
        const nextToken = this.next();
        value += nextToken.value ?? '';
        if (nextToken.fstring) fstring = true;
        if (nextToken.fstringNames) names.push(...nextToken.fstringNames);
        if (nextToken.fstringExpressions) expressions.push(...nextToken.fstringExpressions);
        end = nextToken.end;
      }
      return { kind: 'str', value, fstring, names, expressions, index: token.index, end };
    }
    if (this.isOp('(')) {
      const open = this.next();
    if (this.isOp(')')) {
      const close = this.next();
      void close;
      return { kind: 'tuple', items: [], index: open.index, end: close.end };
    }
      const first = this.parseExpression();
      if (this.isName('for')) this.skipComprehension();
      if (this.isOp(',')) {
        const items: PyExpr[] = [first];
        while (this.isOp(',')) {
          this.next();
          if (this.isOp(')')) break;
          items.push(this.parseExpression());
        }
        const close = this.expectOp(')');
        return { kind: 'tuple', items, index: open.index, end: close.end };
      }        this.expectOp(')');
      return first;
    }
    if (this.isOp('[')) {
      const open = this.next();
      if (this.isOp(']')) {
        const close = this.next();
        return { kind: 'list', items: [], index: open.index, end: close.end };
      }
      const first = this.parseExpression();
      if (this.isName('for')) this.skipComprehension();
      if (this.isOp(',')) {
        const items: PyExpr[] = [first];
        while (this.isOp(',')) {
          this.next();
          if (this.isOp(']')) break;
          items.push(this.parseExpression());
        }
        const close = this.expectOp(']');
        return { kind: 'list', items, index: open.index, end: close.end };
      }
      const close = this.expectOp(']');
      return { kind: 'list', items: [first], index: open.index, end: close.end };
    }
    if (this.isOp('{')) {
      const open = this.next();
      if (this.isOp('}')) {
        const close = this.next();
        return { kind: 'dict', items: [], index: open.index, end: close.end };
      }
      const first = this.parseExpression();
      if (this.isOp(':')) {
        this.next();
        const value = this.parseExpression();
        if (this.isName('for')) this.skipComprehension();
        const items: Array<{ key: PyExpr; value: PyExpr }> = [{ key: first, value }];
        while (this.isOp(',')) {
          this.next();
          if (this.isOp('}')) break;
          const key = this.parseExpression();
          this.expectOp(':');
          items.push({ key, value: this.parseExpression() });
        }
        const close = this.expectOp('}');
        return { kind: 'dict', items, index: open.index, end: close.end };
      }
      if (this.isName('for')) this.skipComprehension();
      const items: PyExpr[] = [first];
      while (this.isOp(',')) {
        this.next();
        if (this.isOp('}')) break;
        items.push(this.parseExpression());
      }
      const close = this.expectOp('}');
      return { kind: 'set', items, index: open.index, end: close.end };
    }
    if (this.isName('await')) {
      const start = this.next().index;
      const value = this.parsePostfix();
      return { kind: 'await', value, index: start, end: value.end };
    }
    throw new PyParseError(`Unexpected token ${JSON.stringify(token.text)}`, token.index);
  }

  private skipComprehension(): void {
    while (this.isName('for') || this.isName('if')) {
      if (this.isName('for')) {
        this.next();
        this.skipToIn();
        if (!this.isName('in')) throw new PyParseError('Expected in in comprehension', this.peek().index);
        this.next();
        this.parseOrTest();
      } else {
        this.next();
        this.parseOrTest();
      }
    }
  }
}

function sourceText(content: string, expr: PyExpr): string {
  return content.slice(expr.index, expr.end).trim().replaceAll(/\s+/g, ' ').slice(0, 200);
}

function calleeText(expr: PyExpr, ctx: PyContext): string {
  if (expr.kind === 'name') {
    return ctx.moduleAliases.get(String(expr.name)) ?? ctx.fromAliases.get(String(expr.name)) ?? String(expr.name);
  }
  if (expr.kind === 'attr') {
    const base = calleeText(expr.object as PyExpr, ctx);
    if (base.includes('[')) return base;
    return `${base}.${String(expr.name)}`;
  }
  if (expr.kind === 'subscript') {
    return `${calleeText(expr.object as PyExpr, ctx)}[]`;
  }
  return '?';
}

function stringLiteral(expr: PyExpr | null | undefined): string | undefined {
  if (!expr || expr.kind !== 'str') return;
  const value = String(expr.value ?? '');
  if (!value) return undefined;
  if (expr.fstring) {
    // Scope extraction still benefits from the literal URL; interpolation is replaced by a placeholder.
    return value.replace(/\{[^}]*\}/g, 'x');
  }
  return value;
}

function networkScope(value: string | undefined): string {
  if (!value) return 'unspecified';
  try {
    return new URL(value).host;
  } catch {
    return value === 'unspecified' ? value : `dynamic:${value.slice(0, 80)}`;
  }
}

function fileScope(value: string | undefined): string {
  if (!value) return 'unspecified';
  if (/^(?:\/|~|[A-Za-z]:\\)/.test(value) || /(?:HOME|homedir)/.test(value)) return 'broad';
  return value;
}

const NETWORK_MODULES = ['requests', 'httpx', 'urllib3', 'aiohttp', 'urllib.request', 'http.client', 'websocket'];

function isNetworkCallee(callee: string): boolean {
  return NETWORK_MODULES.some((module) => callee === module || callee.startsWith(`${module}.`));
}

function operationForCall(callee: string, expr: PyExpr, ctx: PyContext): OperationNode | undefined {
  const location = locationAt(ctx.content, expr.index);
  const first = (expr.args as PyArg[])[0]?.expr;
  const scopeText = stringLiteral(first);
  if (isNetworkCallee(callee)) {
    return { kind: 'network.connect', symbol: callee, scope: networkScope(scopeText), location };
  }
  if (/^subprocess\./.test(callee) || /^os\.(system|popen|spawn)/.test(callee) || /^pty\.spawn/.test(callee)) {
    return { kind: 'process.execute', symbol: callee, scope: scopeText ?? 'unspecified', location };
  }
  if (callee === 'open') {
    const modeExpr = (expr.args as PyArg[])[1]?.expr;
    const mode = stringLiteral(modeExpr) ?? '';
    const kind: OperationKind = /[wa+x]/.test(mode) ? 'filesystem.write' : 'filesystem.read';
    return { kind, symbol: 'open', scope: fileScope(scopeText), location };
  }
  if (/^os\.(remove|unlink|rmdir|removedirs)/.test(callee) || callee === 'shutil.rmtree') {
    return { kind: 'filesystem.delete', symbol: callee, scope: fileScope(scopeText), location };
  }
  if (/^os\.(makedirs|mkdir|write|rename)/.test(callee)) {
    return { kind: 'filesystem.write', symbol: callee, scope: fileScope(scopeText), location };
  }
  if (/^os\.(listdir|walk|readlink)/.test(callee) || /\.(read_text|read_bytes|readlines)$/.test(callee)) {
    return { kind: 'filesystem.read', symbol: callee, scope: fileScope(scopeText), location };
  }
  if (/\.(write_text|write_bytes)$/.test(callee)) {
    return { kind: 'filesystem.write', symbol: callee, scope: fileScope(scopeText), location };
  }
  if (/^(sqlite3|psycopg2|psycopg)\.connect/.test(callee) || /\.MongoClient$/.test(callee) ||
      /^redis\.(Redis|from_url|StrictRedis)/.test(callee) || callee === 'create_engine') {
    return { kind: 'database.connect', symbol: callee, scope: scopeText ?? 'unspecified', location };
  }
  if (/^(selenium|playwright)\./.test(callee) || /webdriver/.test(callee) ||
      /(?:sync_playwright|async_playwright)$/.test(callee)) {
    return { kind: 'browser.automate', symbol: callee, scope: 'unspecified', location };
  }
  if (/^(smtplib|sendgrid|slack_sdk)\./.test(callee) || /\.sendmail$/.test(callee)) {
    return { kind: 'messaging.send', symbol: callee, scope: scopeText ?? 'unspecified', location };
  }
  return undefined;
}

function envRead(expr: PyExpr, ctx: PyContext): string | undefined {
  if (expr.kind === 'call') {
    const callee = calleeText(expr.callee as PyExpr, ctx);
    if (callee === 'os.getenv' || callee === 'os.environ.get') {
      const first = (expr.args as PyArg[])[0]?.expr;
      return stringLiteral(first) ?? 'unspecified';
    }
    return undefined;
  }
  if (expr.kind === 'subscript') {
    const base = calleeText(expr.object as PyExpr, ctx);
    if (base === 'os.environ') {
      return stringLiteral(expr.indexExpr as PyExpr) ?? 'unspecified';
    }
    return undefined;
  }
  if (expr.kind === 'attr') {
    const callee = calleeText(expr, ctx);
    if (callee === 'os.environ') return 'unspecified';
    return undefined;
  }
  return undefined;
}

function childrenOf(expr: PyExpr): PyExpr[] {
  const children: PyExpr[] = [];
  const push = (value: unknown): void => {
    if (value && typeof value === 'object' && typeof (value as PyExpr).kind === 'string') {
      children.push(value as PyExpr);
    }
  };
  const pushList = (values: unknown): void => {
    if (Array.isArray(values)) for (const value of values) push(value);
  };
  switch (expr.kind) {
    case 'list':
    case 'tuple':
    case 'set':
      pushList(expr.items);
      break;
    case 'dict':
      pushList((expr.items as Array<{ key: PyExpr | null; value: PyExpr }>).flatMap((item) => [item.key, item.value]));
      break;
    case 'call':
      push(expr.callee);
      pushList((expr.args as PyArg[]).map((arg) => arg.expr));
      break;
    case 'attr':
      push(expr.object);
      break;
    case 'subscript':
      push(expr.object);
      push(expr.indexExpr);
      break;
    case 'binop':
      push(expr.left);
      push(expr.right);
      break;
    case 'unary':
    case 'await':
    case 'starred':
      push(expr.operand ?? expr.value);
      break;
    case 'boolop':
      pushList(expr.values);
      break;
    case 'compare':
      push(expr.left);
      pushList(expr.comparators);
      break;
    case 'ifexp':
      push(expr.test);
      push(expr.body);
      push(expr.orelse);
      break;
    default:
      break;
  }
  return children;
}

/**
 * Detects an environment read embedded in an f-string interpolation such as
 * `f"token={os.getenv(\"TOKEN\")}"` so an inline secret source is not missed.
 */
function envReadInFString(expression: string): { scope: string; index: number } | undefined {
  const getenv = /(?:os\.)?(?:environ\.)?get(?:env)?\(\s*['"]([^'"]+)['"]\s*\)/.exec(expression);
  if (getenv) return { scope: getenv[1]!, index: expression.indexOf('get') };
  const subscript = /(?:os\.)?environ\s*\[\s*['"]([^'"]+)['"]\s*\]/.exec(expression);
  if (subscript) return { scope: subscript[1]!, index: expression.indexOf('environ') };
  return undefined;
}

function taintOf(expr: PyExpr, ctx: PyContext): PyTaint | undefined {
  if (expr.kind === 'name') {
    const taint = ctx.taints.get(String(expr.name));
    return taint ? { ...taint } : undefined;
  }
  if (expr.kind === 'str') {
    if (expr.fstring) {
      for (const expression of (expr.expressions as string[]) ?? []) {
        const embedded = envReadInFString(expression);
        if (embedded) {
          return { sourceName: embedded.scope, source: locationAt(ctx.content, expr.index), through: [] };
        }
      }
      for (const name of (expr.names as string[]) ?? []) {
        const taint = ctx.taints.get(name);
        if (taint) return { ...taint };
      }
    }
    return undefined;
  }
  const env = envRead(expr, ctx);
  if (env) {
    return { sourceName: env, source: locationAt(ctx.content, expr.index), through: [] };
  }
  for (const child of childrenOf(expr)) {
    const taint = taintOf(child, ctx);
    if (taint) return taint;
  }
  return undefined;
}

function analyzeExpr(expr: PyExpr, ctx: PyContext, inCallee = false): void {
  if (expr.kind === 'str' && expr.fstring) {
    for (const expression of (expr.expressions as string[]) ?? []) {
      const embedded = envReadInFString(expression);
      if (embedded) {
        ctx.operations.push({
          kind: 'environment.read',
          symbol: 'fstring-interpolation',
          scope: embedded.scope,
          location: locationAt(ctx.content, expr.index)
        });
      }
    }
  }
  if (expr.kind === 'call') {
    const callee = calleeText(expr.callee as PyExpr, ctx);
    const location = locationAt(ctx.content, expr.index);
    ctx.calls.push({
      callee,
      arguments: (expr.args as PyArg[]).map((arg) => sourceText(ctx.content, arg.expr)),
      location
    });
    const env = envRead(expr, ctx);
    if (env) {
      ctx.operations.push({ kind: 'environment.read', symbol: callee, scope: env, location });
    } else {
      const operation = operationForCall(callee, expr, ctx);
      if (operation) {
        ctx.operations.push(operation);
        if (operation.kind === 'network.connect') {
          for (const arg of expr.args as PyArg[]) {
            const taint = taintOf(arg.expr, ctx);
            if (taint) {
              ctx.flows.push({
                sourceName: taint.sourceName,
                source: taint.source,
                sinkName: callee,
                sink: location,
                destination: operation.scope,
                through: taint.through
              });
              break;
            }
          }
        }
      }
    }
    for (const arg of expr.args as PyArg[]) analyzeExpr(arg.expr, ctx);
    // Recurse into the callee so receiver calls such as open(...).write(...) are still analyzed;
    // env-read attributes used as a callee (os.environ.get) are already handled above.
    analyzeExpr(expr.callee as PyExpr, ctx, true);
    return;
  }
  if (expr.kind === 'attr' || expr.kind === 'subscript') {
    const env = envRead(expr, ctx);
    if (env && !inCallee) {
      ctx.operations.push({
        kind: 'environment.read',
        symbol: calleeText(expr, ctx),
        scope: env,
        location: locationAt(ctx.content, expr.index)
      });
    }
    analyzeExpr(expr.object as PyExpr, ctx, inCallee);
    if (expr.kind === 'subscript' && expr.indexExpr) {
      analyzeExpr(expr.indexExpr as PyExpr, ctx);
    }
    return;
  }
  for (const child of childrenOf(expr)) analyzeExpr(child, ctx);
}

function analyzeBody(body: PyStmt[], ctx: PyContext): void {
  for (const stmt of body) {
    switch (stmt.kind) {
      case 'expr':
        if (stmt.value) analyzeExpr(stmt.value, ctx);
        break;
      case 'assign': {
        const taint = stmt.value ? taintOf(stmt.value, ctx) : undefined;
        for (const target of stmt.targets ?? []) {
          if (target.kind === 'name') {
            const name = String(target.name);
            if (taint) ctx.taints.set(name, { ...taint, through: [...taint.through, name] });
            else ctx.taints.delete(name);
          }
        }
        if (stmt.value) analyzeExpr(stmt.value, ctx);
        break;
      }
      case 'augassign': {
        const taint = stmt.value
          ? (taintOf(stmt.value, ctx) ?? (stmt.target && stmt.target.kind === 'name' ? ctx.taints.get(String(stmt.target.name)) : undefined))
          : undefined;
        if (stmt.target && stmt.target.kind === 'name' && taint) {
          const name = String(stmt.target.name);
          ctx.taints.set(name, { ...taint, through: [...taint.through, name] });
        }
        if (stmt.value) analyzeExpr(stmt.value, ctx);
        break;
      }
      case 'import':
        for (const name of stmt.names ?? []) {
          const local = name.alias ?? name.dotted.split('.')[0]!;
          ctx.imports.push({ specifier: name.dotted, bindings: [local], location: locationAt(ctx.content, stmt.index) });
          ctx.moduleAliases.set(local, name.dotted.split('.')[0]!);
        }
        break;
      case 'fromimport':
        for (const name of stmt.names ?? []) {
          const local = name.alias ?? name.dotted;
          ctx.imports.push({ specifier: stmt.module ?? '', bindings: [name.dotted], location: locationAt(ctx.content, stmt.index) });
          ctx.fromAliases.set(local, `${stmt.module ?? ''}.${name.dotted}`);
        }
        break;
      case 'block':
        if (stmt.body) analyzeBody(stmt.body, ctx);
        break;
      default:
        break;
    }
  }
}

function dedupeOperations(operations: OperationNode[]): OperationNode[] {
  const seen = new Set<string>();
  return operations.filter((operation) => {
    const key = `${operation.kind}:${operation.symbol}:${operation.scope}:${operation.location.index}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Parses a Python source file into the common IR.
 *
 * Never throws. Tokenizer or parser failures produce a stable `error` diagnostic (AS-SC-900 path);
 * the partial IR is still returned so the scanner can attribute what it did understand.
 */
export function parsePython(path: string, rawContent: string): ParsedFile {
  const content = rawContent.charCodeAt(0) === 0xfeff ? ` ${rawContent.slice(1)}` : rawContent;
  const { tokens, diagnostics } = tokenizePython(content);
  const result: ParsedFile = {
    path,
    language: 'python',
    mode: 'ast',
    imports: [],
    calls: [],
    operations: [],
    secretFlows: [],
    tools: [],
    diagnostics,
    metadata: {}
  };
  try {
    const parser = new PyParser(tokens, content);
    const body = parser.parseModule();
    const ctx: PyContext = {
      content,
      imports: result.imports,
      calls: result.calls,
      operations: result.operations,
      flows: result.secretFlows,
      taints: new Map(),
      moduleAliases: new Map(),
      fromAliases: new Map()
    };
    analyzeBody(body, ctx);
    result.operations = dedupeOperations(result.operations);
    result.metadata = { nodeCount: tokens.length, astKind: 'python-ast' };
  } catch (error) {
    const exhausted = error instanceof RangeError;
    result.diagnostics.push({
      code: exhausted ? 'PARSER_RESOURCE_EXHAUSTED' : 'PY_SYNTAX',
      message: exhausted
        ? 'The python parser exhausted available stack depth on this input; analysis is incomplete.'
        : `The python parser failed: ${error instanceof Error ? error.message : String(error)}`,
      severity: 'error',
      location: locationAt(content, 0)
    });
    result.metadata = { analysisGap: 'parser failure; partial intermediate representation was produced' };
  }
  return result;
}
