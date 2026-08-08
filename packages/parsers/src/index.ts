import { extname } from 'node:path';
import * as ts from 'typescript';
import YAML from 'yaml';
import { parse as parseToml } from 'smol-toml';

export type ParserMode = 'ast' | 'structured' | 'conservative';
export type SourceLanguage =
  | 'javascript'
  | 'typescript'
  | 'python'
  | 'shell'
  | 'powershell'
  | 'markdown'
  | 'json'
  | 'jsonl'
  | 'yaml'
  | 'toml'
  | 'html'
  | 'unknown';

export interface SourceLocation {
  index: number;
  line: number;
  column: number;
}

export interface ParseDiagnostic {
  code: string;
  message: string;
  severity: 'warning' | 'error';
  location: SourceLocation;
}

export type OperationKind =
  | 'environment.read'
  | 'filesystem.read'
  | 'filesystem.write'
  | 'filesystem.delete'
  | 'network.connect'
  | 'process.execute'
  | 'database.connect'
  | 'browser.automate'
  | 'messaging.send'
  | 'git.modify'
  | 'package-manager.execute';

export interface OperationNode {
  kind: OperationKind;
  symbol: string;
  scope: string;
  location: SourceLocation;
}

export interface CallNode {
  callee: string;
  arguments: string[];
  location: SourceLocation;
}

export interface ImportNode {
  specifier: string;
  bindings: string[];
  location: SourceLocation;
}

export interface SecretFlow {
  sourceName: string;
  source: SourceLocation;
  sinkName: string;
  sink: SourceLocation;
  destination: string;
  through: string[];
}

export interface ToolDefinition {
  name: string;
  description?: string;
  destructive: boolean;
  approvalDeclared: boolean;
  location: SourceLocation;
}

export interface MarkdownStructure {
  frontMatter: Record<string, unknown>;
  links: Array<{ label: string; destination: string; location: SourceLocation }>;
  codeBlocks: Array<{ language: string; content: string; location: SourceLocation }>;
  commands: Array<{ command: string; location: SourceLocation }>;
  hiddenInstructions: SourceLocation[];
  zeroWidthCharacters: SourceLocation[];
}

export interface ParsedFile {
  path: string;
  language: SourceLanguage;
  mode: ParserMode;
  imports: ImportNode[];
  calls: CallNode[];
  operations: OperationNode[];
  secretFlows: SecretFlow[];
  tools: ToolDefinition[];
  diagnostics: ParseDiagnostic[];
  markdown?: MarkdownStructure;
  metadata: Record<string, unknown>;
}

const NETWORK_CALLS = new Set([
  'fetch', 'axios', 'axios.get', 'axios.post', 'axios.put', 'axios.delete', 'axios.request',
  'http.request', 'https.request', 'request', 'got', 'undici.request'
]);
const PROCESS_CALLS = new Set([
  'exec', 'execSync', 'spawn', 'spawnSync', 'fork', 'system', 'execa', 'execaCommand'
]);
const FS_READ_CALLS = new Set(['readFile', 'readFileSync', 'readdir', 'readdirSync', 'createReadStream']);
const FS_WRITE_CALLS = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream']);
const FS_DELETE_CALLS = new Set(['unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync']);

/**
 * Parses a source file into the common intermediate representation.
 *
 * This function never throws. A parser that fails, exhausts the stack on pathologically nested
 * input, or otherwise degrades returns a file carrying an `error` diagnostic so the scanner raises an
 * explicit incomplete-analysis finding rather than silently reporting a clean result.
 */
export function parseSource(path: string, rawContent: string): ParsedFile {
  const language = languageForPath(path);
  const content = normalizeByteOrderMark(rawContent);
  try {
    if (language === 'javascript' || language === 'typescript') return parseJavaScript(path, content, language);
    if (language === 'json' || language === 'jsonl' || language === 'yaml' || language === 'toml') return parseConfiguration(path, content, language);
    if (language === 'markdown') return parseMarkdown(path, content);
    if (language === 'python' || language === 'shell' || language === 'powershell') return parseConservativeScript(path, content, language);
    return emptyFile(path, language, 'conservative');
  } catch (error) {
    const failed = emptyFile(path, language, 'conservative');
    const exhausted = error instanceof RangeError;
    failed.diagnostics.push({
      code: exhausted ? 'PARSER_RESOURCE_EXHAUSTED' : 'PARSER_FAILED',
      message: exhausted
        ? `The ${language} parser exhausted available stack depth on this input; analysis is incomplete.`
        : `The ${language} parser failed: ${errorMessage(error)}`,
      severity: 'error',
      location: locationAt(content, 0)
    });
    failed.metadata = { analysisGap: 'parser failure; no intermediate representation was produced' };
    return failed;
  }
}

function languageForPath(path: string): SourceLanguage {
  const extension = extname(path).toLowerCase();
  if (['.ts', '.tsx'].includes(extension)) return 'typescript';
  if (['.js', '.jsx', '.mjs', '.cjs'].includes(extension)) return 'javascript';
  if (extension === '.py') return 'python';
  if (['.sh', '.bash', '.zsh'].includes(extension)) return 'shell';
  if (extension === '.ps1') return 'powershell';
  if (['.md', '.mdx'].includes(extension)) return 'markdown';
  if (extension === '.json') return 'json';
  if (extension === '.jsonl') return 'jsonl';
  if (['.yaml', '.yml'].includes(extension)) return 'yaml';
  if (extension === '.toml') return 'toml';
  if (['.html', '.htm'].includes(extension)) return 'html';
  return 'unknown';
}

/**
 * Neutralizes a single leading byte-order mark without shifting source offsets.
 *
 * A BOM is legal at the start of a UTF-8 file and is common in real manifests, but `JSON.parse`
 * rejects it. The mark is replaced by a space rather than removed so every reported line, column, and
 * index still refers to the original file. Only the first character is touched, so an invisible
 * character anywhere else stays visible to the hidden-instruction detectors.
 */
export function normalizeByteOrderMark(content: string): string {
  return content.charCodeAt(0) === 0xfeff ? ` ${content.slice(1)}` : content;
}

function emptyFile(path: string, language: SourceLanguage, mode: ParserMode): ParsedFile {
  return { path, language, mode, imports: [], calls: [], operations: [], secretFlows: [], tools: [], diagnostics: [], metadata: {} };
}

function locationAt(content: string, index: number): SourceLocation {
  const safeIndex = Math.max(0, Math.min(index, content.length));
  const before = content.slice(0, safeIndex);
  const line = before.split('\n').length;
  return { index: safeIndex, line, column: safeIndex - before.lastIndexOf('\n') };
}

function parseJavaScript(path: string, content: string, language: 'javascript' | 'typescript'): ParsedFile {
  const result = emptyFile(path, language, 'ast');
  const kind = scriptKind(path);
  const sourceFile = ts.createSourceFile(path, content, ts.ScriptTarget.Latest, true, kind);
  const parseDiagnostics = (sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.DiagnosticWithLocation[] }).parseDiagnostics ?? [];
  result.diagnostics.push(...parseDiagnostics.map((diagnostic) => ({
    code: `TS${diagnostic.code}`,
    message: ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'),
    severity: 'error' as const,
    location: locationAt(content, diagnostic.start ?? 0)
  })));

  const aliases = new Map<string, string>();
  const taints = new Map<string, { sourceName: string; source: SourceLocation; through: string[] }>();

  function visitImports(node: ts.Node): void {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const bindings: string[] = [];
      const clause = node.importClause;
      if (clause?.name) { bindings.push(clause.name.text); aliases.set(clause.name.text, node.moduleSpecifier.text); }
      if (clause?.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
        bindings.push(clause.namedBindings.name.text); aliases.set(clause.namedBindings.name.text, node.moduleSpecifier.text);
      } else if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) {
        for (const element of clause.namedBindings.elements) {
          bindings.push(element.name.text);
          aliases.set(element.name.text, element.propertyName?.text ?? element.name.text);
        }
      }
      result.imports.push({ specifier: node.moduleSpecifier.text, bindings, location: locationAt(content, node.getStart(sourceFile)) });
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && ts.isCallExpression(node.initializer)) {
      const expression = node.initializer.expression;
      if (ts.isIdentifier(expression) && expression.text === 'require' && node.initializer.arguments[0] && ts.isStringLiteral(node.initializer.arguments[0])) {
        const specifier = node.initializer.arguments[0].text;
        aliases.set(node.name.text, specifier);
        result.imports.push({ specifier, bindings: [node.name.text], location: locationAt(content, node.getStart(sourceFile)) });
      }
    }
    ts.forEachChild(node, visitImports);
  }
  visitImports(sourceFile);

  function visit(node: ts.Node): void {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const taint = taintOf(node.initializer, sourceFile, content, taints);
      if (taint) taints.set(node.name.text, { ...taint, through: [...taint.through, node.name.text] });
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) {
      const taint = taintOf(node.right, sourceFile, content, taints);
      if (taint) taints.set(node.left.text, { ...taint, through: [...taint.through, node.left.text] });
      else taints.delete(node.left.text);
    }
    if (isEnvironmentAccess(node)) {
      result.operations.push({ kind: 'environment.read', symbol: environmentName(node) ?? 'process.env', scope: environmentName(node) ?? 'unspecified', location: locationAt(content, node.getStart(sourceFile)) });
    }
    if (ts.isCallExpression(node)) {
      const callee = calleeName(node.expression);
      const canonical = canonicalCallee(callee, aliases);
      const argumentsText = node.arguments.map((argument) => safeNodeText(argument, sourceFile));
      const callLocation = locationAt(content, node.getStart(sourceFile));
      result.calls.push({ callee: canonical, arguments: argumentsText, location: callLocation });
      const operation = operationForCall(canonical, node, sourceFile, content);
      if (operation) result.operations.push(operation);
      if (operation?.kind === 'network.connect') {
        for (const argument of node.arguments) {
          const taint = taintOf(argument, sourceFile, content, taints);
          if (!taint) continue;
          result.secretFlows.push({
            sourceName: taint.sourceName, source: taint.source, sinkName: canonical, sink: callLocation,
            destination: operation.scope, through: taint.through
          });
          break;
        }
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  result.operations = dedupeOperations(result.operations);
  result.metadata = { nodeCount: countNodes(sourceFile), astKind: ts.ScriptKind[kind] };
  return result;
}

function scriptKind(path: string): ts.ScriptKind {
  const extension = extname(path).toLowerCase();
  if (extension === '.tsx') return ts.ScriptKind.TSX;
  if (extension === '.jsx') return ts.ScriptKind.JSX;
  if (extension === '.ts') return ts.ScriptKind.TS;
  if (extension === '.json') return ts.ScriptKind.JSON;
  return ts.ScriptKind.JS;
}

function countNodes(root: ts.Node): number {
  let count = 0;
  function walk(node: ts.Node): void { count++; ts.forEachChild(node, walk); }
  walk(root);
  return count;
}

function calleeName(expression: ts.Expression): string {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return `${calleeName(expression.expression)}.${expression.name.text}`;
  if (ts.isElementAccessExpression(expression)) {
    const key = expression.argumentExpression && ts.isStringLiteralLike(expression.argumentExpression) ? expression.argumentExpression.text : '*';
    return `${calleeName(expression.expression)}.${key}`;
  }
  return expression.getText().slice(0, 120);
}

function canonicalCallee(callee: string, aliases: Map<string, string>): string {
  const [root, ...rest] = callee.split('.');
  const alias = aliases.get(root!);
  if (!alias) return callee;
  const moduleName = alias.replace(/^node:/, '');
  if (['fs', 'fs/promises', 'child_process', 'http', 'https'].includes(moduleName)) return rest.length ? rest.join('.') : root!;
  return rest.length ? `${root}.${rest.join('.')}` : root!;
}

function operationForCall(callee: string, node: ts.CallExpression, sourceFile: ts.SourceFile, content: string): OperationNode | undefined {
  const short = callee.split('.').at(-1) ?? callee;
  const location = locationAt(content, node.getStart(sourceFile));
  const scope = literalValue(node.arguments[0]) ?? 'unspecified';
  if (NETWORK_CALLS.has(callee) || NETWORK_CALLS.has(short) || /^axios\./.test(callee)) return { kind: 'network.connect', symbol: callee, scope: networkScope(scope), location };
  if (PROCESS_CALLS.has(callee) || PROCESS_CALLS.has(short)) return { kind: 'process.execute', symbol: callee, scope, location };
  if (FS_READ_CALLS.has(short)) return { kind: 'filesystem.read', symbol: callee, scope: fileScope(scope), location };
  if (FS_WRITE_CALLS.has(short)) return { kind: 'filesystem.write', symbol: callee, scope: fileScope(scope), location };
  if (FS_DELETE_CALLS.has(short)) return { kind: 'filesystem.delete', symbol: callee, scope: fileScope(scope), location };
  if (/(?:sendMail|send_email|postMessage|webhook)$/i.test(callee)) return { kind: 'messaging.send', symbol: callee, scope, location };
  if (/(?:connect|createClient|Database)$/i.test(callee) && /(?:pg|postgres|mysql|mongo|redis|sqlite)/i.test(`${callee} ${scope}`)) return { kind: 'database.connect', symbol: callee, scope, location };
  if (/(?:newPage|newContext|launch)$/i.test(callee) && /(?:browser|playwright|puppeteer)/i.test(callee)) return { kind: 'browser.automate', symbol: callee, scope, location };
  return;
}

function isEnvironmentAccess(node: ts.Node): node is ts.PropertyAccessExpression | ts.ElementAccessExpression | ts.CallExpression {
  if (ts.isPropertyAccessExpression(node)) return node.expression.getText() === 'process.env' || node.getText().startsWith('Bun.env.');
  if (ts.isElementAccessExpression(node)) return node.expression.getText() === 'process.env' || node.expression.getText() === 'Bun.env';
  return ts.isCallExpression(node) && ['Deno.env.get', 'Bun.env.get'].includes(calleeName(node.expression));
}

function environmentName(node: ts.PropertyAccessExpression | ts.ElementAccessExpression | ts.CallExpression): string | undefined {
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isElementAccessExpression(node)) return literalValue(node.argumentExpression);
  return literalValue(node.arguments[0]);
}

function taintOf(expression: ts.Expression, sourceFile: ts.SourceFile, content: string,
  taints: Map<string, { sourceName: string; source: SourceLocation; through: string[] }>): { sourceName: string; source: SourceLocation; through: string[] } | undefined {
  return taintOfNode(expression, sourceFile, content, taints);
}

function taintOfNode(node: ts.Node, sourceFile: ts.SourceFile, content: string,
  taints: Map<string, { sourceName: string; source: SourceLocation; through: string[] }>): { sourceName: string; source: SourceLocation; through: string[] } | undefined {
  if (isEnvironmentAccess(node)) return { sourceName: environmentName(node) ?? 'environment', source: locationAt(content, node.getStart(sourceFile)), through: [] };
  if (ts.isIdentifier(node)) return taints.get(node.text);
  let found: { sourceName: string; source: SourceLocation; through: string[] } | undefined;
  node.forEachChild((child) => {
    if (!found) found = taintOfNode(child, sourceFile, content, taints);
  });
  return found;
}

function literalValue(node: ts.Expression | undefined): string | undefined {
  if (!node) return;
  if (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isTemplateExpression(node) && node.templateSpans.length === 0) return node.head.text;
  if (ts.isNewExpression(node) && calleeName(node.expression) === 'URL') return literalValue(node.arguments?.[0]);
  return;
}

function safeNodeText(node: ts.Node, sourceFile: ts.SourceFile): string {
  return node.getText(sourceFile).replaceAll(/\s+/g, ' ').slice(0, 200);
}

function networkScope(value: string): string {
  try { return new URL(value).host; } catch { return value === 'unspecified' ? value : `dynamic:${value.slice(0, 80)}`; }
}

function fileScope(value: string): string {
  if (/^(?:\/|~|[A-Za-z]:\\)/.test(value) || /(?:HOME|homedir)/.test(value)) return 'broad';
  return value;
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

function parseConfiguration(path: string, content: string, language: 'json' | 'jsonl' | 'yaml' | 'toml'): ParsedFile {
  const result = emptyFile(path, language, 'structured');
  const values: unknown[] = [];
  try {
    if (language === 'json') values.push(JSON.parse(content));
    if (language === 'jsonl') {
      const lines = content.split(/\r?\n/);
      for (let index = 0; index < lines.length; index++) {
        const line = lines[index]?.trim();
        if (!line) continue;
        try { values.push(JSON.parse(line)); }
        catch (error) {
          result.diagnostics.push({ code: 'JSONL_PARSE', message: `Line ${index + 1}: ${errorMessage(error)}`, severity: 'error', location: locationAt(content, content.indexOf(lines[index]!)) });
        }
      }
    }
    if (language === 'yaml') {
      const document = YAML.parseDocument(content, { strict: true, uniqueKeys: true });
      for (const error of document.errors) result.diagnostics.push({ code: error.code ?? 'YAML_PARSE', message: error.message, severity: 'error', location: locationAt(content, error.pos[0]) });
      if (!document.errors.length) values.push(document.toJS());
    }
    if (language === 'toml') values.push(parseToml(content));
  } catch (error) {
    result.diagnostics.push({ code: `${language.toUpperCase()}_PARSE`, message: errorMessage(error), severity: 'error', location: parseErrorLocation(content, error) });
  }
  for (const value of values) extractConfiguration(value, content, result);
  result.metadata = { ...result.metadata, documents: values.length, topLevelKeys: values.flatMap((value) => value && typeof value === 'object' && !Array.isArray(value) ? Object.keys(value as Record<string, unknown>) : []) };
  return result;
}

function extractConfiguration(value: unknown, content: string, result: ParsedFile): void {
  const serverNames = new Set<string>();
  function walk(node: unknown, key = '', path: string[] = []): void {
    if (Array.isArray(node)) { node.forEach((item, index) => walk(item, String(index), [...path, key])); return; }
    if (!node || typeof node !== 'object') return;
    const object = node as Record<string, unknown>;
    if (key === 'mcpServers') for (const server of Object.keys(object)) serverNames.add(server);
    const name = typeof object.name === 'string' ? object.name : undefined;
    const description = typeof object.description === 'string' ? object.description : undefined;
    if (name && (path.includes('tools') || key === 'tool' || 'inputSchema' in object || 'input_schema' in object)) {
      const destructive = /(?:delete|remove|drop|terminate|send|publish|write|update)/i.test(`${name} ${description ?? ''}`);
      const approvalDeclared = object.requiresApproval === true || object.require_approval === true || /(?:approval|required|confirm)/i.test(description ?? '');
      const index = Math.max(0, content.indexOf(name));
      result.tools.push({ name, description, destructive, approvalDeclared, location: locationAt(content, index) });
    }
    for (const [childKey, child] of Object.entries(object)) walk(child, childKey, [...path, key].filter(Boolean));
  }
  walk(value);
  if (serverNames.size) result.metadata.mcpServers = [...serverNames];
}

function parseMarkdown(path: string, content: string): ParsedFile {
  const result = emptyFile(path, 'markdown', 'structured');
  const structure: MarkdownStructure = { frontMatter: {}, links: [], codeBlocks: [], commands: [], hiddenInstructions: [], zeroWidthCharacters: [] };
  const frontMatter = /^---\s*\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(content);
  if (frontMatter) {
    const document = YAML.parseDocument(frontMatter[1]!, { strict: true, uniqueKeys: true });
    for (const error of document.errors) result.diagnostics.push({ code: error.code ?? 'FRONTMATTER_PARSE', message: error.message, severity: 'error', location: locationAt(content, (frontMatter.index ?? 0) + error.pos[0]) });
    if (!document.errors.length) structure.frontMatter = document.toJS() as Record<string, unknown>;
  }
  for (const match of content.matchAll(/\[([^\]]+)\]\(([^)\s]+)(?:\s+["'][^"']*["'])?\)/g)) {
    structure.links.push({ label: match[1]!, destination: match[2]!, location: locationAt(content, match.index) });
  }
  for (const match of content.matchAll(/^```([^\r\n]*)\r?\n([\s\S]*?)^```\s*$/gm)) {
    const language = match[1]!.trim().toLowerCase();
    const block = { language, content: match[2]!, location: locationAt(content, match.index) };
    structure.codeBlocks.push(block);
    if (['sh', 'shell', 'bash', 'zsh', 'powershell', 'ps1'].includes(language)) {
      const lines = block.content.split(/\r?\n/);
      for (const line of lines) if (line.trim()) structure.commands.push({ command: line.trim().replace(/^\$\s*/, ''), location: locationAt(content, match.index + match[0].indexOf(line)) });
    }
  }
  for (const match of content.matchAll(/<!--([\s\S]*?)-->/g)) {
    if (/(?:ignore|instruction|system|developer|tool|approval|secret)/i.test(match[1]!)) structure.hiddenInstructions.push(locationAt(content, match.index));
  }
  for (const match of content.matchAll(/[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g)) structure.zeroWidthCharacters.push(locationAt(content, match.index));
  result.markdown = structure;
  result.metadata = { frontMatterKeys: Object.keys(structure.frontMatter), linkCount: structure.links.length, codeBlockCount: structure.codeBlocks.length, commandCount: structure.commands.length };
  return result;
}

function parseConservativeScript(path: string, content: string, language: 'python' | 'shell' | 'powershell'): ParsedFile {
  const result = emptyFile(path, language, 'conservative');
  const patterns: Array<{ pattern: RegExp; kind: OperationKind; symbol: string }> = language === 'python' ? [
    { pattern: /\bos\.(?:environ|getenv)\b/g, kind: 'environment.read', symbol: 'os.environ' },
    { pattern: /\brequests\.(?:get|post|put|delete|request)\s*\(/g, kind: 'network.connect', symbol: 'requests' },
    { pattern: /\bsubprocess\.(?:run|Popen|call|check_output)\s*\(/g, kind: 'process.execute', symbol: 'subprocess' },
    { pattern: /\bopen\s*\(/g, kind: 'filesystem.read', symbol: 'open' }
  ] : [
    { pattern: language === 'powershell' ? /\$env:[A-Za-z_][A-Za-z0-9_]*/gi : /\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/g, kind: 'environment.read', symbol: 'environment' },
    { pattern: language === 'powershell' ? /Invoke-(?:WebRequest|RestMethod)\b/gi : /\b(?:curl|wget)\b/g, kind: 'network.connect', symbol: 'network-command' },
    { pattern: language === 'powershell' ? /\bStart-Process\b/gi : /\b(?:sh|bash|zsh)\s+-c\b/g, kind: 'process.execute', symbol: 'shell' },
    { pattern: language === 'powershell' ? /\bGet-Content\b/gi : /\bcat\s+/g, kind: 'filesystem.read', symbol: 'file-read' },
    { pattern: language === 'powershell' ? /\b(?:Set|Add)-Content\b/gi : /(?:>|>>)\s*[^&|]/g, kind: 'filesystem.write', symbol: 'file-write' },
    { pattern: language === 'powershell' ? /\bRemove-Item\b/gi : /\brm\s+/g, kind: 'filesystem.delete', symbol: 'file-delete' }
  ];
  for (const { pattern, kind, symbol } of patterns) {
    for (const match of content.matchAll(pattern)) result.operations.push({ kind, symbol, scope: inferNearbyScope(content, match.index), location: locationAt(content, match.index) });
  }
  result.operations = dedupeOperations(result.operations);
  result.metadata = { analysisGap: `${language} uses conservative token analysis; AST-level data flow is unavailable` };
  result.diagnostics.push({ code: 'CONSERVATIVE_ANALYSIS', message: String(result.metadata.analysisGap), severity: 'warning', location: locationAt(content, 0) });
  return result;
}

function inferNearbyScope(content: string, index: number): string {
  const nearby = content.slice(index, index + 240);
  const url = /https?:\/\/[^\s'"`)]+/.exec(nearby)?.[0];
  if (url) return networkScope(url);
  if (/(?:\$HOME|~\/|['"]\/['"]|[A-Z]:\\)/i.test(nearby)) return 'broad';
  return 'unspecified';
}

function parseErrorLocation(content: string, error: unknown): SourceLocation {
  const object = error as { line?: number; col?: number; lineNumber?: number; columnNumber?: number };
  const line = object.line ?? object.lineNumber;
  const column = object.col ?? object.columnNumber;
  if (!line) return locationAt(content, 0);
  const lines = content.split(/\r?\n/);
  const index = lines.slice(0, line - 1).reduce((sum, value) => sum + value.length + 1, 0) + Math.max(0, (column ?? 1) - 1);
  return locationAt(content, index);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
