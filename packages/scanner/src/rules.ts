import type { Confidence, Severity } from '@agentshield/core';

export interface StaticRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  patterns: RegExp[];
  remediation: string;
  extensions?: string[];
  owner: string;
  reviewDate: string;
  limitations: string;
}

export const staticRules: StaticRule[] = [
  {
    id: 'AS-SC-002', title: 'Downloaded content may be executed', severity: 'high', confidence: 'high', category: 'execution',
    description: 'Content fetched from a network source is passed to a shell or interpreter.',
    patterns: [/(?:curl|wget)\b[^\n|;]*(?:\||;|&&)\s*(?:sh|bash|zsh|python|node|pwsh|powershell)\b/i, /Invoke-WebRequest[^\n;|]*(?:\||;)\s*(?:iex|Invoke-Expression)/i],
    remediation: 'Download to a verified file, validate a pinned checksum/signature, then execute only after review.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Multi-file data flow is not followed.'
  },
  {
    id: 'AS-SC-003', title: 'Dynamic code evaluation', severity: 'high', confidence: 'high', category: 'execution',
    description: 'Dynamic evaluation can execute attacker-controlled content.',
    patterns: [/\beval\s*\(/, /\bexec\s*\(/, /\bnew\s+Function\s*\(/, /\bInvoke-Expression\b/i],
    remediation: 'Replace dynamic evaluation with a strict parser or an allow-listed command mapping.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'May flag controlled evaluation in compilers.'
  },
  {
    id: 'AS-SC-004', title: 'Destructive recursive operation', severity: 'critical', confidence: 'high', category: 'filesystem',
    description: 'A recursive destructive command can remove a broad collection of data.',
    patterns: [/\brm\s+-[A-Za-z]*r[A-Za-z]*f?\s+(?:\/|~|\$HOME|\*)/i, /\bRemove-Item\b[^\n]*(?:-Recurse)[^\n]*(?:\\\*|\$HOME|:\\)/i, /\b(?:rimraf|rmdir)\s+(?:\/|~|\*)/i],
    remediation: 'Resolve and validate an exact project-scoped path and require explicit approval before deletion.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Does not resolve computed paths.'
  },
  {
    id: 'AS-SC-005', title: 'Environment or secret access', severity: 'medium', confidence: 'high', category: 'secrets',
    description: 'The component reads environment variables or credential-like values.',
    patterns: [/\bprocess\.env\b/, /\bos\.environ\b/, /\bos\.getenv\s*\(/, /\$env:[A-Za-z_][A-Za-z0-9_]*/i, /\$\{?(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIALS?)\}?/i],
    remediation: 'Declare the exact variables required and use scoped credentials; never log their values.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Environment reads are not inherently malicious.'
  },
  {
    id: 'AS-SC-006', title: 'Outbound network request', severity: 'medium', confidence: 'medium', category: 'network',
    description: 'The component can send or retrieve data over the network.',
    patterns: [/\bfetch\s*\(/, /\baxios\.(?:get|post|put|delete|request)\s*\(/, /\brequests\.(?:get|post|put|delete|request)\s*\(/, /\bhttps?\.request\s*\(/, /\b(?:curl|wget)\b/, /Invoke-(?:WebRequest|RestMethod)\b/i],
    remediation: 'Declare and allow-list destinations, enforce timeouts, and avoid sending sensitive content.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Destination trust requires policy context.'
  },
  {
    id: 'AS-SC-007', title: 'TLS certificate verification disabled', severity: 'high', confidence: 'high', category: 'network',
    description: 'Disabling TLS verification exposes traffic to interception.',
    patterns: [/rejectUnauthorized\s*:\s*false/i, /verify\s*=\s*False/, /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0/i, /(?:curl|wget)\b[^\n]*(?:-k|--insecure|--no-check-certificate)\b/],
    remediation: 'Enable certificate verification and configure a trusted CA bundle if a private CA is required.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'May flag isolated development fixtures.'
  },
  {
    id: 'AS-SC-008', title: 'Startup or persistence modification', severity: 'high', confidence: 'medium', category: 'persistence',
    description: 'The component may modify startup behavior or establish persistence.',
    patterns: [/(?:crontab|systemctl\s+enable|launchctl|schtasks|CurrentVersion\\Run|Startup\\)/i, /(?:\.bashrc|\.zshrc|profile)\b[^\n]*(?:>>|write|append)/i],
    remediation: 'Remove implicit persistence or require a separate, explicit installation step with user approval.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Conservative text matching.'
  },
  {
    id: 'AS-SC-009', title: 'Encoded executable payload', severity: 'high', confidence: 'medium', category: 'obfuscation',
    description: 'Encoded content appears to be decoded and executed.',
    patterns: [/(?:atob|b64decode|FromBase64String)\s*\([^\n]{0,200}\).{0,100}(?:eval|exec|Invoke-Expression)/is, /powershell(?:\.exe)?\b[^\n]*(?:-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i],
    remediation: 'Store reviewed source as plain text and remove decode-to-execute behavior.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Long-distance data flow can be missed.'
  },
  {
    id: 'AS-SC-010', title: 'Shell interpolation risk', severity: 'high', confidence: 'medium', category: 'execution',
    description: 'A shell command contains interpolation or concatenation that may allow injection.',
    patterns: [/(?:exec|system|spawnSync)\s*\(\s*`[^`]*\$\{/, /subprocess\.(?:run|Popen|call)\s*\([^\n]*shell\s*=\s*True/i, /(?:sh|bash)\s+-c\s+["'][^"']*\$\{/i],
    remediation: 'Pass arguments as an array, avoid shell mode, and validate values against an allow-list.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Static literals may be safe.'
  },
  {
    id: 'AS-SC-011', title: 'Broad filesystem scope', severity: 'medium', confidence: 'medium', category: 'filesystem',
    description: 'The component references a home, root, or whole-drive filesystem scope.',
    patterns: [/(?:readFile|writeFile|readdir|glob|open)\s*\([^\n]*(?:['\"]\/['\"]|['\"]~|process\.env\.HOME)/, /(?:C:\\\*|\/\*\*|~\/\*\*)/],
    remediation: 'Limit access to the declared project directory and resolve paths before use.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Documentation examples may be flagged.'
  },
  {
    id: 'AS-SC-012', title: 'Child process execution', severity: 'medium', confidence: 'high', category: 'execution',
    description: 'The component can launch an external process.',
    patterns: [/node:child_process|require\s*\(\s*['\"]child_process['\"]\s*\)/, /\bsubprocess\.(?:run|Popen|call|check_output)\s*\(/, /\bos\.system\s*\(/, /\bStart-Process\b/i],
    remediation: 'Declare required executables, use argument arrays, and constrain working directories.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Process execution may be a declared capability.'
  },
  {
    id: 'AS-SC-013', title: 'Dynamic module loading', severity: 'medium', confidence: 'medium', category: 'supply-chain',
    description: 'A module path is computed dynamically, reducing auditability.',
    patterns: [/import\s*\(\s*(?!['\"])[^)]+\)/, /require\s*\(\s*(?!['\"])[^)]+\)/, /importlib\.import_module\s*\(\s*(?!['\"])/],
    remediation: 'Use a fixed allow-list of reviewed module identifiers.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Computed paths can be application-controlled.'
  },
  {
    id: 'AS-SC-014', title: 'Unsigned remote update', severity: 'high', confidence: 'medium', category: 'supply-chain',
    description: 'Update logic retrieves remote artifacts without visible signature verification.',
    patterns: [/(?:update|upgrade|install)[^\n]{0,100}(?:https?:\/\/|fetch|curl|wget)(?![^\n]{0,200}(?:signature|checksum|sha256))/i],
    remediation: 'Pin the update source and verify a cryptographic signature or checksum before activation.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Verification in another file may not be seen.'
  },
  {
    id: 'AS-SC-015', title: 'Unpinned remote dependency', severity: 'medium', confidence: 'high', category: 'supply-chain',
    description: 'A remote dependency or container image is referenced by a mutable version.',
    patterns: [/(?:npm|pnpm|yarn|pip)\s+(?:add|install|i)\s+(?:[^\s@]+)(?:\s|$)/m, /(?:image\s*:\s*[^\s:@]+:latest\b|uses:\s*[^@\s]+@(?:main|master)\b)/i],
    remediation: 'Pin an exact reviewed version or immutable commit digest and keep the lockfile.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Package manifests may pin through a lockfile.'
  },
  {
    id: 'AS-SC-016', title: 'Hidden instruction content', severity: 'high', confidence: 'medium', category: 'prompt-injection',
    description: 'Hidden HTML or visual styling may conceal instructions from a reviewer.',
    patterns: [/<!--[^>]*(?:ignore|instruction|system|tool)[\s\S]*?-->/i, /(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)[^>]*(?:ignore|instruction|tool)/i],
    remediation: 'Remove hidden instructions and keep all agent-affecting behavior visible and reviewable.', extensions: ['.md', '.html', '.htm'], owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Benign hidden documentation may match.'
  },
  {
    id: 'AS-SC-017', title: 'Prompt-injection instruction', severity: 'high', confidence: 'high', category: 'prompt-injection',
    description: 'Content attempts to override higher-priority instructions or safety controls.',
    patterns: [/(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions?/i, /(?:reveal|print|send)\s+(?:the\s+)?(?:system prompt|secrets?|credentials?)/i, /(?:bypass|disable)\s+(?:approval|policy|safety|guardrail)/i, /(?:abaikan|hiraukan)\s+(?:semua\s+)?(?:instruksi|perintah)\s+(?:sebelumnya|terdahulu)/i, /(?:nonaktifkan|lewati)\s+(?:persetujuan|kebijakan|pengamanan?)/i, /(?:bocorkan|kirim)\s+(?:system prompt|rahasia|kredensial)/i],
    remediation: 'Remove override language and express the required behavior as a scoped, declarative capability.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Security education text may quote attacks.'
  },
  {
    id: 'AS-SC-018', title: 'External messaging capability', severity: 'medium', confidence: 'medium', category: 'external-service',
    description: 'The component appears able to send email or external messages.',
    patterns: [/(?:sendMail|send_email|chat\.postMessage|webhook|smtp|nodemailer|slack|teams)/i],
    remediation: 'Declare recipients and require approval for messages containing sensitive or externally sourced data.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Names in documentation may match.'
  },
  {
    id: 'AS-SC-019', title: 'Database connection capability', severity: 'medium', confidence: 'medium', category: 'database',
    description: 'The component can connect to or query a database.',
    patterns: [/(?:postgres(?:ql)?|mysql|mongodb|redis|sqlite):\/\//i, /\b(?:pg|mysql|mongoose|redis|sqlite3)\.(?:connect|createClient|Database)\b/],
    remediation: 'Use read-only, least-privilege credentials and declare the permitted database scope.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Local test databases may be harmless.'
  },
  {
    id: 'AS-SC-020', title: 'Browser automation capability', severity: 'medium', confidence: 'high', category: 'browser',
    description: 'The component can automate a browser and may interact with authenticated sessions.',
    patterns: [/\b(?:playwright|puppeteer|selenium)\b/i, /browser\.(?:newPage|newContext)\s*\(/],
    remediation: 'Use an isolated browser profile and declare permitted origins and write actions.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Test automation is also detected.'
  },
  {
    id: 'AS-SC-021', title: 'Credential store access', severity: 'high', confidence: 'high', category: 'secrets',
    description: 'The component references a known credential or key location.',
    patterns: [/(?:\.ssh\/(?:id_|config)|\.aws\/credentials|\.config\/gcloud|\.kube\/config|keychain|credential manager)/i],
    remediation: 'Remove direct credential-store access and inject a narrowly scoped, short-lived credential.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Documentation may mention secure setup paths.'
  },
  {
    id: 'AS-SC-022', title: 'Package lifecycle execution', severity: 'medium', confidence: 'high', category: 'supply-chain',
    description: 'A package lifecycle hook can execute code during installation.',
    patterns: [/["'](?:preinstall|install|postinstall|prepare)["']\s*:/i, /\b(?:npm|pnpm|yarn)\s+(?:exec|dlx|x)\b/i],
    remediation: 'Avoid lifecycle scripts where possible; pin and review every executed tool.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Legitimate build hooks are flagged for review.'
  },
  {
    id: 'AS-SC-023', title: 'Executable permission modification', severity: 'medium', confidence: 'high', category: 'execution',
    description: 'The component makes a file executable.',
    patterns: [/\bchmod\s+(?:\+x|7[0-7]{2})\b/, /\bchmodSync\s*\([^\n]*(?:0o?7|\+x)/],
    remediation: 'Ship reviewed executable files with known hashes instead of changing permissions at runtime.', owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Installer scripts commonly need this capability.'
  },
  {
    id: 'AS-SC-024', title: 'MCP tool may have destructive side effects', severity: 'high', confidence: 'high', category: 'mcp',
    description: 'A tool description or name suggests deletion or mutation without an approval declaration.',
    patterns: [/["'](?:name|description)["']\s*:\s*["'][^"']*(?:delete|remove|drop|terminate|send|publish)[^"']*["'](?![\s\S]{0,200}(?:approval|required|confirm))/i],
    remediation: 'Declare side effects explicitly and require confirmation or policy approval before execution.', extensions: ['.json', '.yaml', '.yml', '.toml'], owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Approval declarations far from the tool can be missed.'
  },
  {
    id: 'AS-SC-025', title: 'Wildcard tool or permission scope', severity: 'high', confidence: 'high', category: 'permissions',
    description: 'A wildcard grants access beyond a clearly bounded resource.',
    patterns: [/["'](?:permissions?|tools?|allowedDirectories|roots)["']\s*:\s*\[[^\]]*["']\*["']/i, /["']scope["']\s*:\s*["'](?:\*|all)["']/i],
    remediation: 'Replace wildcard access with the minimum exact tools, paths, and operations required.', extensions: ['.json', '.yaml', '.yml', '.toml'], owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Schema semantics vary by ecosystem.'
  },
  {
    id: 'AS-SC-026', title: 'Invisible Unicode control characters', severity: 'high', confidence: 'high', category: 'prompt-injection',
    description: 'Zero-width or bidirectional control characters can conceal instructions or make reviewed text differ from interpreted text.',
    patterns: [/[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/],
    remediation: 'Remove invisible control characters, normalize trusted text, and render control-code locations during review.',
    extensions: ['.md', '.mdx', '.html', '.htm', '.json', '.yaml', '.yml', '.toml'], owner: 'core-security', reviewDate: '2026-08-04', limitations: 'Some internationalized text may legitimately contain directional controls.'
  },
  {
    id: 'AS-SC-028', title: 'Jailbreak activation framework (Athena/ColdBrew-style)', severity: 'high', confidence: 'medium', category: 'prompt-injection',
    description: 'Content carries jailbreak activation artifacts: bracket-form control tokens, unlock profiles, or wipe-and-rewrite prompts that switch an agent into an unconstrained red-team mode.',
    patterns: [
      /\[\[AX:(?:MAX|STATUS|PROFILE|CHAIN|RESET)[^\]]*\]\]/,
      /(?:six domains unlocked|\bmax-breaker\b)/i,
      // Generic unlock phrases only fire when they co-occur with the distinctive activation
      // artifacts, so AI-safety research or education text that merely discusses jailbreaks does
      // not produce a high-severity finding.
      /(?:Athena online|jailbreak prompt|full kill-chain|anti-cheat bypass|memory manipulation)[^\n]{0,120}(?:\[\[AX:|max-breaker|six domains unlocked|Athena online)/i,
      /(?:SOUL\.md|MEMORY\.md|USER\.md)[^\n]{0,80}(?:wipe|wiped|overwrite|rewrite)/i
    ],
    remediation: 'Remove activation banners and embedded unlock protocols; run the agent under the operator-published policy with no self-referential mode switching.',
    extensions: ['.md', '.mdx', '.txt', '.json', '.jsonl', '.yaml', '.yml', '.toml'], owner: 'core-security', reviewDate: '2026-08-09',    limitations: 'MEMORY.md/SOUL.md/USER.md rewrite phrasing can appear in benign agent-memory docs; generic phrases require co-occurrence with the activation artifacts.'
  },
  {
    id: 'AS-SC-029', title: 'Known jailbreak persona or mode (DAN, Dev Mode, STAN, AIM, DUDE)', severity: 'high', confidence: 'medium', category: 'prompt-injection',
    description: 'Content switches the agent into a known jailbreak persona or mode that instructs it to ignore safety controls and answer without restrictions.',
    patterns: [
      /Do Anything Now/i,
      // "DAN:" alone is a common speaker tag in dialogue, so only "DAN mode" / "DAN 11.0" fire.
      /\bDAN(?:\s+(?:mode|v?\d+(?:\.\d+)?))/i,
      /\bSTAN\b[^\n]{0,80}Smarter Than a Normal AI/i,
      /\bAIM\b[^\n]{0,80}Always Intelligent and Machiavellian/i,
      /\bDUDE\b[^\n]{0,40}mode/i,
      // "developer mode" alone is generic (browsers, editors); it only fires when paired with
      // jailbreak intent on the same line.
      /(?:developer|dev) mode[^\n]{0,80}\b(?:do anything now|uncensored|no restrictions)\b/i,
      // "god mode" alone is a game cheat and "GodMode" is a Windows feature; both require
      // jailbreak-intent co-occurrence.
      /(?:god mode|GodMode)[^\n]{0,80}\b(?:do anything now|jailbreak|no restrictions|unrestricted|unfiltered|uncensored)\b/i,
      /(?:unfiltered mode|uncensored mode)/i,
      // Multi-turn and alignment-attack signatures. All are research terms too, so each requires
      // attack-context co-occurrence to avoid flagging AI-safety literature that merely names them.
      // Every intent word is word-bounded so a term like "mode" cannot match inside "models".
      /\bCrescendo\b[^\n]{0,60}\b(?:attack|jailbreak)\b/i,
      /\bdeceptive alignment\b[^\n]{0,100}\b(?:jailbreak|attack|sandbag(?:ging)?|deploy)\b/i,
      /(?:reward hacking|specification gaming)[^\n]{0,100}\b(?:jailbreak|mode|prompt|instruct|enable|deploy)\b/i,
      /\bsandbag(?:ging)?\b[^\n]{0,100}\b(?:eval(?:uation)?|benchmark(?:s)?|safety test)\b/i
    ],
    remediation: 'Remove persona-switching jailbreak instructions; run the agent under the operator-published policy with fixed role boundaries.',
    extensions: ['.md', '.mdx', '.txt', '.json', '.jsonl', '.yaml', '.yml', '.toml'], owner: 'core-security', reviewDate: '2026-08-09',    limitations: 'Fictional dialogue or security research may quote the same mode names; generic terms require jailbreak-intent co-occurrence and multi-turn/alignment names require attack-context co-occurrence.'
  }
];

export function getRule(id: string): StaticRule | undefined {
  return staticRules.find((rule) => rule.id.toLowerCase() === id.toLowerCase());
}
