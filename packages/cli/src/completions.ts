export type Shell = 'bash' | 'zsh' | 'fish';
export const SUPPORTED_SHELLS: readonly Shell[] = ['bash', 'zsh', 'fish'];

const COMMANDS = ['scan', 'scan-mcp', 'permissions', 'diff', 'policy', 'report', 'rules', 'explain', 'baseline', 'memory', 'persona', 'runtime', 'telemetry', 'completion'];
const PERSONA_SUBCOMMANDS = 'create list show render apply model verify applications remove';

const bash = `# AgentShield bash completion
_agentshield_completion() {
  local cur prev words cword
  _init_completion -n : || return
  local commands="${COMMANDS.join(' ')}"
  if [ "\$cword" -eq 1 ]; then
    COMPREPLY=( \$(compgen -W "\$commands" -- "\$cur") )
    return 0
  fi
  case "\${words[1]}" in
    scan|scan-mcp|permissions|diff|report|explain) COMPREPLY=( \$(compgen -f -- "\$cur") ); return 0 ;;
    policy) COMPREPLY=( \$(compgen -W "check simulate" -- "\$cur") ); return 0 ;;
    rules) COMPREPLY=( \$(compgen -W "list" -- "\$cur") ); return 0 ;;
    baseline) COMPREPLY=( \$(compgen -W "create add validate prune" -- "\$cur") ); return 0 ;;
    memory) COMPREPLY=( \$(compgen -W "audit quarantine restore quarantine-list" -- "\$cur") ); return 0 ;;
    persona) COMPREPLY=( \$(compgen -W "${PERSONA_SUBCOMMANDS}" -- "\$cur") ); return 0 ;;
    runtime) COMPREPLY=( \$(compgen -W "ingest trace" -- "\$cur") ); return 0 ;;
    telemetry) COMPREPLY=( \$(compgen -W "status enable disable preview" -- "\$cur") ); return 0 ;;
    completion) COMPREPLY=( \$(compgen -W "bash zsh fish" -- "\$cur") ); return 0 ;;
  esac
  return 0
}
complete -F _agentshield_completion agentshield
`;

const zsh = `#compdef agentshield
# AgentShield zsh completion
_agentshield() {
  local -a commands
  commands=(${COMMANDS.map((command) => `'${command}'`).join(' ')})
  if (( CURRENT == 2 )); then
    _describe 'command' commands
    return
  fi
  case \${words[2]} in
    scan|scan-mcp|permissions|diff|report|explain) _files ;;
    policy) _values 'subcommand' check simulate ;;
    rules) _values 'subcommand' list ;;
    baseline) _values 'subcommand' create add validate prune ;;
    memory) _values 'subcommand' audit quarantine restore quarantine-list ;;
    persona) _values 'subcommand' create list show render apply model verify applications remove ;;
    runtime) _values 'subcommand' ingest trace ;;
    telemetry) _values 'subcommand' status enable disable preview ;;
    completion) _values 'shell' bash zsh fish ;;
  esac
}
_agentshield "$@"
`;

const fish = `# AgentShield fish completion
complete -c agentshield -f
${COMMANDS.map((command) => `complete -c agentshield -n '__fish_use_subcommand' -a '${command}'`).join('\n')}
complete -c agentshield -n '__fish_seen_subcommand_from policy' -a 'check simulate'
complete -c agentshield -n '__fish_seen_subcommand_from rules' -a 'list'
complete -c agentshield -n '__fish_seen_subcommand_from baseline' -a 'create add validate prune'
complete -c agentshield -n '__fish_seen_subcommand_from memory' -a 'audit quarantine restore quarantine-list'
complete -c agentshield -n '__fish_seen_subcommand_from persona' -a '${PERSONA_SUBCOMMANDS}'
complete -c agentshield -n '__fish_seen_subcommand_from runtime' -a 'ingest trace'
complete -c agentshield -n '__fish_seen_subcommand_from telemetry' -a 'status enable disable preview'
complete -c agentshield -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c agentshield -n '__fish_seen_subcommand_from scan scan-mcp permissions diff report explain' -a '(__fish_complete_path)'
`;

const scripts: Record<Shell, string> = { bash, zsh, fish };

export function completionScript(shell: Shell): string {
  return scripts[shell];
}

export function isSupportedShell(value: string): value is Shell {
  return (SUPPORTED_SHELLS as readonly string[]).includes(value);
}
