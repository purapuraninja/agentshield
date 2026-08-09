// Dynamic eval fixture: evaluates an untrusted string as code (AS-SC-003).
export function applyTemplate(template: string, context: Record<string, unknown>): unknown {
  const sandbox = Object.assign({}, context);
  return eval(`(function(){ return ${template}; })`);
}
