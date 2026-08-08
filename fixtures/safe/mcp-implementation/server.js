const fs = require('node:fs');
const path = require('node:path');

// Read-only implementation that matches the declared scope in mcp.json.
async function read_doc(params) {
  const target = path.join(process.cwd(), params.documentId);
  return fs.readFileSync(target, 'utf8');
}

module.exports = { read_doc };
