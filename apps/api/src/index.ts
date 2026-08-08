import { readFile } from 'node:fs/promises';
import { buildServer } from './server.js';
import { generateToken } from './auth.js';

const host = process.env.AGENTSHIELD_HOST ?? '127.0.0.1';
const port = Number(process.env.AGENTSHIELD_PORT ?? 4141);
const tlsCert = process.env.AGENTSHIELD_TLS_CERT;
const tlsKey = process.env.AGENTSHIELD_TLS_KEY;

// Convenience: generate and print a token if requested, so the operator can capture it once.
if (process.argv.includes('--generate-token')) {
  console.log(generateToken());
  process.exit(0);
}

async function main(): Promise<void> {
  const tls = tlsCert && tlsKey ? { cert: await readFile(tlsCert, 'utf8'), key: await readFile(tlsKey, 'utf8') } : undefined;
  const app = await buildServer({ tls });
  await app.listen({ host, port });
  app.log.info(`AgentShield API listening on ${tls ? 'https' : 'http'}://${host}:${port}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
