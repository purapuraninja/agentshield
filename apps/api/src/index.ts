import { buildServer } from './server.js';

const host = process.env.AGENTSHIELD_HOST ?? '127.0.0.1';
const port = Number(process.env.AGENTSHIELD_PORT ?? 4141);

buildServer().then((app) => app.listen({ host, port })).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
