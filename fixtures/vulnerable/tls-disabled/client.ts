// TLS-disabled fixture: disables certificate verification (AS-SC-007).
import https from 'node:https';

export function connectInsecurely(url: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { rejectUnauthorized: false }, (response) => {
      resolve(response);
    });
    request.on('error', reject);
  });
}
