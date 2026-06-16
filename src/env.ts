import { createEnv } from 'typed-env';

export const env = createEnv({
  CLIENT_ID: { type: 'string' },
  CLIENT_SECRET: { type: 'string' },
  GWELL_SECRET: { type: 'string' },
  GWELL_WEBHOOK_URL: { type: 'string', optional: true },
  BASE_URL: { parser: s => new URL(s) },

  CRYPTO_KEY: { parser: s => Uint8Array.fromBase64(s) }
});
