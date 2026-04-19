import { env } from './env.ts';

const key = await crypto.subtle.importKey('raw', env.CRYPTO_KEY, 'AES-GCM', false, ['encrypt', 'decrypt']);

export function generateIv() {
  return crypto.getRandomValues(new Uint8Array(12));
}

export function encrypt(input: string, iv: NodeJS.BufferSource) {
  const encoded = new TextEncoder().encode(input);
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
}

export async function decrypt(ciphertext: NodeJS.BufferSource, iv: NodeJS.BufferSource) {
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}
