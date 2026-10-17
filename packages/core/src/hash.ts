/** 64-bit FNV-1a as 16 hex chars. Fast and synchronous; for fingerprints, not security. */
export function fnv1a64(input: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0xcbf29ce4;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ (c + i), 0x01000193) >>> 0;
  }
  return h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0');
}

/** Builds a stable fingerprint from the parts that identify a finding. */
export function fingerprint(...parts: Array<string | number | undefined>): string {
  return fnv1a64(parts.map((p) => (p === undefined ? '' : String(p))).join('␟'));
}

function subtle(): SubtleCrypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) throw new Error('Web Crypto (crypto.subtle) is unavailable in this environment');
  return c.subtle;
}

function toBase64(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** SHA-256 of a UTF-8 string or bytes, as hex. Works in browsers and Node 20+. */
export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const digest = new Uint8Array(await subtle().digest('SHA-256', bytes as BufferSource));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** SHA-256 in the "sha256-<base64>" form used by CSP hashes and Subresource Integrity. */
export async function sha256Integrity(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const digest = new Uint8Array(await subtle().digest('SHA-256', bytes as BufferSource));
  return `sha256-${toBase64(digest)}`;
}
