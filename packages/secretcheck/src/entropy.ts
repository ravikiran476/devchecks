/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export interface EntropyOptions {
  minLength: number;
  base64Threshold: number;
  hexThreshold: number;
}

export const DEFAULT_ENTROPY: EntropyOptions = { minLength: 20, base64Threshold: 4.5, hexThreshold: 3.0 };

const HEX = /^[0-9a-f]+$/i;
const B64 = /^[A-Za-z0-9+/=_-]+$/;

/** Returns true when a quoted string literal looks like a random credential. */
export function isHighEntropy(value: string, opts: EntropyOptions = DEFAULT_ENTROPY): boolean {
  if (value.length < opts.minLength) return false;
  // Words, paths and sentences are not secrets.
  if (/[\s./\\]/.test(value) && !/^[A-Za-z0-9+/=]+$/.test(value)) return false;
  if (/^[a-z]+(?:[-_][a-z]+)*$/i.test(value)) return false;
  // Require a mix of character classes so camelCase identifiers are skipped.
  const classes = [/[a-z]/, /[A-Z]/, /\d/].filter((r) => r.test(value)).length;
  if (HEX.test(value)) return value.length >= 32 && shannonEntropy(value) >= opts.hexThreshold;
  if (B64.test(value)) return classes >= 3 && shannonEntropy(value) >= opts.base64Threshold;
  return false;
}
