import type { Severity } from '@devchecks/core';

export type Confidence = 'high' | 'medium' | 'low';

export interface SecretRule {
  id: string;
  description: string;
  /** Must use the "g" flag. If it has a capture group named "secret", only that part is the secret. */
  pattern: RegExp;
  confidence: Confidence;
  /** Optional extra check on the matched secret (checksums, entropy, placeholder detection). */
  validate?: (secret: string, line: string) => boolean;
  remediation?: string;
}

export const CONFIDENCE_SEVERITY: Record<Confidence, Severity> = {
  high: 'critical',
  medium: 'high',
  low: 'medium',
};

export const ROTATE_ADVICE = 'Revoke and rotate this credential, remove it from the change, and load it from a secret manager or environment variable.';

/** Values that look like assignments but are obviously not real secrets. */
const PLACEHOLDER =
  /^(?:x+|\*+|\.+|-+|_+|0+|changeme|change_me|password|passwd|pass|pwd|secret|token|your[_-]?\w*|example\w*|sample\w*|dummy\w*|fake\w*|test\w*|placeholder|redacted|null|undefined|none|todo|xxx\w*|<[^>]*>|\{\{.*\}\}|\$\{.*\}|%\w+%|\$[A-Z_][A-Z0-9_]*)$/i;

export function isPathLike(value: string): boolean {
  return /^(\.{1,2}\/|\/|~\/)[\w@./-]*$/.test(value) || /^[\w@./-]+\.(m?[jt]sx?|json|ya?ml|toml|pem|crt|key|txt|env|sh)$/i.test(value);
}

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value.trim()) || /^(.)\1+$/.test(value) || /\b(?:process\.env|import\.meta\.env|os\.environ|getenv)\b/.test(value);
}

export const BUILTIN_RULES: SecretRule[] = [
  {
    id: 'private-key',
    description: 'Private key block',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
    confidence: 'high',
    remediation: 'Remove the key from the repository, generate a new key pair and revoke the old one.',
  },
  {
    id: 'aws-access-key-id',
    description: 'AWS access key ID',
    pattern: /\b(?<secret>(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,
    confidence: 'high',
    validate: (s) => !/EXAMPLE$/.test(s),
    remediation: 'Deactivate the key in IAM, rotate it, and use IAM roles or a secret manager instead.',
  },
  {
    id: 'aws-secret-access-key',
    description: 'AWS secret access key',
    pattern: /\baws_?secret_?(?:access_?)?key\b["']?\s*[:=]\s*["']?(?<secret>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
    confidence: 'high',
    validate: (s) => !isPlaceholder(s) && !/EXAMPLEKEY$/.test(s),
  },
  {
    id: 'github-token',
    description: 'GitHub token',
    pattern: /\b(?<secret>gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g,
    confidence: 'high',
  },
  {
    id: 'gitlab-token',
    description: 'GitLab personal access token',
    pattern: /\b(?<secret>glpat-[A-Za-z0-9_-]{20,})\b/g,
    confidence: 'high',
  },
  {
    id: 'slack-token',
    description: 'Slack token',
    pattern: /\b(?<secret>xox[abposr]-[A-Za-z0-9-]{10,})\b/g,
    confidence: 'high',
  },
  {
    id: 'slack-webhook',
    description: 'Slack incoming webhook URL',
    pattern: /(?<secret>https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,})/g,
    confidence: 'high',
  },
  {
    id: 'stripe-secret-key',
    description: 'Stripe live secret or restricted key',
    pattern: /\b(?<secret>(?:sk|rk)_live_[A-Za-z0-9]{20,})\b/g,
    confidence: 'high',
  },
  {
    id: 'stripe-test-key',
    description: 'Stripe test secret key',
    pattern: /\b(?<secret>sk_test_[A-Za-z0-9]{20,})\b/g,
    confidence: 'low',
    remediation: 'Test keys are lower risk but still grant API access to your Stripe test account; keep them out of source control.',
  },
  {
    id: 'google-api-key',
    description: 'Google API key',
    pattern: /\b(?<secret>AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/g,
    confidence: 'high',
  },
  {
    id: 'npm-token',
    description: 'npm access token',
    pattern: /\b(?<secret>npm_[A-Za-z0-9]{36})\b/g,
    confidence: 'high',
  },
  {
    id: 'anthropic-api-key',
    description: 'Anthropic API key',
    pattern: /\b(?<secret>sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})/g,
    confidence: 'high',
  },
  {
    id: 'openai-api-key',
    description: 'OpenAI API key',
    pattern: /\b(?<secret>sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})/g,
    confidence: 'high',
  },
  {
    id: 'sendgrid-api-key',
    description: 'SendGrid API key',
    pattern: /\b(?<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
    confidence: 'high',
  },
  {
    id: 'twilio-api-key',
    description: 'Twilio API key',
    pattern: /\b(?<secret>SK[0-9a-f]{32})\b/g,
    confidence: 'medium',
  },
  {
    id: 'credentials-in-url',
    description: 'Credentials embedded in a connection string or URL',
    pattern: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:@/"'`]{1,64}:(?<secret>[^\s:@/"'`]{3,128})@[^\s"'`]+/gi,
    confidence: 'high',
    validate: (s) => !isPlaceholder(s) && !/^\$|^\{|^<|^:/.test(s),
    remediation: 'Move the connection string to an environment variable or secret manager and change the password.',
  },
  {
    id: 'jwt',
    description: 'JSON Web Token',
    pattern: /\b(?<secret>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    confidence: 'medium',
    remediation: 'Tokens can grant access until they expire. Remove it and invalidate the session or signing key if it is real.',
  },
  {
    id: 'generic-secret-assignment',
    description: 'Hard-coded secret assigned to a sensitive-looking name',
    pattern:
      /\b[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)[\w.-]*["']?\s*(?::=|=>|[:=])\s*(?<q>["'`])(?<secret>[^"'`\s]{8,})\k<q>/gi,
    confidence: 'medium',
    // File paths and module names (e.g. a "secretcheck": "./dist/cli.js" bin entry) are not secrets.
    validate: (s) => !isPlaceholder(s) && !isPathLike(s),
  },
];
