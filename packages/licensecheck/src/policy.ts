import { leaves, parseExpression, type Expr } from './spdx.js';

export type Category =
  | 'permissive'
  | 'weak-copyleft'
  | 'strong-copyleft'
  | 'network-copyleft'
  | 'source-available'
  | 'non-commercial'
  | 'proprietary'
  | 'unknown';

export type Verdict = 'allowed' | 'review' | 'denied';

const PERMISSIVE = /^(MIT|MIT-0|ISC|0BSD|BSD-[1-4]-Clause.*|BSD-Source-Code|Apache-[12]\.\d|Zlib|Unlicense|CC0-1\.0|WTFPL|X11|BSL-1\.0|Python-2\.0.*|PSF-2\.0|BlueOak-1\.0\.0|CC-BY-[34]\.0|Artistic-2\.0|OFL-1\.1|Unicode-.*|PostgreSQL|NCSA|UPL-1\.0|MS-PL|AFL-[23]\.\d|LicenseRef-Public-Domain|ICU|W3C.*|curl|Beerware)$/i;
const WEAK = /^(LGPL-.*|MPL-[12]\.\d.*|EPL-[12]\.0|CDDL-1\.[01]|CPL-1\.0|MS-RL|EUPL-1\.[12]|CC-BY-SA-[34]\.0|Ruby|OSL-3\.0)$/i;
const STRONG = /^(GPL-.*|CECILL-.*)$/i;
const NETWORK = /^(AGPL-.*|SSPL-1\.0|RPL-1\.5)$/i;
const SOURCE_AVAILABLE = /^(BUSL-1\.1|Elastic-2\.0|LicenseRef-Commons-Clause|Commons-Clause|PolyForm-.*|Confluent-Community.*)$/i;
const NON_COMMERCIAL = /^CC-BY-NC.*$/i;

/** Exceptions that turn copyleft licenses into linking-friendly ones. */
const LINKING_EXCEPTIONS = /^(Classpath-exception-2\.0|GCC-exception-.*|LLVM-exception|Autoconf-exception-.*|Bison-exception-.*|Font-exception-2\.0)$/i;

export function categorize(id: string, exception?: string): Category {
  if (id === 'LicenseRef-Proprietary') return 'proprietary';
  if (id === 'LicenseRef-Unknown' || id === 'LicenseRef-Custom') return 'unknown';
  if (PERMISSIVE.test(id)) return 'permissive';
  if (NETWORK.test(id)) return 'network-copyleft';
  if (STRONG.test(id)) return exception && LINKING_EXCEPTIONS.test(exception) ? 'weak-copyleft' : 'strong-copyleft';
  if (WEAK.test(id)) return 'weak-copyleft';
  if (SOURCE_AVAILABLE.test(id)) return 'source-available';
  if (NON_COMMERCIAL.test(id)) return 'non-commercial';
  return 'unknown';
}

export interface LicensePolicy {
  /** License ids that are always allowed. When set, other licenses need review unless denied. */
  allow?: string[];
  /** License ids that are never allowed. */
  deny?: string[];
  /** License ids that need a human decision. */
  review?: string[];
  denyCategories?: Category[];
  reviewCategories?: Category[];
  /** Accepted packages, e.g. a GPL dev tool that is never distributed. */
  exceptions?: Array<{ package: string; version?: string; reason?: string }>;
}

/** Suitable for proprietary software that is distributed or offered as a service. */
export const DEFAULT_POLICY: LicensePolicy = {
  denyCategories: ['strong-copyleft', 'network-copyleft', 'non-commercial', 'proprietary'],
  reviewCategories: ['weak-copyleft', 'source-available', 'unknown'],
};

export const POLICIES: Record<'permissive' | 'strict' | 'copyleft-ok', LicensePolicy> = {
  permissive: DEFAULT_POLICY,
  strict: { ...DEFAULT_POLICY, denyCategories: [...DEFAULT_POLICY.denyCategories!, 'source-available', 'unknown'] },
  'copyleft-ok': { denyCategories: ['non-commercial', 'proprietary'], reviewCategories: ['network-copyleft', 'source-available', 'unknown'] },
};

const RANK: Record<Verdict, number> = { allowed: 0, review: 1, denied: 2 };

export interface Evaluation {
  verdict: Verdict;
  /** The license that decided the verdict (for OR, the best acceptable alternative). */
  license: string;
  category: Category;
}

function evaluateLeaf(id: string, exception: string | undefined, policy: LicensePolicy): Evaluation {
  const category = categorize(id, exception);
  const lc = (xs?: string[]) => (xs ?? []).map((x) => x.toLowerCase());
  const key = id.toLowerCase();
  let verdict: Verdict = 'allowed';
  if (lc(policy.deny).includes(key)) verdict = 'denied';
  else if (lc(policy.allow).includes(key)) verdict = 'allowed';
  else if (lc(policy.review).includes(key)) verdict = 'review';
  else if (policy.denyCategories?.includes(category)) verdict = 'denied';
  else if (policy.reviewCategories?.includes(category)) verdict = 'review';
  else if (policy.allow?.length) verdict = 'review';
  return { verdict, license: exception ? `${id} WITH ${exception}` : id, category };
}

/** OR picks the most acceptable alternative; AND requires every part to be acceptable. */
export function evaluate(expression: string | Expr, policy: LicensePolicy = DEFAULT_POLICY): Evaluation {
  const expr = typeof expression === 'string' ? parseExpression(expression) : expression;
  if ('license' in expr) return evaluateLeaf(expr.license, expr.exception, policy);
  const parts = ('and' in expr ? expr.and : expr.or).map((e) => evaluate(e, policy));
  const pick = 'or' in expr ? parts.reduce((a, b) => (RANK[b.verdict] < RANK[a.verdict] ? b : a)) : parts.reduce((a, b) => (RANK[b.verdict] > RANK[a.verdict] ? b : a));
  return pick;
}

export function categoriesOf(expression: string): Category[] {
  try {
    return [...new Set(leaves(parseExpression(expression)).map((l) => categorize(l.license, l.exception)))];
  } catch {
    return ['unknown'];
  }
}
