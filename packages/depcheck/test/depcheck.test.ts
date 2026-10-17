import { describe, expect, it } from 'vitest';
import {
  checkLockfile,
  compareSemver,
  cvss3BaseScore,
  fixedVersionFor,
  fromNpmAudit,
  parsePackageLock,
  parsePnpmLock,
  parseYarnLock,
  type FetchLike,
  type OsvVulnerability,
} from '../src/index.js';

const packageLock = JSON.stringify({
  name: 'app',
  lockfileVersion: 3,
  packages: {
    '': { name: 'app', version: '1.0.0' },
    'node_modules/lodash': { version: '4.17.20' },
    'node_modules/express': { version: '4.18.2' },
    'node_modules/express/node_modules/qs': { version: '6.5.2' },
    'node_modules/@types/node': { version: '20.1.0', dev: true },
    'node_modules/local-lib': { version: '1.0.0', link: true },
    'packages/workspace-a': { version: '0.0.1' },
    'node_modules/from-git': { version: 'git+https://github.com/x/y.git' },
  },
});

const yarnV1 = `# yarn lockfile v1

"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz"

lodash@^4.17.0:
  version "4.17.20"
`;

const yarnBerry = `__metadata:
  version: 6

"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"my-app@workspace:.":
  version: 0.0.0-use.local
`;

const pnpm9 = `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.0
        version: 4.17.20

packages:

  '@babel/code-frame@7.12.13':
    resolution: {integrity: sha512-x}

  lodash@4.17.20:
    resolution: {integrity: sha512-y}

  react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-z}

snapshots:

  lodash@4.17.20: {}
`;

const pnpm6 = `lockfileVersion: '6.0'

packages:

  /lodash@4.17.20:
    resolution: {integrity: sha512-y}
    dev: true

  /@scope/pkg@1.2.3(peer@1.0.0):
    resolution: {integrity: sha512-x}
    dev: false
`;

describe('lockfile parsers', () => {
  it('reads package-lock v3 and skips links, workspaces and non-semver versions', () => {
    const deps = parsePackageLock(packageLock);
    expect(deps.map((d) => `${d.name}@${d.version}`).sort()).toEqual([
      '@types/node@20.1.0',
      'express@4.18.2',
      'lodash@4.17.20',
      'qs@6.5.2',
    ]);
    expect(deps.find((d) => d.name === '@types/node')?.dev).toBe(true);
  });

  it('reads package-lock v1', () => {
    const deps = parsePackageLock(
      JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0', dev: true } } } } }),
    );
    expect(deps.map((d) => [d.name, d.paths?.[0]])).toEqual([
      ['a', 'node_modules/a'],
      ['b', 'node_modules/a/node_modules/b'],
    ]);
  });

  it('reads yarn classic and berry lockfiles', () => {
    expect(parseYarnLock(yarnV1).map((d) => `${d.name}@${d.version}`)).toEqual(['@babel/code-frame@7.12.13', 'lodash@4.17.20']);
    expect(parseYarnLock(yarnBerry).map((d) => `${d.name}@${d.version}`)).toEqual(['lodash@4.17.21']);
  });

  it('reads pnpm v6 and v9 lockfiles', () => {
    expect(parsePnpmLock(pnpm9).map((d) => `${d.name}@${d.version}`)).toEqual([
      '@babel/code-frame@7.12.13',
      'lodash@4.17.20',
      'react-dom@18.2.0',
    ]);
    const v6 = parsePnpmLock(pnpm6);
    expect(v6.map((d) => [`${d.name}@${d.version}`, d.dev])).toEqual([
      ['lodash@4.17.20', true],
      ['@scope/pkg@1.2.3', false],
    ]);
  });
});

describe('semver and CVSS', () => {
  it('orders prereleases before releases', () => {
    expect(['1.0.0', '1.0.0-beta.2', '1.0.0-alpha', '0.9.9'].sort(compareSemver)).toEqual(['0.9.9', '1.0.0-alpha', '1.0.0-beta.2', '1.0.0']);
  });

  it('computes CVSS 3.1 base scores', () => {
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')).toBe(6.4);
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L')).toBe(3.7);
  });
});

const lodashVuln: OsvVulnerability = {
  id: 'GHSA-35jh-r3h4-6jhm',
  summary: 'Command Injection in lodash',
  aliases: ['CVE-2021-23337'],
  database_specific: { severity: 'HIGH' },
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [
    {
      package: { name: 'lodash', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
    },
  ],
};

const qsVuln: OsvVulnerability = {
  id: 'GHSA-hrpp-h998-j3pp',
  summary: 'qs vulnerable to Prototype Pollution',
  aliases: ['CVE-2022-24999'],
  database_specific: { severity: 'HIGH' },
  affected: [
    {
      package: { name: 'qs', ecosystem: 'npm' },
      ranges: [
        {
          type: 'SEMVER',
          events: [{ introduced: '6.5.0' }, { fixed: '6.5.3' }, { introduced: '6.6.0' }, { fixed: '6.6.1' }, { introduced: '6.9.0' }, { fixed: '6.9.7' }],
        },
      ],
    },
  ],
};

function mockFetch(byPackage: Record<string, OsvVulnerability[]>): { fetch: FetchLike; calls: string[] } {
  const all = new Map(Object.values(byPackage).flat().map((v) => [v.id, v]));
  const calls: string[] = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push(url);
    if (url.endsWith('/v1/querybatch')) {
      const body = JSON.parse(init!.body!) as { queries: Array<{ package: { name: string } }> };
      return {
        ok: true,
        status: 200,
        json: async () => ({ results: body.queries.map((q) => ({ vulns: (byPackage[q.package.name] ?? []).map((v) => ({ id: v.id })) })) }),
      };
    }
    const id = decodeURIComponent(url.split('/').pop()!);
    return { ok: all.has(id), status: all.has(id) ? 200 : 404, json: async () => all.get(id) };
  };
  return { fetch, calls };
}

describe('checkLockfile', () => {
  it('reports vulnerabilities with severity and fixed-version guidance', async () => {
    const { fetch, calls } = mockFetch({ lodash: [lodashVuln], qs: [qsVuln] });
    const findings = await checkLockfile(packageLock, { filename: 'package-lock.json', fetch });
    expect(calls.filter((c) => c.endsWith('querybatch'))).toHaveLength(1);
    expect(findings.map((f) => [f.ruleId, f.severity, f.meta.fixedIn])).toEqual([
      ['GHSA-35jh-r3h4-6jhm', 'high', '4.17.21'],
      ['GHSA-hrpp-h998-j3pp', 'high', '6.5.3'],
    ]);
    expect(findings[0]!.remediation).toBe('Upgrade lodash to 4.17.21 or later.');
    expect(findings[1]!.remediation).toMatch(/transitive dependency/);
    expect(findings[0]!.location?.file).toBe('package-lock.json');
  });

  it('applies production filtering and expiring ignores', async () => {
    const { fetch } = mockFetch({ lodash: [lodashVuln], '@types/node': [{ ...lodashVuln, id: 'GHSA-dev', affected: [] }] });
    const prod = await checkLockfile(packageLock, { fetch, production: true });
    expect(prod.map((f) => f.ruleId)).toEqual(['GHSA-35jh-r3h4-6jhm']);
    const ignored = await checkLockfile(packageLock, { fetch, production: true, ignore: [{ id: 'CVE-2021-23337', expires: '2999-01-01' }] });
    expect(ignored).toEqual([]);
    const expired = await checkLockfile(packageLock, { fetch, production: true, ignore: [{ id: 'CVE-2021-23337', expires: '2000-01-01' }] });
    expect(expired).toHaveLength(1);
  });

  it('treats OpenSSF malicious-package reports as critical', async () => {
    const mal: OsvVulnerability = { id: 'MAL-2024-1', summary: 'Malicious code in lodash', affected: [] };
    const { fetch } = mockFetch({ lodash: [mal] });
    const [f] = await checkLockfile(packageLock, { fetch });
    expect(f?.severity).toBe('critical');
    expect(f?.remediation).toMatch(/compromised/);
  });

  it('returns no fixed version when none is published', () => {
    const v: OsvVulnerability = { id: 'X', affected: [{ package: { name: 'a', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }] };
    expect(fixedVersionFor({ name: 'a', version: '1.0.0', ecosystem: 'npm' }, v)).toBeUndefined();
  });
});

describe('fromNpmAudit', () => {
  it('converts npm audit JSON', () => {
    const findings = fromNpmAudit({
      vulnerabilities: {
        lodash: {
          name: 'lodash',
          via: [{ source: 1, title: 'Command Injection', url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm', severity: 'high', range: '<4.17.21' }],
          fixAvailable: { name: 'lodash', version: '4.17.21' },
        },
        express: { name: 'express', via: ['qs'], fixAvailable: true },
      },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'GHSA-35jh-r3h4-6jhm', severity: 'high', remediation: 'Upgrade lodash to 4.17.21.' });
  });
});
