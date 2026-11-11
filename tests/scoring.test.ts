import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isNodeEol, lowestNodeMajor, rank, scoreHygiene, scoreVulnerability, toPriority } from '../src/scoring.js';
import type { Manifest, RepoConfig, Vulnerability } from '../src/types.js';

const publicApi: RepoConfig = { name: 'api', path: '.', exposure: 'PUBLIC_INTERNET' };
const batchJob: RepoConfig = { name: 'batch', path: '.', exposure: 'INTERNAL_BATCH' };

const vuln = (over: Partial<Vulnerability>): Vulnerability => ({
  packageName: 'pkg', cvss: 7.5, severity: 'high', title: 't', url: null,
  scope: 'prod', isDirect: true, fix: null, ...over,
});

const healthy: Manifest = {
  name: 'x', hasLockfile: true, hasRealTestScript: true, hasCiWorkflow: true,
  nodeEngine: '>=22', prodDependencyCount: 1, devDependencyCount: 1,
};

test('priority thresholds', () => {
  assert.equal(toPriority(9), 'P1');
  assert.equal(toPriority(8.9), 'P2');
  assert.equal(toPriority(6), 'P2');
  assert.equal(toPriority(3), 'P3');
  assert.equal(toPriority(2.9), 'P4');
});

test('a high CVE in production on a public API is P1', () => {
  const f = scoreVulnerability(publicApi, vuln({ cvss: 7.5, scope: 'prod' }));
  assert.equal(f.score, 11.3);
  assert.equal(f.priority, 'P1');
});

test('a critical CVE in dev tooling on an internal batch job is P4', () => {
  const f = scoreVulnerability(batchJob, vuln({ cvss: 9.8, scope: 'dev' }));
  assert.equal(f.score, 1.2);
  assert.equal(f.priority, 'P4');
});

test('the same CVE ranks higher on the more exposed system', () => {
  const v = vuln({ cvss: 6.0 });
  assert.ok(scoreVulnerability(publicApi, v).score > scoreVulnerability(batchJob, v).score);
});

test('a missing fix is stated, not hidden', () => {
  assert.match(scoreVulnerability(publicApi, vuln({ fix: null })).action, /No fixed version/);
});

test('node engine parsing and end-of-life', () => {
  assert.equal(lowestNodeMajor('>=16'), 16);
  assert.equal(lowestNodeMajor('^20.1.0 || >=22'), 20);
  assert.equal(lowestNodeMajor(null), null);
  const nov2026 = new Date('2026-11-13');
  assert.equal(isNodeEol(20, nov2026), true);
  assert.equal(isNodeEol(22, nov2026), false);
  assert.equal(isNodeEol(22, new Date('2027-06-01')), true);
});

test('a healthy repo has no hygiene findings', () => {
  assert.deepEqual(scoreHygiene(publicApi, healthy, new Date('2026-11-13')), []);
});

test('hygiene gaps are found and scaled by exposure', () => {
  const messy: Manifest = { ...healthy, hasLockfile: false, hasRealTestScript: false, hasCiWorkflow: false, nodeEngine: '>=16' };
  const onApi = scoreHygiene(publicApi, messy, new Date('2026-11-13'));
  const onBatch = scoreHygiene(batchJob, messy, new Date('2026-11-13'));
  assert.equal(onApi.length, 4);
  assert.equal(onApi.find((f) => f.title === 'No lockfile committed')?.priority, 'P1');
  assert.equal(onBatch.find((f) => f.title === 'No lockfile committed')?.priority, 'P3');
});

test('rank puts the highest score first', () => {
  const ranked = rank([
    scoreVulnerability(batchJob, vuln({ cvss: 9.8, scope: 'dev' })),
    scoreVulnerability(publicApi, vuln({ cvss: 7.5 })),
  ]);
  assert.equal(ranked[0]?.repo, 'api');
});
