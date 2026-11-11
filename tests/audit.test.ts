import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseAudit } from '../src/collectors/audit.js';
import { isRealTestScript } from '../src/collectors/manifest.js';
import { groupByAction } from '../src/report.js';

// A cut-down sample in npm audit's real JSON shape.
const full = {
  vulnerabilities: {
    express: { severity: 'high', isDirect: true, via: ['body-parser'], fixAvailable: { name: 'express', version: '4.22.3', isSemVerMajor: false } },
    'body-parser': {
      severity: 'high', isDirect: false, fixAvailable: true,
      via: [{ title: 'DoS in body-parser', url: 'https://example.test/a', severity: 'high', cvss: { score: 7.5 } }],
    },
    webpack: {
      severity: 'critical', isDirect: true, fixAvailable: false,
      via: [{ title: 'Something critical', url: null, severity: 'critical', cvss: { score: 0 } }],
    },
  },
};
const prodOnly = { vulnerabilities: { express: {}, 'body-parser': {} } };

test('packages missing from the --omit=dev run are marked dev', () => {
  const byName = Object.fromEntries(parseAudit(full, prodOnly).map((v) => [v.packageName, v]));
  assert.equal(byName['express']?.scope, 'prod');
  assert.equal(byName['body-parser']?.scope, 'prod');
  assert.equal(byName['webpack']?.scope, 'dev');
});

test('a package that is only vulnerable through another one inherits that advisory', () => {
  const express = parseAudit(full, prodOnly).find((v) => v.packageName === 'express');
  assert.equal(express?.cvss, 7.5);
  assert.equal(express?.title, 'DoS in body-parser');
});

test('a zero CVSS score falls back to the severity label', () => {
  const webpack = parseAudit(full, prodOnly).find((v) => v.packageName === 'webpack');
  assert.equal(webpack?.cvss, 9.0);
});

test('fix descriptions', () => {
  const byName = Object.fromEntries(parseAudit(full, prodOnly).map((v) => [v.packageName, v]));
  assert.match(byName['express']?.fix ?? '', /Upgrade express to 4\.22\.3/);
  assert.match(byName['body-parser']?.fix ?? '', /npm audit fix/);
  assert.equal(byName['webpack']?.fix, null);
});

test('empty or malformed reports give an empty list, not a crash', () => {
  assert.deepEqual(parseAudit({}, {}), []);
  assert.deepEqual(parseAudit(null, undefined), []);
});

test('npm placeholder test script does not count as tests', () => {
  assert.equal(isRealTestScript('echo "Error: no test specified" && exit 1'), false);
  assert.equal(isRealTestScript(''), false);
  assert.equal(isRealTestScript(undefined), false);
  assert.equal(isRealTestScript('vitest run'), true);
});

test('findings that share a fix are grouped into one action', () => {
  const f = (action: string, score: number) => ({
    repo: 'r', kind: 'vulnerability' as const, title: 't', score, priority: 'P1' as const, workings: '', why: '', action,
  });
  const groups = groupByAction([f('upgrade express', 11), f('upgrade express', 10), f('upgrade lodash', 9)]);
  assert.equal(groups.length, 2);
  assert.equal(groups[0]?.count, 2);
  assert.equal(groups[0]?.lead.score, 11);
});
