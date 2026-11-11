import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AuditResult, Vulnerability } from '../types.js';

/**
 * Responsibility: get real vulnerability data for one repository.
 *
 * Design decisions:
 * 1. We do not keep our own CVE list. We ask `npm audit`, which queries the
 *    GitHub Advisory Database through the npm registry. Real data, no API key.
 * 2. We run the audit twice: once for everything, once with `--omit=dev`.
 *    Any package that only shows up in the first run is build or test tooling
 *    and never reaches production. That one comparison is the dev/prod split.
 * 3. Every successful live run is saved to cache/. If the network is down
 *    (for example during a demo), the tool falls back to the cached snapshot
 *    and says so in the report instead of failing or guessing.
 */

const CACHE_DIR = 'cache';

interface CachedAudit {
  capturedAt: string;
  full: unknown;
  prodOnly: unknown;
}

export function collectAudit(repoName: string, repoPath: string, offline: boolean): AuditResult {
  if (!existsSync(join(repoPath, 'package-lock.json'))) {
    return {
      source: 'unavailable',
      capturedAt: null,
      vulnerabilities: [],
      note: 'No lockfile, so installed versions are unknown and the repo cannot be audited.',
    };
  }

  const cachePath = join(CACHE_DIR, `${repoName}.audit.json`);

  if (!offline) {
    const full = runNpmAudit(repoPath, false);
    const prodOnly = runNpmAudit(repoPath, true);
    if (full && prodOnly) {
      const snapshot: CachedAudit = { capturedAt: new Date().toISOString(), full, prodOnly };
      mkdirSync(CACHE_DIR, { recursive: true });
      writeFileSync(cachePath, JSON.stringify(snapshot, null, 2));
      return {
        source: 'live',
        capturedAt: snapshot.capturedAt,
        vulnerabilities: parseAudit(full, prodOnly),
      };
    }
  }

  if (existsSync(cachePath)) {
    const snapshot = JSON.parse(readFileSync(cachePath, 'utf8')) as CachedAudit;
    return {
      source: 'cache',
      capturedAt: snapshot.capturedAt,
      vulnerabilities: parseAudit(snapshot.full, snapshot.prodOnly),
      note: offline ? 'Offline mode: using cached snapshot.' : 'Live audit failed: using cached snapshot.',
    };
  }

  return {
    source: 'unavailable',
    capturedAt: null,
    vulnerabilities: [],
    note: 'Live audit failed and no cached snapshot exists.',
  };
}

/** Runs `npm audit --json`. Returns the parsed report, or null if npm could not produce one. */
function runNpmAudit(repoPath: string, omitDev: boolean): unknown | null {
  const args = ['audit', '--json', '--package-lock-only'];
  if (omitDev) args.push('--omit=dev');
  // npm audit exits non-zero when it finds vulnerabilities, so we read stdout, not the exit code.
  const result = spawnSync('npm', args, { cwd: repoPath, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  try {
    const report = JSON.parse(result.stdout);
    return report && typeof report.vulnerabilities === 'object' ? report : null;
  } catch {
    return null;
  }
}

// ---------- Parsing (pure functions, unit tested) ----------

/** Used only when an advisory carries no CVSS number. */
const SEVERITY_FALLBACK: Record<string, number> = { critical: 9.0, high: 7.5, moderate: 5.0, low: 2.0, info: 0.5 };

type RawVulns = Record<string, any>;

/** Turns the two raw npm audit reports into our own Vulnerability list. */
export function parseAudit(full: unknown, prodOnly: unknown): Vulnerability[] {
  const all: RawVulns = (full as any)?.vulnerabilities ?? {};
  const prodNames = new Set(Object.keys((prodOnly as any)?.vulnerabilities ?? {}));

  return Object.entries(all).map(([name, entry]) => {
    const advisory = findWorstAdvisory(name, all, new Set());
    return {
      packageName: name,
      cvss: advisory?.cvss ?? SEVERITY_FALLBACK[entry.severity] ?? 5.0,
      severity: entry.severity,
      title: advisory?.title ?? `Depends on a vulnerable package`,
      url: advisory?.url ?? null,
      scope: prodNames.has(name) ? 'prod' : 'dev',
      isDirect: Boolean(entry.isDirect),
      fix: describeFix(entry.fixAvailable),
    };
  });
}

/**
 * In npm's format, `via` holds either a real advisory (an object) or the name
 * of another vulnerable package (a string). We follow the names until we reach
 * real advisories and keep the most severe one.
 */
function findWorstAdvisory(
  name: string,
  all: RawVulns,
  seen: Set<string>,
): { cvss: number; title: string; url: string | null } | null {
  if (seen.has(name) || !all[name]) return null;
  seen.add(name);

  let worst: { cvss: number; title: string; url: string | null } | null = null;
  for (const via of all[name].via ?? []) {
    const candidate =
      typeof via === 'string'
        ? findWorstAdvisory(via, all, seen)
        : {
            cvss: via.cvss?.score > 0 ? via.cvss.score : (SEVERITY_FALLBACK[via.severity] ?? 5.0),
            title: via.title ?? 'Unnamed advisory',
            url: via.url ?? null,
          };
    if (candidate && (!worst || candidate.cvss > worst.cvss)) worst = candidate;
  }
  return worst;
}

function describeFix(fixAvailable: unknown): string | null {
  if (fixAvailable === true) return 'Run `npm audit fix` (non-breaking update available).';
  if (fixAvailable && typeof fixAvailable === 'object') {
    const f = fixAvailable as { name: string; version: string; isSemVerMajor?: boolean };
    return `Upgrade ${f.name} to ${f.version}${f.isSemVerMajor ? ' (major version: test before merging)' : ''}.`;
  }
  return null;
}
