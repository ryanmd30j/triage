import type { Exposure, Finding, Manifest, Priority, RepoConfig, Vulnerability } from './types.js';

/**
 * Responsibility: turn facts into a ranked list. This is the only file that
 * contains opinion, and every opinion is a named constant below.
 *
 * The idea in one line:
 *
 *     score = severity  x  exposure  x  reach
 *
 * severity : how bad the flaw is in theory (CVSS 0 to 10)
 * exposure : who can reach the system it lives in
 * reach    : whether the vulnerable code runs in production at all
 *
 * A raw CVE count treats all three as equal. This tool does not.
 * The weights are judgement calls, not measurements. They are kept in one
 * place so a team can argue about them and change them.
 */

export const EXPOSURE_WEIGHT: Record<Exposure, number> = {
  PUBLIC_INTERNET: 1.5, // anyone on the internet can send it input
  LIBRARY: 1.2, // ships inside other products, so the blast radius is unknown
  INTERNAL_SERVICE: 1.0, // reachable only from inside the network
  INTERNAL_BATCH: 0.6, // no inbound traffic at all
};

export const REACH_WEIGHT = {
  prod: 1.0, // installed and running for real users
  dev: 0.2, // build and test tooling only. Not zero: a compromised build tool is still a supply-chain risk.
} as const;

/** Score needed for each priority. P1 is what fails the CI gate. */
export const THRESHOLDS = { P1: 9, P2: 6, P3: 3 } as const;

export function toPriority(score: number): Priority {
  if (score >= THRESHOLDS.P1) return 'P1';
  if (score >= THRESHOLDS.P2) return 'P2';
  if (score >= THRESHOLDS.P3) return 'P3';
  return 'P4';
}

const round1 = (n: number) => Math.round(n * 10) / 10;

export function scoreVulnerability(repo: RepoConfig, v: Vulnerability): Finding {
  const exposure = EXPOSURE_WEIGHT[repo.exposure];
  const reach = REACH_WEIGHT[v.scope];
  const score = round1(v.cvss * exposure * reach);

  const where = v.scope === 'prod' ? 'runs in production' : 'is build/test tooling only and never ships';
  const how = v.isDirect ? 'a direct dependency' : 'pulled in indirectly by another package';

  return {
    repo: repo.name,
    kind: 'vulnerability',
    title: `${v.packageName}: ${v.title}`,
    score,
    priority: toPriority(score),
    workings: `CVSS ${v.cvss} x exposure ${exposure} (${repo.exposure}) x reach ${reach} (${v.scope})`,
    why: `${v.packageName} is ${how} and ${where}.`,
    action: v.fix ?? 'No fixed version exists. Replace the package, or isolate and monitor it.',
  };
}

// ---------- Engineering hygiene ----------

/**
 * Node.js end-of-life dates, from the official release schedule
 * (https://github.com/nodejs/release#release-schedule).
 * Kept as a small dated table on purpose: it changes once a year and is easy to check.
 */
export const NODE_EOL: Record<number, string> = {
  10: '2021-04-30',
  12: '2022-04-30',
  14: '2023-04-30',
  16: '2023-09-11',
  18: '2025-04-30',
  20: '2026-04-30',
  22: '2027-04-30',
  24: '2028-04-30',
};

/** Returns the lowest Node major a repo says it supports, e.g. ">=16" -> 16. */
export function lowestNodeMajor(engine: string | null): number | null {
  const match = engine?.match(/\d+/);
  return match ? parseInt(match[0], 10) : null;
}

export function isNodeEol(major: number, today: Date): boolean {
  const eol = NODE_EOL[major];
  if (!eol) return major < 10; // unknown newer versions are assumed supported
  return new Date(eol) < today;
}

/** Base scores for hygiene gaps, on the same 0 to 10 scale as CVSS so the two can be ranked together. */
export const HYGIENE_BASE = {
  noLockfile: 6.5,
  eolRuntime: 6.0,
  noTests: 5.0,
  noCi: 3.0,
  noEngine: 2.0,
} as const;

export function scoreHygiene(repo: RepoConfig, m: Manifest, today: Date = new Date()): Finding[] {
  const exposure = EXPOSURE_WEIGHT[repo.exposure];
  const findings: Finding[] = [];

  const add = (title: string, base: number, why: string, action: string) => {
    const score = round1(base * exposure);
    findings.push({
      repo: repo.name,
      kind: 'hygiene',
      title,
      score,
      priority: toPriority(score),
      workings: `base ${base} x exposure ${exposure} (${repo.exposure})`,
      why,
      action,
    });
  };

  if (!m.hasLockfile) {
    add(
      'No lockfile committed',
      HYGIENE_BASE.noLockfile,
      'Installed versions can change between builds, and the repo cannot be audited at all. Its real risk is unknown.',
      'Run `npm install` and commit package-lock.json.',
    );
  }

  const major = lowestNodeMajor(m.nodeEngine);
  if (major === null) {
    add(
      'Node.js version not declared',
      HYGIENE_BASE.noEngine,
      'Without an "engines" field nobody can tell which runtime this is meant to run on.',
      'Add "engines": { "node": ">=22" } to package.json.',
    );
  } else if (isNodeEol(major, today)) {
    add(
      `Supports end-of-life Node.js ${major}`,
      HYGIENE_BASE.eolRuntime,
      `Node.js ${major} stopped receiving security patches on ${NODE_EOL[major] ?? 'an earlier date'}. Runtime flaws stay open forever.`,
      'Move to a supported LTS release and raise "engines.node".',
    );
  }

  if (!m.hasRealTestScript) {
    add(
      'No automated tests',
      HYGIENE_BASE.noTests,
      'Security upgrades cannot be applied with confidence when nothing checks for regressions. This slows every other fix.',
      'Add a test script and cover the main paths before upgrading dependencies.',
    );
  }

  if (!m.hasCiWorkflow) {
    add(
      'No CI workflow',
      HYGIENE_BASE.noCi,
      'Nothing runs checks automatically on each change, so problems are found late.',
      'Add a GitHub Actions workflow that runs tests and this scan.',
    );
  }

  return findings;
}

/** Highest score first. Ties: vulnerabilities before hygiene, then alphabetical for stable output. */
export function rank(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => b.score - a.score || a.kind.localeCompare(b.kind) * -1 || a.title.localeCompare(b.title),
  );
}
