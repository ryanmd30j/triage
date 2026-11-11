/**
 * Shared data shapes. No logic lives here.
 *
 * Design decision: every stage of the pipeline (collect -> score -> report)
 * talks to the next one only through these types, so each stage can be
 * explained, tested and replaced on its own.
 */

/** Where the code runs. This is declared by the team in risk-config.json,
 *  because exposure is a deployment fact that cannot be read from source code. */
export type Exposure = 'PUBLIC_INTERNET' | 'LIBRARY' | 'INTERNAL_SERVICE' | 'INTERNAL_BATCH';

/** P1 = fix now (fails the CI gate). P2 = plan this sprint. P3 = backlog. P4 = safe to de-prioritise. */
export type Priority = 'P1' | 'P2' | 'P3' | 'P4';

/** One repository to scan, as listed in risk-config.json. */
export interface RepoConfig {
  name: string;
  path: string;
  exposure: Exposure;
  clone?: string;
  note?: string;
}

/** Facts read from package.json and the repo folder. No judgement yet. */
export interface Manifest {
  name: string;
  hasLockfile: boolean;
  hasRealTestScript: boolean;
  hasCiWorkflow: boolean;
  /** The "engines.node" string, for example ">=16", or null when not declared. */
  nodeEngine: string | null;
  prodDependencyCount: number;
  devDependencyCount: number;
}

/** One vulnerable package, as reported by npm audit. */
export interface Vulnerability {
  packageName: string;
  /** 0 to 10. Taken from the advisory, or estimated from the severity label. */
  cvss: number;
  severity: string;
  title: string;
  url: string | null;
  /** 'prod' = installed for real users. 'dev' = only build and test tooling. */
  scope: 'prod' | 'dev';
  /** true = listed in package.json. false = pulled in by another package. */
  isDirect: boolean;
  /** Human-readable fix, or null when no fixed version exists. */
  fix: string | null;
}

/** Where the vulnerability data came from, so the report can say so honestly. */
export interface AuditResult {
  source: 'live' | 'cache' | 'unavailable';
  capturedAt: string | null;
  vulnerabilities: Vulnerability[];
  note?: string;
}

/** One ranked item in the final report. Vulnerabilities and hygiene gaps share this shape
 *  so they can be sorted into a single "fix first" list. */
export interface Finding {
  repo: string;
  kind: 'vulnerability' | 'hygiene';
  title: string;
  score: number;
  priority: Priority;
  /** The arithmetic behind the score, shown to the engineer. */
  workings: string;
  why: string;
  action: string;
}

export interface RepoReport {
  repo: RepoConfig;
  manifest: Manifest;
  audit: AuditResult;
  findings: Finding[];
  /** How many raw advisories npm audit listed, before prioritisation. */
  rawAdvisoryCount: number;
}
