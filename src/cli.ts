import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { collectAudit } from './collectors/audit.js';
import { readManifest } from './collectors/manifest.js';
import { renderGate, renderMarkdown, renderTerminal } from './report.js';
import { rank, scoreHygiene, scoreVulnerability } from './scoring.js';
import type { RepoConfig, RepoReport } from './types.js';

/**
 * Entry point. It only wires the stages together:
 *
 *   config -> collect facts -> score -> report -> exit code
 *
 * Exit codes (this is what makes it a CI gate):
 *   0 = no P1 findings
 *   1 = at least one P1 finding
 *   2 = the tool itself failed (bad config, unreadable repo)
 *
 * Flags:
 *   --config <file>   repos to scan (default risk-config.json)
 *   --offline         use cached audit snapshots, no network
 *   --only <name>     scan a single repo from the config
 *   --md <file>       also write a Markdown summary
 *   --json <file>     also write the full report as JSON
 *   --no-gate         always exit 0 (report only)
 */

function flag(name: string): boolean {
  return process.argv.includes(name);
}
function option(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

/** Shallow-clones a repo listed with a "clone" URL if it is not on disk yet. */
function ensureCloned(repo: RepoConfig): void {
  if (existsSync(repo.path) || !repo.clone) return;
  console.error(`Cloning ${repo.clone} ...`);
  mkdirSync(dirname(repo.path), { recursive: true });
  spawnSync('git', ['clone', '--depth', '1', '--quiet', repo.clone, repo.path], { stdio: 'inherit' });
}

export function scanRepo(repo: RepoConfig, offline: boolean): RepoReport {
  const manifest = readManifest(repo.path);
  const audit = collectAudit(repo.name, repo.path, offline);
  const findings = rank([
    ...audit.vulnerabilities.map((v) => scoreVulnerability(repo, v)),
    ...scoreHygiene(repo, manifest),
  ]);
  return { repo, manifest, audit, findings, rawAdvisoryCount: audit.vulnerabilities.length };
}

function main(): number {
  const configPath = option('--config') ?? 'risk-config.json';
  const offline = flag('--offline');
  const only = option('--only');

  let repos: RepoConfig[] = JSON.parse(readFileSync(configPath, 'utf8')).repos;
  if (only) repos = repos.filter((r) => r.name === only);
  if (repos.length === 0) throw new Error('No repositories to scan.');

  const reports: RepoReport[] = [];
  for (const repo of repos) {
    if (!offline) ensureCloned(repo);
    if (!existsSync(repo.path)) {
      console.error(`Skipping ${repo.name}: ${repo.path} not found.`);
      continue;
    }
    reports.push(scanRepo(repo, offline));
  }
  if (reports.length === 0) throw new Error('None of the configured repositories could be read.');

  console.log(renderTerminal(reports));
  console.log(renderGate(reports));

  const mdPath = option('--md');
  if (mdPath) writeFileSync(mdPath, renderMarkdown(reports));
  const jsonPath = option('--json');
  if (jsonPath) writeFileSync(jsonPath, JSON.stringify(reports, null, 2));

  const hasP1 = reports.some((r) => r.findings.some((f) => f.priority === 'P1'));
  return hasP1 && !flag('--no-gate') ? 1 : 0;
}

// If the output is piped into a tool that stops reading early (head, less), exit quietly.
process.stdout.on('error', (err: NodeJS.ErrnoException) => {
  if (err.code === 'EPIPE') process.exit(0);
});

try {
  process.exitCode = main();
} catch (err) {
  console.error(`Tool error: ${(err as Error).message}`);
  process.exitCode = 2;
}
