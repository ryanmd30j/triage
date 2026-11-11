import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Manifest } from '../types.js';

/**
 * Responsibility: read plain facts about a repository from disk.
 * It never decides whether something is risky. That is the scorer's job.
 */
export function readManifest(repoPath: string): Manifest {
  const pkgPath = join(repoPath, 'package.json');
  if (!existsSync(pkgPath)) {
    throw new Error(`No package.json found in ${repoPath}`);
  }
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));

  return {
    name: pkg.name ?? repoPath,
    hasLockfile: existsSync(join(repoPath, 'package-lock.json')),
    hasRealTestScript: isRealTestScript(pkg.scripts?.test),
    hasCiWorkflow: hasWorkflowFiles(join(repoPath, '.github', 'workflows')),
    nodeEngine: pkg.engines?.node ?? null,
    prodDependencyCount: Object.keys(pkg.dependencies ?? {}).length,
    devDependencyCount: Object.keys(pkg.devDependencies ?? {}).length,
  };
}

/** npm's default placeholder is `echo "Error: no test specified" && exit 1`. That is not a test suite. */
export function isRealTestScript(script: unknown): boolean {
  if (typeof script !== 'string' || script.trim() === '') return false;
  return !script.toLowerCase().includes('no test specified');
}

function hasWorkflowFiles(dir: string): boolean {
  if (!existsSync(dir)) return false;
  return readdirSync(dir).some((f) => f.endsWith('.yml') || f.endsWith('.yaml'));
}
