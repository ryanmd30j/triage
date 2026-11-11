import type { Finding, Priority, RepoReport } from './types.js';

/**
 * Responsibility: presentation only. Takes finished reports and renders them
 * for a terminal, or as Markdown for the GitHub Actions job summary.
 * No scoring decisions are made here.
 */

const PRIORITY_LABEL: Record<Priority, string> = {
  P1: 'P1 FIX NOW',
  P2: 'P2 THIS SPRINT',
  P3: 'P3 BACKLOG',
  P4: 'P4 DE-PRIORITISE',
};

const count = (findings: Finding[], p: Priority) => findings.filter((f) => f.priority === p).length;

export function allFindings(reports: RepoReport[]): Finding[] {
  return reports.flatMap((r) => r.findings).sort((a, b) => b.score - a.score);
}

/**
 * Several findings often share one fix (upgrading express also fixes body-parser,
 * qs and so on). Engineers act on fixes, not on advisories, so the headline list
 * groups findings by repo + action and keeps the highest-scoring one as the lead.
 */
export function groupByAction(sorted: Finding[]): { lead: Finding; count: number }[] {
  const groups = new Map<string, { lead: Finding; count: number }>();
  for (const f of sorted) {
    const key = `${f.repo}|${f.action}`;
    const existing = groups.get(key);
    if (existing) existing.count += 1;
    else groups.set(key, { lead: f, count: 1 });
  }
  return [...groups.values()];
}

export function renderTerminal(reports: RepoReport[], topN = 5): string {
  const out: string[] = [];
  const line = '='.repeat(78);
  const all = allFindings(reports);

  out.push(line, ' TRIAGE  |  Engineering Risk Intelligence', line, '');

  // 1. The answer first: the few actions that remove the most risk, across every repo.
  const actions = groupByAction(all).slice(0, topN);
  out.push(` FIX FIRST (top ${actions.length} actions across ${reports.length} repositories)`, '');
  actions.forEach((a, i) => {
    const f = a.lead;
    out.push(` ${i + 1}. [${PRIORITY_LABEL[f.priority]}] ${f.repo}  (score ${f.score})`);
    out.push(`    Action: ${f.action}`);
    out.push(`    Clears: ${a.count} finding(s), worst is "${f.title.trim()}"`);
    out.push(`    Why:    ${f.why}`);
    out.push(`    Score:  ${f.workings}`, '');
  });

  // 2. Signal versus noise: raw advisory count next to what actually needs attention.
  out.push(line, ' SIGNAL VERSUS NOISE', line, '');
  out.push(' Repository          Exposure          Raw advisories   P1   P2   P3   P4   Data');
  for (const r of reports) {
    out.push(
      ' ' +
        r.repo.name.padEnd(20) +
        r.repo.exposure.padEnd(18) +
        String(r.rawAdvisoryCount).padStart(8).padEnd(17) +
        (['P1', 'P2', 'P3', 'P4'] as Priority[]).map((p) => String(count(r.findings, p)).padEnd(5)).join('') +
        dataLabel(r),
    );
  }
  out.push('');

  // 3. Per-repo detail, with P4 items collapsed into one line each.
  for (const r of reports) {
    out.push(line, ` ${r.repo.name}  |  ${r.repo.exposure}`, line);
    if (r.repo.note) out.push(` ${r.repo.note}`);
    if (r.audit.note) out.push(` Note: ${r.audit.note}`);
    out.push('');
    const important = r.findings.filter((f) => f.priority !== 'P4');
    const low = r.findings.filter((f) => f.priority === 'P4');
    if (important.length === 0) out.push(' Nothing above P4.', '');
    for (const f of important) {
      out.push(` [${PRIORITY_LABEL[f.priority]}] (score ${f.score}) ${f.title}`);
      out.push(`    Why:    ${f.why}`);
      out.push(`    Score:  ${f.workings}`);
      out.push(`    Action: ${f.action}`, '');
    }
    if (low.length > 0) {
      out.push(` ${low.length} item(s) safely de-prioritised (P4):`);
      for (const f of low) out.push(`    - (score ${f.score}) ${f.title}`);
      out.push('');
    }
  }
  return out.join('\n');
}

export function renderGate(reports: RepoReport[]): string {
  const p1 = allFindings(reports).filter((f) => f.priority === 'P1');
  if (p1.length === 0) return ' CI GATE: PASSED. No P1 findings.';
  const repos = [...new Set(p1.map((f) => f.repo))].join(', ');
  return ` CI GATE: FAILED. ${p1.length} P1 finding(s) in: ${repos}`;
}

function dataLabel(r: RepoReport): string {
  if (r.audit.source === 'unavailable') return 'not audited';
  return `${r.audit.source} ${r.audit.capturedAt?.slice(0, 10) ?? ''}`;
}

export function renderMarkdown(reports: RepoReport[], topN = 5): string {
  const all = allFindings(reports);
  const md: string[] = ['# Triage: Engineering Risk Intelligence', '', renderGate(reports).trim(), ''];

  md.push('## Fix first', '', '| # | Priority | Repo | Action | Clears | Score |', '|---|---|---|---|---|---|');
  groupByAction(all)
    .slice(0, topN)
    .forEach((a, i) => {
      md.push(`| ${i + 1} | ${a.lead.priority} | ${a.lead.repo} | ${a.lead.action} | ${a.count} finding(s) | ${a.lead.score} |`);
    });

  md.push('', '## Signal versus noise', '', '| Repo | Exposure | Raw advisories | P1 | P2 | P3 | P4 | Data |', '|---|---|---|---|---|---|---|---|');
  for (const r of reports) {
    md.push(
      `| ${r.repo.name} | ${r.repo.exposure} | ${r.rawAdvisoryCount} | ${count(r.findings, 'P1')} | ${count(r.findings, 'P2')} | ${count(r.findings, 'P3')} | ${count(r.findings, 'P4')} | ${dataLabel(r)} |`,
    );
  }
  md.push('');
  return md.join('\n');
}
