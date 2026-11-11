# Triage

*Engineering risk intelligence: fix what matters first.*

A command-line tool that scans several repositories and answers one question:
**what should we investigate or fix first, and why?**

It does not count CVEs. It ranks them by context:

    score = severity (CVSS)  x  exposure (who can reach the system)  x  reach (does the code ship?)

Engineering hygiene gaps (no lockfile, end-of-life Node.js, no tests, no CI) are scored
on the same 0 to 10 scale, so they appear in the same ranked list.

## Run it

    npm install
    npm run scan              # live: clones SIP.js on first run, calls npm audit
    npm run scan:offline      # uses the snapshots in cache/, no network needed
    npm run scan -- --only edge-gateway
    npm test                  # 16 unit tests
    npm run typecheck

Exit codes: `0` no P1 findings, `1` at least one P1 (fails CI), `2` the tool itself failed.

## What it scans

| Repo | What it is | Exposure |
|---|---|---|
| SIP.js | Real open-source telecom (SIP/WebRTC) library, cloned from GitHub | LIBRARY |
| edge-gateway | Synthetic mock of a public API, old production dependencies pinned on purpose | PUBLIC_INTERNET |
| batch-reporting | Synthetic mock of an internal job, vulnerable packages are dev tooling only | INTERNAL_BATCH |

The two mocks are controls: they hold the vulnerability data roughly constant and change
only the context, which shows whether the ranking reacts to context. Their vulnerabilities
are real advisories for real package versions. Nothing is hard-coded.

## Result on 10 Nov 2026

| Repo | Raw advisories | P1 | P2 | P3 | P4 |
|---|---|---|---|---|---|
| SIP.js | 33 | 0 | 1 | 0 | 33 |
| edge-gateway | 9 | 6 | 2 | 1 | 0 |
| batch-reporting | 25 | 0 | 0 | 3 | 25 |

The repo with the fewest advisories (9) is the only one that fails the gate, and three
upgrades clear all six of its P1 findings. SIP.js has 33 advisories and none of them
ship: every one is in build or test tooling. Its top item is a hygiene gap instead
(it still declares support for Node.js 10).

## How it is built

    risk-config.json            which repos, and how exposed each one is
    src/types.ts                data shapes shared by every stage (no logic)
    src/collectors/manifest.ts  reads facts from package.json and the folder
    src/collectors/audit.ts     gets real advisories from npm audit, with a cache
    src/scoring.ts              the only file with opinions: weights, thresholds, ranking
    src/report.ts               terminal and Markdown output
    src/cli.ts                  wires the stages together and sets the exit code

Design decisions:

1. **Exposure is declared, not guessed.** Whether a service faces the internet is a
   deployment fact. It cannot be read reliably from source, so the team states it in
   `risk-config.json`.
2. **Real data, no home-made CVE list.** `npm audit` queries the GitHub Advisory Database.
3. **Dev versus prod by comparison.** The audit runs twice, with and without `--omit=dev`.
   A package that appears only in the full run never reaches production.
4. **Dev risk is reduced, not removed** (weight 0.2). A compromised build tool is still a
   supply-chain risk.
5. **Findings are grouped by fix.** Engineers act on upgrades, not advisories.
   "Upgrade express" clears six findings in one change.
6. **Cache for reliability.** Every live run saves a dated snapshot. If the network fails,
   the tool uses the snapshot and labels the data as cached.
7. **All weights are named constants in one file**, so they can be challenged and changed.
8. **No runtime dependencies.** Only TypeScript, tsx and Node type definitions, all dev-only.

## CI

`.github/workflows/risk-gate.yml` runs the type check and tests, then scans each repo as a
separate job and writes a summary to the job page. `edge-gateway` is expected to fail:
that is the gate working.

## Limitations (known and deliberate)

- **The weights are judgement, not measurement.** 1.5 for public exposure is a starting
  point for discussion. It is not calibrated against incident data.
- **No reachability analysis.** The tool knows a vulnerable package is installed in
  production. It does not know whether the vulnerable function is ever called.
- **No exploit intelligence yet.** Adding CISA KEV (known exploited) and EPSS
  (exploit probability) would be the next step, as a fourth factor.
- **npm only.** Other ecosystems would each need their own collector.
- **Hygiene checks are shallow.** A test script existing does not mean the tests are good.
- **CVSS fallback.** When an advisory has no CVSS number, the score is estimated from the
  severity label (critical 9.0, high 7.5, moderate 5.0, low 2.0).
- **Node end-of-life dates are a small table in the code**, checked against the official
  release schedule. A production version would fetch them.
- This complements tools such as Dependabot, Snyk and OpenSSF Scorecard. It does not
  replace them.
