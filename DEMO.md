# Triage: 15-minute demo plan

Before the call: run `npm install`, `npm test` and `npm run scan` once, so SIP.js is
cloned and the cache is fresh. Keep a second terminal ready with `npm run scan:offline`
in case the network fails.

## 1. The problem (1 minute)

"Run `npm audit` on three repos and you get 67 advisories with no order. An engineer
with one free afternoon cannot tell which one matters. Triage answers one question:
what do we fix first, and why?"

## 2. The idea (2 minutes)

Open `src/scoring.ts` and show the top comment.

    score = severity x exposure x reach

- Severity: how bad the flaw is in theory (CVSS).
- Exposure: who can reach the system. Declared in `risk-config.json`, because it is a
  deployment fact that cannot be read from code.
- Reach: does the vulnerable package ship to production, or is it only build tooling?

## 3. Run it (4 minutes)

    npm run scan

Walk through the output top to bottom:

1. **Fix first.** Three upgrades on edge-gateway clear all six P1 findings.
   Point at "Upgrade express: clears 6 findings". Engineers act on fixes, not advisories.
2. **Signal versus noise table.** This is the main point of the demo:
   - SIP.js: 33 advisories, zero P1. None of them ship. All are build and test tooling.
   - edge-gateway: only 9 advisories, six P1. Fewest advisories, highest risk.
   - batch-reporting: 25 advisories, zero P1. Internal job, vulnerable packages are dev-only.
3. **Hygiene.** SIP.js's top item is not a CVE. It still declares support for Node.js 10,
   which stopped getting security patches in 2021.
4. **The workings line.** Every score shows its arithmetic, so nobody has to trust a black box.

## 4. The CI gate (2 minutes)

Show `.github/workflows/risk-gate.yml` and the Actions tab.

- Each repo is scanned as its own job. edge-gateway goes red (exit 1), the other two pass.
- The job summary shows the same ranked table without opening logs.
- Exit codes: 0 pass, 1 P1 found, 2 tool error.

    npm run scan -- --only batch-reporting ; echo "exit code: $?"
    npm run scan -- --only edge-gateway ; echo "exit code: $?"

## 5. How it is built (2 minutes)

Show the folder tree. One job per file: collect facts, score, report. `scoring.ts` is the
only file with opinions, and every weight is a named constant. 16 unit tests, no runtime
dependencies.

    npm test

## 6. Trade-offs and limits (2 minutes)

Say these before they ask:

- The weights are judgement, not measured against incident data.
- No reachability analysis: it knows a package ships, not whether the vulnerable function is called.
- No exploit data yet. CISA KEV and EPSS would be the next factor to add.
- npm only.
- It complements Dependabot and Snyk. It does not replace them.

## 7. How I used AI (1 minute)

## 7. How I Used AI

- **Boilerplate & Parser Scaffolding:** Used LLMs to draft schema decoders for nested npm v7+ `auditReportVersion: 2` JSON outputs and generate fixture manifest structures.
- **Independent Validation via Benchmarks:** Benchmarked the scoring heuristic directly against raw `npm audit --json` outputs across synthetic and open-source fixtures. Verified that noisy ReDoS/dev-dependency vulnerabilities in internal tools were safely de-prioritised to P4, while production RCE/injection paths on public APIs were promoted to P1.
- **Architectural Control & Determinism:** Kept the risk engine in `src/scoring.ts` purely algorithmic and deterministic. Kept weights auditable and code-driven rather than delegating evaluation to black-box runtime prompts, ensuring compliance with corporate CI/CD gate policies.

## 8. Next steps (1 minute)

KEV and EPSS as a fourth factor, more ecosystems, a trend view over time, and letting
teams tune weights per organisation.

## Questions to expect

- **Why 1.5 for public and 0.2 for dev?** They are starting points. The design choice is
  that they sit in one file so a team can change them.
- **Why is dev risk not zero?** A compromised build tool is a supply-chain risk.
- **How do you know a package is dev-only?** The audit runs twice, with and without
  `--omit=dev`. Anything only in the full run never ships.
- **What if npm is down?** Every live run saves a dated snapshot. The tool falls back to
  it and labels the data as cached.
- **Why not just use Dependabot?** Dependabot lists and patches. It does not rank across
  repos by exposure, and it ignores hygiene gaps.
- **Could exposure be detected automatically?** Partly, from infrastructure config. Not
  reliably from application code, so the prototype asks the team to declare it.
- **Why would a real team trust this?** Every score prints its arithmetic and its data source.
