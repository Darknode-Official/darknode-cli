# Nexus coding-agent benchmark — 2026-10-13T03-15-58-258Z

Objective scoring: an agent passes a task only by making `node test.js` exit 0, in an isolated copy of the task. No opinion, no partial credit.

| task | nexus-claude | claude-code | codex |
| --- | --- | --- | --- |
| concurrency-limit | PASS 43.6s | PASS 56s | FAIL |
| csv-rfc4180 | PASS 69.4s | PASS 58.9s | FAIL |
| fix-csv | PASS 38.6s | PASS 45.6s | FAIL |
| fix-range | PASS 36.7s | PASS 42.6s | FAIL |
| fix-stack | PASS 39.9s | PASS 43.9s | FAIL |
| impl-fizzbuzz | PASS 38.1s | PASS 41.9s | FAIL |
| multi-file | PASS 38.5s | PASS 42.6s | FAIL |
| perf-pairs | PASS 56.5s | PASS 50.2s | FAIL |
| semver-range | PASS 104.4s | PASS 78.7s | FAIL |
| trace-pagination | PASS 40.2s | PASS 44.9s | FAIL |

| agent | passed | pass rate | avg s (passed) |
| --- | --- | --- | --- |
| nexus-claude | 10/10 | 100% | 50.6 |
| claude-code | 10/10 | 100% | 50.5 |
| codex | 0/10 | 0% | - |
