# Nexus coding-agent benchmark — 2026-10-13T05-04-20-372Z

Objective scoring: an agent passes a task only by making `node test.js` exit 0, in an isolated copy of the task. No opinion, no partial credit.

| task | codex |
| --- | --- |
| concurrency-limit | PASS 68.2s |
| csv-rfc4180 | PASS 81.6s |
| fix-csv | PASS 80.2s |
| fix-range | PASS 55.8s |
| fix-stack | PASS 60s |
| impl-fizzbuzz | PASS 52.5s |
| multi-file | PASS 100.5s |
| perf-pairs | PASS 63.2s |
| semver-range | PASS 154.7s |
| trace-pagination | PASS 73.7s |

| agent | passed | pass rate | avg s (passed) |
| --- | --- | --- | --- |
| codex | 10/10 | 100% | 79.0 |
