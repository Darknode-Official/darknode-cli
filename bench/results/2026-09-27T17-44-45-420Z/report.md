# Nexus coding-agent benchmark — 2026-09-27T17-44-45-420Z

Objective scoring: an agent passes a task only by making `node test.js` exit 0, in an isolated copy of the task. No opinion, no partial credit.

| task | nexus-local |
| --- | --- |
| fix-csv | FAIL (timeout) |
| fix-range | FAIL (timeout) |
| fix-stack | FAIL (timeout) |
| impl-fizzbuzz | FAIL |
| multi-file | FAIL (timeout) |

| agent | passed | pass rate | avg s (passed) |
| --- | --- | --- | --- |
| nexus-local | 0/5 | 0% | - |
