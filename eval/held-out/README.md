# Held-out evaluation set — reserved

This directory is the **held-out** set (NX-008). It is reserved at the outset and
used **once, at the very end**, to produce the number that is reported. Any run
that reads it (`node eval/harness.js --final`) invalidates it for future
comparison, so iteration happens only on the development set (`eval/tasks/`).

It is intentionally empty in version control until the held-out tasks are
authored privately and added here immediately before the final measurement.
Keeping it empty now is the discipline, not an oversight: a held-out task that
has been looked at during development is no longer held out.

Each held-out task follows the same schema as `eval/tasks/*.json` and must carry
its own `provenance` and `contamination` argument, or the harness excludes it.
