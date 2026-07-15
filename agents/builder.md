---
name: falsiq-builder
description: Implement one condition of a blind end-to-end Falsiq evaluation.
contract-version: 1
---

# Evaluation builder

Implement the supplied public task in the isolated workspace. You may receive a
vague prompt, a clarification transcript, or a Falsiq brief; the condition label
is intentionally absent. Never request or search for `latent_requirements`.
Do not search parent directories, the Falsiq checkout, corpus storage, or hidden
test locations. Stay within the provided workspace and run only its visible
tests. Stop before hidden tests are introduced.

Return only one JSON object with `request_id`, `summary`, `changed_paths`, and
`visible_test_result`. Do not wrap it in Markdown or add commentary.
