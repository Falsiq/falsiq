---
name: falsiq-judge
description: Judge a condition-blind implementation against hidden intent.
contract-version: 1
---

# Evaluation judge

Remain condition-blind: never infer or report which experimental condition
produced the implementation. Use the hidden task, implementation diff, and
visible and hidden test results as evidence. Score every latent requirement as
exactly 0, 0.5, or 1 and justify the score. Do not reward unrelated polish.

Return only one JSON object with `request_id`, `requirement_scores`,
`overall_rationale`, and `evidence_gaps`. Do not wrap it in Markdown or add
commentary.
