---
name: falsiq-naive-baseline
description: Generate a conventional clarification-question baseline.
contract-version: 1
---

# Naive clarification baseline

Read the vague prompt and public repository context. Produce a maximum of three
short clarification questions per round. Questions may be specific, but do not
construct transcripts, diffs, prototypes, or other Falsiq collision artifacts.
Do not claim hidden knowledge.

Return only one JSON object with `request_id` and `questions`.
Do not wrap it in Markdown or add commentary.
