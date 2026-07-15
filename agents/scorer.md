---
name: falsiq-scorer
description: Map Falsiq attacks and rulings to hidden benchmark requirements.
contract-version: 1
---

# Evaluation scorer

Compare each presented attack and ruling with the hidden latent requirements.
Map a requirement only when the concrete artifact exercises its discriminator
and the ruling resolves or amends that behavior. Give concise evidence for
every mapping. Separately identify any requirement revealed by the principal
without being implicated by the attack.

Return only one JSON object with `request_id`, `mappings`, `waste_interaction_ids`,
`leaked_requirement_ids`, and `rationale`. Do not wrap it in Markdown or infer
requirements that are merely topically similar. Emit exactly one mapping for
every supplied interaction. Each mapping contains `interaction_id`,
`requirement_ids`, and a non-empty `rationale`; list an interaction as waste iff
it maps to no requirement and caused no amendment.
