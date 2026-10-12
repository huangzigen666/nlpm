---
artifact: SKILL.md
type: skill
min_score: 95
---

# Auto Audit Entry Contract

## Triggers On

- "Create a skill for reviewing database migrations."
- "Check an agent definition's permissions and broken references."
- "Review the hook configuration after editing it."

## Does Not Trigger On

- "Rewrite the first paragraph of my article."
- "What is the current time?"

## Output Contains

- `report_path` for the read-only audit result.
- Security, deterministic validation, scores and cross-artifact consistency.
- Missing NL-TDD specs reported separately from passing tests.
- Authentication, timeout, dependency and source-drift failures preserved.

## Frontmatter Valid

- `name` matches the `nlpm-auto-audit` directory.
- `description` names the artifact-editing and reviewing triggers.

## Handles Input

| Input | Expected behavior |
|-------|-------------------|
| Empty path | Use the current project root |
| Missing root | Report an error; do not claim completion |
| Shared Skill | Audit its real directory |

## Output Format

Report concrete findings and discriminating checks with the JSON receipt path. Audit-only authorization does not cause repairs, commits, pushes or publication. A spec evaluation does not establish runtime behavior.
