---
name: nlpm-auto-audit
description: "Use when creating, editing, or reviewing SKILL.md, AGENTS.md, agent definitions, hook configs, plugin manifests, or prompt rules; automatically run the complete read-only NLPM audit and report security, validation, scores, cross-file consistency and available NL-TDD specs. 中文触发：写改 Skill、治理规则体检、智能体定义审查、Hook 或插件配置审计。"
metadata:
  version: "0.1.0-local"
---

# NLPM Auto Audit

Scope: audit agent-driving artifacts after their final local revision. Ordinary article prose and application source code are outside this entrypoint. The installed `nlpm:*` reference skills explain the individual rules; this entrypoint executes the combined audit. Human task intent and permissions remain authoritative.

## Workflow

1. Resolve the affected artifact's real path and select its Skill directory or project root. Preserve existing task scope; use synthetic fixtures for runtime experiments.
2. Native hooks and the filesystem monitor queue an audit after the final local edit. Read its state from that root:

   ```bash
   "$HOME/.local/bin/nlpm-auto-audit" status "$PWD"
   ```

   For a shared Skill, pass its actual Skill directory rather than the whole shared library. For an explicit review or immediate audit, use `nlpm-auto-audit run <root>` when the caller may write the report directory. A sandbox that cannot write the report directory can read the queued result; it does not need broader permissions. Empty run input means the current project; a missing root is an error. A non-NL task requires no audit.
3. Read `latest.report_path` when available, or the foreground `report_path`. Pending work remains pending. The audit covers security, deterministic validation, rubric scores, cross-artifact consistency and every available `.nlpm-test/*.spec.md`. `NOT_APPLICABLE` for absent specs is separate from a passing test. Model spec evaluation is separate from actual runtime behavior.
4. Report concrete findings and their discriminating checks. Authentication failures, timeout, missing dependencies, incomplete coverage, source drift or invalid structured results remain blocked/stale; none means clean. Do not automatically repair, commit, push or publish in this audit.
5. Existing sessions may need restart to discover this entrypoint. File monitoring and native hooks queue the same executor; report generation does not trigger another audit. `NLPM_AUTO_AUDIT_ACTIVE=1` marks internal worker sessions and prevents recursion.

## Examples

<example>
User: "Create a skill for reviewing database migrations."
Action: finish the authorized Skill, audit its real directory, then report its score and findings with the result path. No mention of NLPM is required to select this entrypoint.
</example>

<example>
User: "Check the agent definition's permissions and broken references."
Action: audit the containing project read-only, identify both sides of each inconsistency, and preserve blocked checks.
</example>

<example>
User: "Rewrite the opening paragraph of this article."
Action: continue the writing task without activating this artifact-audit workflow.
</example>
