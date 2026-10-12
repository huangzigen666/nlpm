# nlpm — reference knowledge for Codex CLI

Before editing or reviewing an NL artifact, select the row below for its artifact type and target tool, then load that Skill. Apply the 50 core rules (R01–R50), the opt-in vocabulary rule (R51), the 100-point scoring rubric, and the convention for the target tool. Select a writing guide when creating a Skill, agent, hook, rule, plugin or prompt.

For a scoring request, load `$nlpm-rules` and `$nlpm-scoring` and cite each applicable penalty. For Codex layout questions, load `$nlpm-conventions-codex`. Treat those references as knowledge; invoke the local audit entrypoint for an executable audit.

## What this plugin does NOT include

nlpm's interactive linting commands (`/nlpm:score`, `/nlpm:check`, `/nlpm:fix`, etc.) are **not** ported to Codex. Those commands orchestrate sub-agents via Claude Code's `Task()` dispatch, which has no in-skill equivalent in Codex. They remain a Claude Code plugin.

After editing an NL artifact, use the optional shared `nlpm-auto-audit` Skill to read the queued report for its real project or Skill root. Check security findings, deterministic validation, rubric scores, cross-file consistency and any supplied NL-TDD specs. Preserve `BLOCKED_*` and `STALE_SOURCE` states. Report spec evaluation separately from actual runtime behavior. The adapter does not port the original `/nlpm:*` commands.

## Prerequisites and checks

Use Python 3.11+ for the standalone checker. The optional automatic audit adapter requires Python 3.12+, a YAML parser selected by `NLPM_YAML_PYTHON`, and an authenticated native Codex or Claude CLI for model judgment. Check authentication before treating a blocked model stage as a content finding.

From the NLPM checkout, check manifest references, frontmatter and hook event names, then run the adapter and release-gate tests:

```bash
python3 bin/nlpm-check . --strict
python3.12 -m unittest tests.test_auto_audit tests.test_gate_pattern_coverage
```

## Where to find each component

- Read `skills/nlpm/` for the canonical rules, rubric, conventions and writing guides; `codex/skills/` contains their Codex reference mirrors.
- Read `commands/` and `agents/` to understand the original Claude Code slash-command orchestration; invoke those commands only in Claude Code.
- Read `automation/skills/nlpm-auto-audit/` for the shared executable entrypoint, `automation/monitor.py` for the background queue, and `automation/auto_audit.py` for the read-only audit stages.
- Use `automation/install.py` to preview or install local links and hooks; use `bin/nlpm-check` for the standalone deterministic validator.
- Check `.claude-plugin/` and `.codex-plugin/` for the respective plugin manifests before changing plugin packaging.

## Load the reference for this task

| Skill | When to load it |
|-------|-----------------|
| `$nlpm-rules` | Check the 50 core rules (R01–R50) and the opt-in R51 boundary. |
| `$nlpm-scoring` | Score the target artifact against its 100-point penalty table. |
| `$nlpm-conventions` | Check SKILL.md frontmatter, AGENTS.md and naming. |
| `$nlpm-conventions-claude` | Check Claude `.claude/` paths, plugin.json and hook events. |
| `$nlpm-conventions-codex` | Check `.codex/config.toml`, `.codex-plugin/` and `.agents/skills/`. |
| `$nlpm-conventions-antigravity` | Check Antigravity and Gemini CLI artifacts. |
| `$nlpm-patterns` | Detect NL programming anti-patterns before revising a file. |
| `$nlpm-vocabulary` | Check controlled terms when R51 is enabled. |
| `$nlpm-testing` | Evaluate supplied NL-TDD specs. |
| `$nlpm-security` | Review executable artifacts against security patterns. |
| `$nlpm-orchestration` | Consult Claude-lineage multi-agent patterns when a task dispatches two or more Claude-lineage agents. |
| `$nlpm-writing-skills` … `$nlpm-writing-prompts` | Choose the guide for the artifact type being written. |

Source and full Claude Code plugin: <https://github.com/xiaolai/nlpm>
