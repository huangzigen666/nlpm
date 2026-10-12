# Local automatic audit adapter

The optional adapter queues complete read-only audits for agent-driving artifacts. It combines the existing NLPM knowledge with deterministic syntax/reference checks and a structured native model response covering security, per-file rubric scores, cross-file consistency and supplied NL-TDD specs. It does not port Claude's original `/nlpm:*` commands or run the GitHub auditor contribution pipeline.

## Installation and scope

On this Mac the adapter requires Python 3.12+, an available authenticated Codex or Claude CLI, and a Python interpreter with PyYAML. `NLPM_YAML_PYTHON` selects the YAML interpreter; the default is the macOS CommandLineTools Python. Installation is explicit:

```sh
python3.12 automation/install.py
python3.12 automation/install.py --apply
launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/local.rex.nlpm-auto-audit.plist"
```

The preview lists planned writes. Apply preserves existing user settings, enabled-plugin flags, model/provider configuration and hook entries; modified files receive same-parent snapshots before atomic replacement. The installer adds one shared Skill to existing Agent Skill roots, installs the native event queue for Claude and Codex, registers resolved shared Skill directories, and creates a macOS LaunchAgent. It does not start Hermes.

SessionStart/UserPromptSubmit register a concrete Git project or Skill directory. PostToolUse/Stop and the filesystem monitor detect changes in registered units, including edits made through agents without compatible native hooks. Existing files are baselined at installation rather than bulk-audited. A new unregistered project needs a compatible session hook or an explicit audit; sharing the Skill entry does not prove each host's implicit-selection behavior.

For a large registered repository, automatic jobs retain the full snapshot for deterministic validation and source-drift checks, then send the changed NL artifacts, their specs/references and the project-level contracts to the model. `coverage.mode=changed_artifacts` lists the model-visible paths and the excluded count. Its result covers the changed artifacts across all four audit sections; it is not a clean verdict on every excluded file. Explicit `run <root>` uses `coverage.mode=full_snapshot`; add `--changed-path <absolute-file>` to request the bounded scope manually.

The background defaults are a 20-second debounce, 5-second polling, a 240-second per-audit timeout and at most six model audit attempts per hour. Reports and state live under `~/.local/state/nlpm-auto-audit/`, outside the source repository. The backend defaults to the existing Codex configuration. Claude is an explicit backend choice; authentication failures never silently switch models or credentials.

## Reading results

```sh
nlpm-auto-audit status /absolute/project/or/skill/root
nlpm-auto-audit run /absolute/project/or/skill/root --threshold 95
```

Use the affected Skill's actual directory for a shared Skill. `latest.report_path` identifies the recorded result. `AUDIT_COMPLETE` means all required audit sections were returned, deterministic validation passed and no reported issue crossed the selected threshold. `FINDINGS` is a completed audit with identified issues. Missing specs are `NOT_APPLICABLE`; a supplied spec passing is `PASS_SPEC_EVALUATION`, not runtime proof. Authentication, dependency, timeout, invalid-output and stale-source states remain explicit. Identical sources, rules, adapter code and model configuration reuse a completed result.

The executor snapshots source hashes, withholds credential configuration values, treats artifact instructions as data, disables MCP/web and recursive hooks, uses the Codex read-only sandbox or Claude's empty tool set, and rejects model tool-call events. An audit never repairs, applies, commits, pushes or publishes. Findings pair source evidence with a discriminating check; human standards, corrections and feedback remain inputs to the next revision. No learning outcome is inferred from a clean report.

## Recorded acceptance boundary

The local installation receipt is `~/.local/state/nlpm-auto-audit/install-receipts/20261012T121922-85593.json`: 23 Agent entry roots resolve to one canonical Skill file and one inode. Both user hook configurations retained their non-hook values and original hook entries. Installation preview after apply reports zero pending file/link changes. Native plugin manifest validation, `plutil` and `launchctl print` were checked separately.

The unprompted native Codex edit test is recorded in `/private/tmp/nlpm-auto-audit-natural-20261012/`: its prompt does not name NLPM; actual tool events show the new audit Skill and the authoring conventions being read, the exact single-heading replacement, and the automatically queued status. This establishes one tested Codex route, not runtime loading in all 23 hosts.

Claude's native probe is blocked by expired OAuth. Reauthentication belongs to the owner; no credentials were read or modified. The full pre-existing Python suite also has nine failures in `auditor/scripts/unstick-bot-prs.sh` because this Mac's Bash 3.2 lacks `mapfile`; unrelated auditor scripts are outside this change. The adapter/checker/preload-safety tests and runtime canary receipts supply the scoped acceptance evidence.

The synthetic bad Skill completed as `FINDINGS`: score 60, three cross-file findings and a failing NL-TDD spec. The synthetic good Skill completed as `AUDIT_COMPLETE`: score 100 and a passing spec evaluation. The installed audit entrypoint itself completed with scores 100 (`SKILL.md`) and 95 (`agents/openai.yaml`), with its spec evaluated as PASS. Full-repository auditing of this unusually large NLPM source tree returned `BLOCKED_TIMEOUT` at both 480 and 900 seconds; the latest receipt is `~/.local/state/nlpm-auto-audit/reports/20261012T160807-8132097a/report.json`. That receipt does not establish a clean full-repository verdict. The default background timeout remains 240 seconds; oversized roots retain an explicit blocked state.

After adding a credential-free loopback proxy to the LaunchAgent environment, an actual queued change to this repository's `AGENTS.md` completed automatically in 110 seconds: `~/.local/state/nlpm-auto-audit/reports/20261012T163906-d5a4f59f/report.json`. Its changed-artifact score is 100 and the full-snapshot native checker passes. The `FINDINGS` status preserves a real cross-file mismatch: `skills/nlpm/vocabulary/registry.yaml` omits `AGENTS.md` from its declared internal paths while the project's canonical memory instruction and deterministic drift-check script include it. This adapter records that finding without modifying the existing vocabulary policy.

Final scoped scoring receipts also show `codex/AGENTS.md` at 100 (`20261012T165020-87ed6e52`), both plugin manifests and the marketplace entry at 100 (`20261012T164304-d4040fd2`), and the shared Skill's `SKILL.md` at 100 with `agents/openai.yaml` at 95 (`20261012T161503-9ed045ea`). The new Skill path was added to the existing pre-release `NL_PATTERN` so the GitHub gate can select it. These receipts establish the changed-file score floor; the prior full-snapshot timeout remains unresolved.
