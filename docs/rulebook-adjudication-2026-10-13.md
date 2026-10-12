# Rulebook adjudication packet — 2026-10-13

Status: `PROPOSAL_ONLY / BLOCKED_PROCESS_GAP`

Baseline: `458b703a548fa514b9d30c66ee1c354d92c6c9e7` (`fork-main`). This packet records three independently checked rulebook inconsistencies. It does not mutate the rulebook, dispatch a workflow, open a PR, merge, push, release, or deploy.

## Process finding

`AGENTS.md` requires every NLPM rulebook mutation to go through `auditor-refine-rules` as a human-review PR. The current workflow prompt also says:

- only edit `skills/nlpm/rules/SKILL.md`;
- derive proposals from `/tmp/refinement-input.json`;
- do not merge the resulting PR automatically.

The three inconsistencies below live in scoring references, the Codex scoring overlay, and the vocabulary registry. A live local run of `rule-health.py` plus `prepare-refinement-input.py` prepared ten proposals, including R51, but none carried evidence for these inconsistencies. Therefore the current workflow cannot author the required changes without violating its own file allowlist or inventing evidence.

A read-only GitHub query on 2026-10-13 also found an existing open `rule-refinement-proposal`, [xiaolai/nlpm#817](https://github.com/xiaolai/nlpm/pull/817), last updated 2026-08-09. The workflow's first gate makes every new run a no-op while that PR remains open. This is a second, independent process block; it does not authorize closing or superseding that PR.

Recommended process change: first open a human-review governance PR that extends `auditor-refine-rules` with an explicit, tested allowlist for the rulebook surfaces below and an evidence-packet input. Only after that PR is reviewed should the workflow generate the actual rulebook proposal. This packet is the proposed evidence input.

## A. Calibration examples do not follow the published penalty table

### Verified facts

`skills/nlpm/scoring/references/calibration-examples.md` Example 3 starts at 100, applies an explicitly non-formal `-3`, then reports 92 by adding an unexplained approximately five-point gap. The scoring Skill says the penalty tables are self-contained; no published row supports either subtraction.

Example 4 publishes these deductions: missing description `-10`, missing bold imperative `-5`, missing rationale `-10`, non-specific/non-testable `-10`, two vague-word deductions, duplicate tooling `-10`, and a second enforceability deduction `-10`.

The published rule table supports only four of them for the artifact as written:

| Supported row | Penalty |
|---|---:|
| R21 missing frontmatter description | -10 |
| R21 no bold imperative opening | -5 |
| R21 no rationale | -10 |
| R22 not specific/testable | -10 |
| **Total** | **-35** |

The exact R01 token list contains `appropriate`, not `appropriately`, and contains no `well-organized`; an exact word-boundary check returns no match. Generic “clean code” is not evidence that eslint, ruff, or clippy already enforces the rule. The second enforceability deduction repeats R22.

### Proposed rulebook change

1. Change Example 3 to 100/100 and remove the unsupported `-3` and approximately five-point gap.
2. Change Example 4 to 65/100, keep the `Weak` band, and retain only the four supported penalties above.
3. Update the calibration index in both canonical and Codex scoring Skills.
4. Add a test that parses each worked example's listed penalties and checks `final = max(0, 100 - sum(penalties))`; require every penalty label to map to a published row.

Acceptance check: a fresh scorer must reproduce 100 and 65 without a judgment-only penalty.

## B. Codex R27 omits a supported `SessionEnd` event

### Verified facts

The current official Codex Hooks documentation lists `SessionEnd`, states that it runs for the main thread, and documents its `reason` field. The repository's `nlpm:conventions-codex` §6 also lists `SessionEnd` as confirmed. `skills/nlpm/scoring/references/codex.md` R27 enumerates ten confirmed events but omits it, so a valid hook can receive a `-15` unrecognized-event penalty.

Official source checked 2026-10-13: <https://learn.chatgpt.com/docs/hooks>

### Proposed rulebook change

1. Add `SessionEnd` to the R27 confirmed-event row in canonical and Codex scoring references.
2. Add a table-parity test that compares the confirmed event set in `nlpm:conventions-codex` with the Codex R27 allowlist.
3. Add a scoring fixture where a minimal valid `SessionEnd` hook receives no R27 event-name penalty.

Acceptance check: the fixture scores without R27, and deleting `SessionEnd` from either authority fails parity.

## C. Vocabulary scope and identity declarations contradict their consumers

### Verified facts

Within the single `auditor` verb scope, the machine registry declares:

- `review` as a deprecated synonym of `audit` and also as a canonical verb;
- `propose` as a deprecated synonym of `contribute` and also as a canonical verb.

A deterministic set intersection of canonical and deprecated auditor verbs returns `["propose", "review"]`. Their recorded outputs are distinct: `audit` produces a composite report, `review` a human-decision artifact, `contribute` opens target-repository PRs, and `propose` produces a draft for human approval.

The registry's internal path declaration includes `CLAUDE.md` but omits `AGENTS.md` and `codex/skills/`. The deterministic drift checker hardcodes `AGENTS.md` into the internal scope, while the release scorer includes Codex Skill mirrors. This creates path-dependent R51 results for artifacts that the repository otherwise treats as the same rule body.

### Proposed rulebook change

1. Remove `review` from `audit.deprecated` and `propose` from `contribute.deprecated` in `registry.yaml`; update the human-readable vocabulary Skill to state the same distinction.
2. Add `AGENTS.md` and `codex/skills/` to the declared internal paths. Preserve the deterministic checker's deliberate decision not to scan generated mirrors, but document that enforcement optimization separately from semantic scope.
3. Make the checker read declared scope paths or test its hardcoded prefixes against them; it must not claim to mirror the registry while silently adding a path.
4. Reject any registry where a verb is both canonical and deprecated in the same scope.

Acceptance checks:

- canonical/deprecated intersection is empty for every verb scope;
- `AGENTS.md`, `CLAUDE.md`, `skills/nlpm/x/SKILL.md`, and `codex/skills/x/SKILL.md` all resolve to internal scope;
- the same body receives the same R51 semantic classification on canonical and Codex paths;
- registry drift self-tests still pass with generated-mirror deduplication enabled.

## Reproduction

Run from a disposable clean worktree. `rule-health.py` currently refreshes `auditor/feedback/log.json` metadata even when its requested report path is under `/tmp`; restore that tracked side effect before reviewing the proposal diff.

From the repository root:

```bash
python3 auditor/scripts/rule-health.py /tmp/rule-health.json
python3 auditor/scripts/prepare-refinement-input.py
jq '.proposals | map({rule_id, state, rule_gaps, downstream_reasons})' /tmp/refinement-input.json

python3 -c 'import yaml; d=yaml.safe_load(open("skills/nlpm/vocabulary/registry.yaml"));
for scope, rows in d["verbs"].items():
    canonical={r["canonical"] for r in rows}
    deprecated={term for r in rows for term in r.get("deprecated", [])}
    print(scope, sorted(canonical & deprecated))'

python3 -m unittest tests.test_gate_pattern_coverage
python3 auditor/scripts/registry-drift-check.py --self-test
```

The expected current contradiction is `auditor ['propose', 'review']`. The first two commands currently prepare ten generic health proposals; they do not include the line-level evidence in this packet.

## Stop condition

Do not edit the listed rulebook files directly under the present workflow contract. Do not treat model agreement as approval. Stop until a human-reviewed process change gives `auditor-refine-rules` a documented path to propose these files, then run the acceptance checks above and leave the resulting rulebook PR unmerged for the owner/reviewer.
