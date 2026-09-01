#!/usr/bin/env python3
"""Compute per-rule health metrics from the structured auditor logs.

Runs SCHEMAS §Learning query over the three append-only logs and
classifies every rule_id as healthy, noisy, dormant, or disputed.

Inputs (paths are relative to the repo root):
    auditor/findings.jsonl          — one record per finding
    auditor/logs/events.jsonl       — finding_outcome + finding_verified + finding_introduced events (filtered)
    auditor/disagreements.jsonl     — self_fp, maintainer_rejected, pr_comments_snapshot, downstream_suppression
    auditor/registry/repos.json     — rule-adopted repos, total repos audited

Output (argv[1] or stdout): a JSON blob with
    summary.*            — PR scorecard numbers (drop-in replacement for the old feedback-summary.json)
    rule_metrics[rid]    — hits, contributed, merged, closed_unmerged, open, self_fp,
                           maintainer_rejected, downstream_suppressions, dissent_types,
                           verified_fixed, verified_persists, verify_rate, introduced, state
    dormant_rules[]      — R* rules in the catalog with zero hits
    unclassified_ids[]   — non-catalog rule_ids seen in findings (SEC-*, BUG-*, CC-*)
    metadata.*           — totals, updated_at

The `verified_*` metrics come from finding_verified events emitted by the
post-merge re-audit (auditor-case-study.yml). They give effect-level
precision: `merged / contributed` says "maintainer accepted our PR";
`verified_fixed / verified_total` says "re-running the scorer confirms
the rule's target is actually gone from the code". When both are present,
rule state classification weights the verified signal above the merged one.

All reads are tolerant: missing files produce zeros, malformed JSONL
lines are skipped with a warning to stderr.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

FINDINGS_PATH = Path("auditor/findings.jsonl")
EVENTS_PATH = Path("auditor/logs/events.jsonl")
DISAGREEMENTS_PATH = Path("auditor/disagreements.jsonl")
REGISTRY_PATH = Path("auditor/registry/repos.json")
RULES_CATALOG = Path("skills/nlpm/rules/SKILL.md")
EXEMPLARS_DIR = Path("auditor/exemplars")


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    with path.open() as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"WARN {path}:{i} malformed JSON: {exc}", file=sys.stderr)
    return records


def load_exemplars_by_rule() -> dict[str, list[str]]:
    """Scan auditor/exemplars/*.md for `exemplifies:` frontmatter lists.

    Returns a dict mapping rule_id → list of exemplar slugs that cite it.
    Used to enrich rule_metrics with `exemplars_count` and `exemplar_slugs`
    so rule-health can answer "which rules have real-world positive
    references" not just "which rules have findings against them."

    A rule with high `hits` and zero `exemplars_count` is a rule we know
    how to break but not how to follow — actionable signal for rule-refine.
    """
    by_rule: dict[str, list[str]] = defaultdict(list)
    if not EXEMPLARS_DIR.exists():
        return dict(by_rule)
    for path in sorted(EXEMPLARS_DIR.glob("*.md")):
        text = path.read_text(errors="ignore")
        # Extract frontmatter between the opening `---` and the first
        # following `---` line. Lazy DOTALL so the second `---` is the
        # closer, not a later one in the body.
        fm_match = re.match(r"^---\n(.*?)\n---\s*$", text, re.DOTALL | re.MULTILINE)
        if not fm_match:
            fm_match = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
        if not fm_match:
            continue
        frontmatter = fm_match.group(1)
        slug_match = re.search(r"^slug:\s*([\S]+)", frontmatter, re.MULTILINE)
        slug = slug_match.group(1) if slug_match else path.stem
        # Walk frontmatter lines. After `exemplifies:`, every indented
        # `- R##` line is an entry; stop at the first non-indented-list line.
        in_list = False
        rules_for_this_file: list[str] = []
        for line in frontmatter.splitlines():
            if re.match(r"^exemplifies:\s*$", line):
                in_list = True
                continue
            if not in_list:
                continue
            m = re.match(r"^[ \t]+-[ \t]+(R\d{2})\b", line)
            if m:
                rules_for_this_file.append(m.group(1))
                continue
            # A top-level key (no leading space) ends the list. A blank
            # line is tolerated but doesn't end the list — YAML allows it.
            if line and not line.startswith((" ", "\t")):
                in_list = False
        for rid in rules_for_this_file:
            by_rule[rid].append(slug)
    return dict(by_rule)


def load_catalog_rules() -> set[str]:
    if not RULES_CATALOG.exists():
        return set()
    text = RULES_CATALOG.read_text()
    return set(re.findall(r"\bR\d{2}\b", text))


def classify_rule(metrics: dict) -> str:
    hits = metrics["hits"]
    contributed = metrics["contributed"]
    self_fp = metrics["self_fp"]
    maintainer_rejected = metrics["maintainer_rejected"]
    downstream = metrics["downstream_suppressions"]
    merged = metrics["merged"]
    applied_separately = metrics.get("applied_separately", 0)
    closed_unmerged = metrics.get("closed_unmerged", 0)
    verified_total = metrics.get("verified_total", 0)
    verified_fixed = metrics.get("verified_fixed", 0)

    # Disputed first — downstream suppressions and maintainer rejection outrank
    # self-precision, since those represent external dissent the auditor
    # can't resolve alone.
    if downstream >= 2:
        return "disputed"
    if contributed >= 3 and maintainer_rejected / contributed > 0.3:
        return "disputed"

    # Noisy: high false-positive rate (self-known or externally inferred).
    if hits >= 3 and self_fp / hits > 0.2:
        return "noisy"

    # Verified signal — when the re-audit has run for enough findings,
    # weight it above the merged signal. A PR that merged but left the
    # finding in place (persists_*) counts against the rule here, where
    # `merged / contributed` would have counted it for.
    if verified_total >= 3:
        if verified_fixed / verified_total < 0.5:
            return "noisy"
    else:
        # Fall back to PR-level signal when re-audit hasn't accumulated yet.
        # Use resolved-only rate so that open PRs don't count against the
        # rule. `applied_separately` PRs count alongside merged — both are
        # positive maintainer judgments ("the bug is real"), they just took
        # different paths to land. Concrete case: avifenesh closed three
        # CC-stale-count PRs with "the issue you flagged is real. Closing
        # in favor of the consolidated structural fix in #840" — that is a
        # win, not a failure.
        accepted = merged + applied_separately
        resolved = accepted + closed_unmerged
        if resolved >= 3 and accepted / resolved < 0.5:
            return "noisy"

    return "healthy"


def main() -> int:
    findings = load_jsonl(FINDINGS_PATH)
    events = load_jsonl(EVENTS_PATH)
    disagreements = load_jsonl(DISAGREEMENTS_PATH)

    try:
        with REGISTRY_PATH.open() as fh:
            registry = json.load(fh)
    except (OSError, json.JSONDecodeError):
        registry = {"repos": {}}

    # Index finding_outcome events by fingerprint. When a fingerprint appears
    # multiple times (e.g., open → merged), the LAST entry wins. events.jsonl
    # is append-only and chronologically ordered, so a simple final-write loop
    # gives the latest state.
    outcome_by_fp: dict[str, str] = {}
    for e in events:
        if e.get("event") != "finding_outcome":
            continue
        data = e.get("data", {})
        state = data.get("pr_state")
        if not state:
            continue
        for fp in data.get("fingerprints", []) or []:
            outcome_by_fp[fp] = state

    # The SCHEMAS pr_state enum is {merged, closed_unmerged, open, stale_90d,
    # cla_blocked} — `applied_separately` is NOT in the enum. The track
    # workflow maps both `rejected` and `applied_separately` outcomes to
    # `closed_unmerged` for event emission, which loses the positive signal
    # for rule-health. Cross-reference the registry's authoritative
    # `prs[].outcome` field to recover the distinction. Findings whose
    # fingerprint maps to a PR with outcome=applied_separately get
    # reclassified into a separate bucket that the classifier credits as
    # positive (alongside merged), not as a failure.
    #
    # Concrete case: agent-sh/agnix #828/#829/#830 closed_unmerged but
    # applied separately in #840 (avifenesh: "the issue you flagged is
    # real. Closing in favor of the consolidated structural fix in #840").
    # CC-stale-count was being classified noisy because rule-health saw
    # 4 closed_unmerged with 0 merged. After this fix, three of those four
    # become applied_separately and the rule clears.
    applied_separately_by_fp: set[str] = set()
    for slug, repo_data in registry.get("repos", {}).items():
        for pr in repo_data.get("prs") or []:
            if pr.get("outcome") != "applied_separately":
                continue
            for fp in pr.get("fingerprints") or []:
                applied_separately_by_fp.add(fp)

    # Index finding_verified events by fingerprint. Same last-write-wins rule
    # applies — a finding can be re-audited more than once (e.g., a case
    # study is regenerated after a new maintainer commit). The verify
    # outcome is an enum documented in SCHEMAS.md §finding_verified.
    FIXED_OUTCOMES = {
        "fixed_and_merged",
        "fixed_applied_separately",
        "fixed_upstream_not_merged",
    }
    PERSISTS_OUTCOMES = {"persists_identically", "persists_line_shifted"}
    verified_by_fp: dict[str, str] = {}
    for e in events:
        if e.get("event") != "finding_verified":
            continue
        data = e.get("data", {})
        fp = data.get("fingerprint")
        outcome = data.get("outcome")
        if fp and outcome:
            verified_by_fp[fp] = outcome

    # Count finding_introduced events per rule. These are NOT in findings.jsonl
    # (by design — re-audit findings don't inflate reach), so they need a
    # separate aggregation path.
    introduced_by_rule: Counter[str] = Counter()
    for e in events:
        if e.get("event") != "finding_introduced":
            continue
        rid = e.get("data", {}).get("rule_id")
        if rid:
            introduced_by_rule[rid] += 1

    self_fp_fps = {
        d.get("fingerprint")
        for d in disagreements
        if d.get("event") == "self_false_positive" and d.get("fingerprint")
    }

    # Registry outcome per PR. Needed before dissent is counted, because a
    # maintainer closing our PR to land the same fix elsewhere produces a
    # `maintainer_rejected` record that is not a rejection of the finding.
    pr_outcome: dict[str, str] = {}
    for slug, repo_data in registry.get("repos", {}).items():
        for pr in repo_data.get("prs") or []:
            number = pr.get("number")
            outcome = pr.get("outcome")
            if number is not None and outcome:
                pr_outcome[f"{slug}#{number}"] = outcome

    # Repos that reached the global findings log at all. Audits run before
    # the per-audit sidecar shipped (the log's first record is dated
    # 2026-04-25) wrote a human-readable report and nothing machine-readable,
    # so their findings have no fingerprints anywhere — nothing to join to,
    # and nothing a backfill could honestly reconstruct.
    repos_with_findings = {f.get("repo") for f in findings if f.get("repo")}

    # A PR the maintainer merged, or closed because the fix landed in
    # another PR, is an accepted finding however the comment thread reads.
    # The classifier labels "Closing as superseded by #333" as dissent with
    # dissent_type context_missed; the registry knows better, because the
    # track workflow recorded the outcome. Without this guard the same
    # fingerprints are credited as applied_separately AND counted as
    # maintainer_rejected, and the rule is penalised for a win. Measured on
    # 2026-08-12: 9 of 25 fingerprinted dissent records sat on accepted PRs
    # (agent-sh/agnix #828-#830, googleworkspace/cli #757-#760,
    # tanweai/pua #154-#155), every one of them labelled context_missed.
    ACCEPTED_OUTCOMES = {"merged", "applied_separately"}

    # An append-only log cannot rewrite a record, so a hand-attributed
    # rejection is appended alongside the empty original. Count the PR once:
    # if any record for it carries fingerprints, the empty one is superseded
    # and is not an outstanding gap.
    dissent_attributed_prs = {
        d.get("pr")
        for d in disagreements
        if d.get("event") in ("maintainer_rejected", "maintainer_pushback")
        and d.get("fingerprints")
        and d.get("pr")
    }

    rejected_by_fp: dict[str, list[dict]] = defaultdict(list)
    dissent_accepted_elsewhere = 0
    dissent_unattributed_legacy = 0
    dissent_unattributed_live = 0
    for d in disagreements:
        if d.get("event") not in ("maintainer_rejected", "maintainer_pushback"):
            continue
        if pr_outcome.get(d.get("pr")) in ACCEPTED_OUTCOMES:
            dissent_accepted_elsewhere += 1
            continue
        fingerprints = d.get("fingerprints", []) or []
        if not fingerprints and d.get("pr") in dissent_attributed_prs:
            continue
        if not fingerprints:
            # Split the blind spot by whether recovery is even possible, so
            # the pre-sidecar backlog can't hide a live attribution bug.
            # `live` means the repo HAS findings in the log and this record
            # still carries none — that is a break in the metadata block or
            # the classifier, and it is actionable today.
            slug = (d.get("pr") or d.get("issue") or "").rsplit("#", 1)[0]
            if slug and slug in repos_with_findings:
                dissent_unattributed_live += 1
            else:
                dissent_unattributed_legacy += 1
            continue
        for fp in fingerprints:
            rejected_by_fp[fp].append(d)

    # Issue-lane dissent — records keyed on `issue` rather than `pr`, per
    # SCHEMAS §Issue-lane variant. These arrive when the target repo accepts
    # no external PRs, so the findings were filed as an issue and no PR
    # exists to track. auditor-track.yml polls pull requests only, so an
    # issue-lane fingerprint never gets a finding_outcome event and would
    # otherwise land in maintainer_rejected while leaving `contributed` at
    # 0 — a denominator of zero means classify_rule's disputed branch can
    # never fire on dissent that arrived through an issue. Map each
    # fingerprint to its event name so a rejection can also count as a
    # resolved-negative, the way closed_unmerged does in the PR lane;
    # maintainer_pushback is deliberately excluded from that second use,
    # since pushback means the objection did not end the contribution.
    issue_lane_by_fp: dict[str, str] = {}
    for d in disagreements:
        event = d.get("event")
        if event not in ("maintainer_rejected", "maintainer_pushback"):
            continue
        if not d.get("issue"):
            continue
        for fp in d.get("fingerprints", []) or []:
            # A rejection outranks a pushback on the same fingerprint.
            if issue_lane_by_fp.get(fp) != "maintainer_rejected":
                issue_lane_by_fp[fp] = event

    suppressions_by_rule: dict[str, list[dict]] = defaultdict(list)
    for d in disagreements:
        if d.get("event") != "downstream_suppression":
            continue
        rid = d.get("rule_id")
        if rid:
            suppressions_by_rule[rid].append(d)

    findings_by_rule: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        rid = f.get("rule_id")
        if rid:
            findings_by_rule[rid].append(f)

    # v0.8.18 — compute drift mask so "rules with high hits but no exemplars"
    # doesn't inflate on scorer mislabels. The 2026-05-13 investigation
    # found R22 with 127 "hits" of which 126 were drift (R22 is a
    # `.claude/rules/` rule; scorer applied it to SKILL.md files for
    # vague-step-no-command patterns that should map to R01/R06/R14).
    # The drift validator is the same one wired into auditor-audit.yml.
    drift_by_fingerprint: set[str] = set()
    try:
        sys.path.insert(0, str(REGISTRY_PATH.parent.parent / "scripts"))
        import importlib.util as _il
        _spec = _il.spec_from_file_location(
            "_validator",
            Path(__file__).parent / "validate-rule-ids.py",
        )
        if _spec and _spec.loader:
            _mod = _il.module_from_spec(_spec)
            sys.modules["_validator"] = _mod
            _spec.loader.exec_module(_mod)
            _rubric = _mod.parse_rubric(
                Path("skills/nlpm/scoring/SKILL.md"),
                Path("skills/nlpm/rules/SKILL.md"),
            )
            # Re-walk the findings through the validator to identify which
            # are drift. The validator works on .findings.jsonl files —
            # synthesize a temp file from the global log for the same check.
            import tempfile, json as _json
            with tempfile.NamedTemporaryFile(
                "w", suffix=".jsonl", delete=False
            ) as _tf:
                for f in findings:
                    _tf.write(_json.dumps(f) + "\n")
                _tf_path = Path(_tf.name)
            drifts = _mod.validate_findings(_tf_path, _rubric)
            _tf_path.unlink(missing_ok=True)
            # Drift detection happens at the finding-line level. Mark the
            # fingerprints whose records drifted; rule-health then counts
            # drift hits separately from validated hits.
            drift_finding_indices = {d.line_no - 1 for d in drifts}
            for i, f in enumerate(findings):
                if i in drift_finding_indices and f.get("fingerprint"):
                    drift_by_fingerprint.add(f["fingerprint"])
    except Exception as e:  # validator is optional — never block on it
        print(f"WARN: drift filter unavailable: {e}", file=sys.stderr)

    rule_metrics: dict[str, dict] = {}
    for rid, fs in findings_by_rule.items():
        unique_fps = {f["fingerprint"] for f in fs if f.get("fingerprint")}
        issue_lane_fps = {fp for fp in unique_fps if fp in issue_lane_by_fp}
        contributed = sum(
            1 for fp in unique_fps if fp in outcome_by_fp or fp in issue_lane_fps
        )
        merged = sum(1 for fp in unique_fps if outcome_by_fp.get(fp) == "merged")
        applied_separately = len(unique_fps & applied_separately_by_fp)
        # Don't double-count: a fingerprint marked applied_separately in
        # the registry will also have pr_state=closed_unmerged in events
        # (until the SCHEMAS enum gets extended). Subtract only those
        # applied-separately fingerprints that ALSO have a closed_unmerged
        # event — otherwise the subtraction can drive the count negative
        # when the registry has applied fingerprints that never got a
        # matching event (e.g., legacy attribution).
        closed_unmerged_fps = {
            fp for fp in unique_fps if outcome_by_fp.get(fp) == "closed_unmerged"
        }
        # An issue closed by the maintainer as a rejection is the issue-lane
        # equivalent of a PR closed unmerged: the contribution is resolved
        # and it did not land. Union, so a fingerprint carrying both a PR
        # outcome and an issue-lane rejection counts once.
        closed_unmerged_fps |= {
            fp
            for fp in issue_lane_fps
            if issue_lane_by_fp.get(fp) == "maintainer_rejected"
        }
        closed_unmerged = len(closed_unmerged_fps - applied_separately_by_fp)
        open_count = sum(1 for fp in unique_fps if outcome_by_fp.get(fp) == "open")
        self_fp = len(unique_fps & self_fp_fps)
        maintainer_rejected = sum(1 for fp in unique_fps if fp in rejected_by_fp)

        # Verified metrics — finding_verified events joined on fingerprint.
        verified_outcomes = [
            verified_by_fp[fp] for fp in unique_fps if fp in verified_by_fp
        ]
        verified_total = len(verified_outcomes)
        verified_fixed = sum(1 for o in verified_outcomes if o in FIXED_OUTCOMES)
        verified_persists = sum(1 for o in verified_outcomes if o in PERSISTS_OUTCOMES)
        verify_rate = (
            verified_fixed / verified_total if verified_total else None
        )

        dissent_types: Counter[str] = Counter()
        for fp in unique_fps:
            for d in rejected_by_fp.get(fp, []):
                dt = d.get("dissent_type")
                if dt:
                    dissent_types[dt] += 1

        # Drift: how many of this rule's findings were scorer mislabels?
        # validated_hits = hits - drift_hits is what every "needs attention"
        # query should actually consume; raw hits inflate on scorer noise.
        drift_hits = sum(1 for fp in unique_fps if fp in drift_by_fingerprint)
        validated_hits = max(0, len(fs) - drift_hits)

        metrics = {
            "hits": len(fs),
            "drift_hits": drift_hits,
            "validated_hits": validated_hits,
            "unique_fingerprints": len(unique_fps),
            "contributed": contributed,
            "merged": merged,
            "applied_separately": applied_separately,
            "closed_unmerged": closed_unmerged,
            "open": open_count,
            "self_fp": self_fp,
            "maintainer_rejected": maintainer_rejected,
            "downstream_suppressions": len(suppressions_by_rule.get(rid, [])),
            "dissent_types": dict(dissent_types),
            "verified_total": verified_total,
            "verified_fixed": verified_fixed,
            "verified_persists": verified_persists,
            "verify_rate": verify_rate,
            "introduced": introduced_by_rule.get(rid, 0),
        }
        metrics["state"] = classify_rule(metrics)
        rule_metrics[rid] = metrics

    # A rule might fire ONLY in a post-merge re-audit (finding_introduced
    # with no prior finding in findings.jsonl). Surface those too, with
    # hits=0 so consumers see the introduced-only signal without conflating
    # it with reach.
    for rid, introduced_count in introduced_by_rule.items():
        if rid in rule_metrics:
            continue
        rule_metrics[rid] = {
            "hits": 0,
            "unique_fingerprints": 0,
            "contributed": 0,
            "merged": 0,
            "closed_unmerged": 0,
            "open": 0,
            "self_fp": 0,
            "maintainer_rejected": 0,
            "downstream_suppressions": len(suppressions_by_rule.get(rid, [])),
            "dissent_types": {},
            "verified_total": 0,
            "verified_fixed": 0,
            "verified_persists": 0,
            "verify_rate": None,
            "introduced": introduced_count,
            "state": "healthy",  # nothing to judge yet — introduced-only
        }

    # v0.8.17 — enrich each rule's metrics with exemplar counts. A rule
    # with hits=many but exemplars_count=0 is one we know how to break but
    # not how to follow: a signal for rule-refine to either re-word the
    # rule or actively hunt exemplars on the always-clean path.
    exemplars_by_rule = load_exemplars_by_rule()
    for rid, slugs in exemplars_by_rule.items():
        rule_metrics.setdefault(rid, {
            "hits": 0,
            "unique_fingerprints": 0,
            "contributed": 0,
            "merged": 0,
            "closed_unmerged": 0,
            "open": 0,
            "self_fp": 0,
            "maintainer_rejected": 0,
            "downstream_suppressions": 0,
            "dissent_types": {},
            "verified_total": 0,
            "verified_fixed": 0,
            "verified_persists": 0,
            "verify_rate": None,
            "introduced": 0,
            "state": "healthy",
        })
        rule_metrics[rid]["exemplars_count"] = len(slugs)
        rule_metrics[rid]["exemplar_slugs"] = slugs
    # Backfill exemplars_count=0 on rules that have hits but no exemplars yet
    for rid, m in rule_metrics.items():
        m.setdefault("exemplars_count", 0)
        m.setdefault("exemplar_slugs", [])

    # Dormant: catalog R* rules with zero findings. SEC/BUG/CC namespaces are
    # dynamic — no authoritative inventory — so dormant detection is catalog-only.
    catalog = load_catalog_rules()
    dormant_rules = sorted(catalog - set(rule_metrics.keys()))

    # Non-catalog rule_ids that appeared in findings — useful for spotting
    # new SEC-* patterns or UNCLASSIFIED drift.
    unclassified_ids = sorted(set(rule_metrics.keys()) - catalog)

    # PR scorecard from the registry (drop-in for the old summary).
    all_prs = []
    for _, v in registry.get("repos", {}).items():
        all_prs.extend(v.get("prs", []) or [])

    merged_prs = [p for p in all_prs if p.get("outcome") == "merged"]
    applied_prs = [p for p in all_prs if p.get("outcome") == "applied_separately"]
    rejected_prs = [p for p in all_prs if p.get("outcome") == "rejected"]
    open_prs = [p for p in all_prs if p.get("outcome") == "open"]
    accepted = len(merged_prs) + len(applied_prs)
    resolved = accepted + len(rejected_prs)

    rule_adopted = [
        k for k, v in registry.get("repos", {}).items() if v.get("rule_adopted") is True
    ]

    # Top rules for the report's Rule Frequency table — ordered by hits.
    top_rules = sorted(
        rule_metrics.items(), key=lambda kv: -kv[1]["hits"]
    )[:10]

    summary = {
        "prs_total": len(all_prs),
        "prs_merged": len(merged_prs),
        "prs_applied_separately": len(applied_prs),
        "prs_rejected": len(rejected_prs),
        "prs_pending": len(open_prs),
        "acceptance_rate": f"{accepted / resolved * 100:.0f}%" if resolved else "N/A",
        "merge_only_rate": f"{len(merged_prs) / resolved * 100:.0f}%" if resolved else "N/A",
        "rule_adopted_repos": rule_adopted,
        # Dissent that never reached a rule. Reported rather than silently
        # dropped: a shrinking `live` count is the signal that attribution
        # is working, and a non-zero one is a bug to chase. `legacy` is the
        # pre-sidecar backlog and is expected to stay fixed.
        "dissent_accepted_elsewhere": dissent_accepted_elsewhere,
        "dissent_unattributed_legacy": dissent_unattributed_legacy,
        "dissent_unattributed_live": dissent_unattributed_live,
        "top_rules": [(rid, m["hits"]) for rid, m in top_rules],
        "rule_metrics": rule_metrics,
        "dormant_rules": dormant_rules,
        "unclassified_ids": unclassified_ids,
        "state_counts": dict(
            Counter(m["state"] for m in rule_metrics.values())
        ),
        "dormant_count": len(dormant_rules),
        "exemplars_total": sum(len(s) for s in exemplars_by_rule.values()),
        "exemplars_unique_repos": len({
            slug for slugs in exemplars_by_rule.values() for slug in slugs
        }),
        "rules_with_exemplars": sum(
            1 for m in rule_metrics.values() if m.get("exemplars_count", 0) > 0
        ),
        # Only flag R-numbered catalog rules — BUG-/CC-/SEC-/AGENT-/UNCLASSIFIED
        # are bug categories with no exemplar concept (you don't exemplify
        # "missing frontmatter"; you exemplify "well-written frontmatter").
        # Use validated_hits, NOT hits — the 2026-05-13 R22 investigation
        # found 126/127 R22 hits were scorer drift (R22 is for .claude/rules/
        # but the LLM was applying it to SKILL.md for vague-step patterns
        # that should map to R01/R06/R14). Raw hits would surface R22 here
        # forever; validated_hits filters those out.
        "rules_high_hits_no_exemplar": sorted([
            rid for rid, m in rule_metrics.items()
            if re.fullmatch(r"R\d{2}", rid)
            and m.get("validated_hits", m.get("hits", 0)) >= 50
            and m.get("exemplars_count", 0) == 0
        ]),
    }

    # Mirror into auditor/feedback/log.json so the legacy shape continues
    # to carry the fields older tooling might read. Only the fields that
    # the old pipeline wrote are kept here.
    feedback_path = Path("auditor/feedback/log.json")
    if feedback_path.exists():
        try:
            with feedback_path.open() as fh:
                feedback = json.load(fh)
        except (OSError, json.JSONDecodeError):
            # validate-feedback.sh expects `events` to be present; default
            # shape must include it so validation doesn't fail on first
            # fresh write or after a recovered crash.
            feedback = {"metadata": {}, "rule_stats": {}, "events": []}
    else:
        feedback = {"metadata": {}, "rule_stats": {}, "events": []}

    feedback.setdefault("metadata", {}).update({
        "total_prs_submitted": len(all_prs),
        "total_prs_merged": len(merged_prs),
        "total_prs_applied_separately": len(applied_prs),
        "total_prs_rejected": len(rejected_prs),
        "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })
    feedback.setdefault("rule_stats", {})
    for rid, m in rule_metrics.items():
        feedback["rule_stats"].setdefault(
            rid, {"total_hits": 0, "led_to_merged_pr": 0, "led_to_rejected_pr": 0}
        )
        feedback["rule_stats"][rid].update({
            "total_hits": m["hits"],
            "led_to_merged_pr": m["merged"],
            "led_to_rejected_pr": m["closed_unmerged"],
            "self_false_positive": m["self_fp"],
            "maintainer_rejected": m["maintainer_rejected"],
            "downstream_suppressions": m["downstream_suppressions"],
            "verified_fixed": m["verified_fixed"],
            "verified_persists": m["verified_persists"],
            "verify_rate": m["verify_rate"],
            "introduced_since_audit": m["introduced"],
            "state": m["state"],
        })
    with feedback_path.open("w") as fh:
        json.dump(feedback, fh, indent=2)

    out = json.dumps(summary, indent=2)
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(out)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
