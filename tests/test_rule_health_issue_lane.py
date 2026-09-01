"""Tests for issue-lane dissent accounting in rule-health.py.

A `maintainer_rejected` record keyed on `issue` rather than `pr` reaches
rule-health through a path with no `finding_outcome` event behind it,
because auditor-track.yml polls pull requests only. These tests pin the
two consequences that follow:

1. The fingerprint counts as `contributed`, so classify_rule's disputed
   branch has a non-zero denominator to divide by.
2. A rejection also counts as `closed_unmerged` (the issue-lane analogue
   of a PR closed without merging), while a pushback does not.

Regression origin: mattpocock/skills#164 — four BUG-missing-manifest-entry
findings filed as an issue on 2026-05-11 and closed by the owner with
"Yep, this is intentional". The rejection sat unrecorded for three months,
and once recorded would have been inert without the denominator fix.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULE_HEALTH = REPO_ROOT / "auditor" / "scripts" / "rule-health.py"

FP = "sha256:" + "a" * 64
OTHER_FP = "sha256:" + "b" * 64


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _finding(fingerprint: str, rule_id: str = "BUG-missing-manifest-entry") -> dict:
    return {
        "event": "finding",
        "repo": "owner/repo",
        "fingerprint": fingerprint,
        "rule_id": rule_id,
        "file": ".claude-plugin/plugin.json",
        "line": None,
        "category": "bug",
        "severity": "high",
        "pattern": "skill-missing-from-plugin-json",
        "description": "d",
        "false_positive": False,
        "suggested_fix": "f",
    }


def _dissent(event: str, key: str, value: str, fingerprint: str) -> dict:
    return {
        "event": event,
        "timestamp": "2026-05-11T08:06:24Z",
        key: value,
        "fingerprints": [fingerprint],
        "rule_ids": ["BUG-missing-manifest-entry"],
        "dissent_type": "intentional_pattern",
        "quote": "Yep, this is intentional",
        "commenter_role": "maintainer",
        "classifier_model": "manual-backfill",
        "classifier_confidence": "high",
    }


class IssueLaneAccountingTest(unittest.TestCase):
    """rule-health.py: dissent that arrived as an issue, not a PR."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "auditor" / "logs").mkdir(parents=True)
        (self.root / "auditor" / "registry").mkdir(parents=True)
        (self.root / "auditor" / "feedback").mkdir(parents=True)
        (self.root / "auditor" / "logs" / "events.jsonl").write_text("")
        (self.root / "auditor" / "registry" / "repos.json").write_text('{"repos": {}}')

    def _run(self, findings: list[dict], disagreements: list[dict]) -> dict:
        auditor = self.root / "auditor"
        (auditor / "findings.jsonl").write_text(
            "".join(json.dumps(f) + "\n" for f in findings)
        )
        (auditor / "disagreements.jsonl").write_text(
            "".join(json.dumps(d) + "\n" for d in disagreements)
        )
        out = self.root / "summary.json"
        cwd = os.getcwd()
        argv = sys.argv[:]
        os.chdir(self.root)
        sys.argv = ["rule-health.py", str(out)]
        try:
            module = _load_module("rule_health_issue_lane", RULE_HEALTH)
            self.assertEqual(module.main(), 0)
        finally:
            os.chdir(cwd)
            sys.argv = argv
        summary = json.loads(out.read_text())
        return summary["rule_metrics"]["BUG-missing-manifest-entry"]

    def test_issue_lane_rejection_counts_as_contributed(self) -> None:
        """The denominator classify_rule divides by is no longer zero."""
        metrics = self._run(
            [_finding(FP)],
            [_dissent("maintainer_rejected", "issue", "owner/repo#164", FP)],
        )
        self.assertEqual(metrics["maintainer_rejected"], 1)
        self.assertEqual(
            metrics["contributed"],
            1,
            "issue-lane dissent must count as a contribution; a zero "
            "denominator makes the disputed branch unreachable",
        )

    def test_issue_lane_rejection_counts_as_closed_unmerged(self) -> None:
        """A rejected issue is resolved-and-did-not-land, like closed_unmerged."""
        metrics = self._run(
            [_finding(FP)],
            [_dissent("maintainer_rejected", "issue", "owner/repo#164", FP)],
        )
        self.assertEqual(metrics["closed_unmerged"], 1)
        self.assertEqual(metrics["merged"], 0)

    def test_issue_lane_pushback_is_contributed_but_not_resolved(self) -> None:
        """Pushback means the objection did not end the contribution."""
        metrics = self._run(
            [_finding(FP)],
            [_dissent("maintainer_pushback", "issue", "owner/repo#164", FP)],
        )
        self.assertEqual(metrics["contributed"], 1)
        self.assertEqual(
            metrics["closed_unmerged"],
            0,
            "pushback leaves the contribution open, so it is not a "
            "resolved-negative",
        )

    def test_pr_lane_fingerprint_without_outcome_stays_uncontributed(self) -> None:
        """The fix is scoped to `issue`; a `pr` record keeps the old behaviour."""
        metrics = self._run(
            [_finding(FP)],
            [_dissent("maintainer_rejected", "pr", "owner/repo#123", FP)],
        )
        self.assertEqual(metrics["maintainer_rejected"], 1)
        self.assertEqual(
            metrics["contributed"],
            0,
            "a PR-lane rejection is contributed only via its "
            "finding_outcome event, which this fixture does not emit",
        )

    def test_unrelated_fingerprint_is_untouched(self) -> None:
        """Issue-lane accounting joins on fingerprint, not on rule id."""
        metrics = self._run(
            [_finding(FP), _finding(OTHER_FP)],
            [_dissent("maintainer_rejected", "issue", "owner/repo#164", FP)],
        )
        self.assertEqual(metrics["hits"], 2)
        self.assertEqual(metrics["unique_fingerprints"], 2)
        self.assertEqual(metrics["contributed"], 1)
        self.assertEqual(metrics["maintainer_rejected"], 1)


if __name__ == "__main__":
    unittest.main()
