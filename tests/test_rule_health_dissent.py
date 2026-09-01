"""Tests for what counts as maintainer dissent in rule-health.py.

The classifier reads a comment thread and labels "Closing in favor of the
consolidated structural fix in #840" as dissent, because on the surface it
looks like a refusal. The registry knows better: the track workflow already
recorded that PR's outcome as applied_separately. Counting it as dissent
penalises a rule for a win, and the same fingerprints end up simultaneously
credited (applied_separately) and penalised (maintainer_rejected).

Measured on 2026-08-12 before the fix: 9 of 25 fingerprinted dissent records
sat on accepted PRs, every one labelled context_missed. Two rules were
classified disputed purely from that miscount — CC-stale-count (4 of 4
rejections were acceptances) and SEC-unpinned-semver.

The second group of tests covers dissent that joins to nothing. Audits that
ran before the per-audit sidecar shipped (the global findings log begins
2026-04-25) produced no machine-readable findings, so their fingerprints do
not exist and no backfill can honestly reconstruct them. Those are counted
and reported rather than silently dropped, and split from the `live` case —
a repo that HAS findings whose dissent still carries none, which is a break
in the metadata block and is actionable today.
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

RULE = "CC-stale-count"
FP = "sha256:" + "c" * 64


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _finding(repo: str = "owner/repo", fingerprint: str = FP) -> dict:
    return {
        "event": "finding",
        "repo": repo,
        "fingerprint": fingerprint,
        "rule_id": RULE,
        "file": "README.md",
        "line": None,
        "category": "cross_component",
        "severity": "high",
        "pattern": "stale-count",
        "description": "d",
        "false_positive": False,
        "suggested_fix": "f",
    }


def _dissent(pr: str, fingerprints: list[str], quote: str = "q") -> dict:
    return {
        "event": "maintainer_rejected",
        "timestamp": "2026-04-23T13:04:09Z",
        "pr": pr,
        "fingerprints": fingerprints,
        "rule_ids": [RULE],
        "dissent_type": "context_missed",
        "quote": quote,
        "commenter_role": "maintainer",
        "classifier_model": "haiku-4-5",
        "classifier_confidence": "high",
    }


def _registry(pr_number: int, outcome: str, repo: str = "owner/repo") -> dict:
    return {
        "repos": {
            repo: {
                "prs": [
                    {
                        "number": pr_number,
                        "outcome": outcome,
                        "fingerprints": [],
                        "rule_ids": [],
                    }
                ]
            }
        }
    }


class DissentAccountingTest(unittest.TestCase):
    """rule-health.py: which records count against a rule."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "auditor" / "logs").mkdir(parents=True)
        (self.root / "auditor" / "registry").mkdir(parents=True)
        (self.root / "auditor" / "feedback").mkdir(parents=True)
        (self.root / "auditor" / "logs" / "events.jsonl").write_text("")

    def _run(
        self,
        findings: list[dict],
        disagreements: list[dict],
        registry: dict | None = None,
    ) -> dict:
        auditor = self.root / "auditor"
        (auditor / "findings.jsonl").write_text(
            "".join(json.dumps(f) + "\n" for f in findings)
        )
        (auditor / "disagreements.jsonl").write_text(
            "".join(json.dumps(d) + "\n" for d in disagreements)
        )
        (auditor / "registry" / "repos.json").write_text(
            json.dumps(registry or {"repos": {}})
        )
        out = self.root / "summary.json"
        cwd, argv = os.getcwd(), sys.argv[:]
        os.chdir(self.root)
        sys.argv = ["rule-health.py", str(out)]
        try:
            module = _load_module("rule_health_dissent", RULE_HEALTH)
            self.assertEqual(module.main(), 0)
        finally:
            os.chdir(cwd)
            sys.argv = argv
        return json.loads(out.read_text())

    def test_dissent_on_applied_separately_pr_is_not_a_rejection(self) -> None:
        """"Closing in favor of #840" is a win, not dissent."""
        summary = self._run(
            [_finding()],
            [_dissent("owner/repo#828", [FP], "Closing in favor of #840")],
            _registry(828, "applied_separately"),
        )
        metrics = summary["rule_metrics"][RULE]
        self.assertEqual(metrics["maintainer_rejected"], 0)
        self.assertEqual(summary["dissent_accepted_elsewhere"], 1)

    def test_dissent_on_merged_pr_is_not_a_rejection(self) -> None:
        """A merged PR settles the finding whatever the thread reads like."""
        summary = self._run(
            [_finding()],
            [_dissent("owner/repo#900", [FP])],
            _registry(900, "merged"),
        )
        self.assertEqual(summary["rule_metrics"][RULE]["maintainer_rejected"], 0)

    def test_dissent_on_rejected_pr_still_counts(self) -> None:
        """The guard must not swallow genuine dissent."""
        summary = self._run(
            [_finding()],
            [_dissent("owner/repo#340", [FP], "caret ranges are intentional")],
            _registry(340, "rejected"),
        )
        self.assertEqual(summary["rule_metrics"][RULE]["maintainer_rejected"], 1)
        self.assertEqual(summary["dissent_accepted_elsewhere"], 0)

    def test_dissent_on_pr_absent_from_registry_still_counts(self) -> None:
        """Unknown outcome is not an accepted outcome."""
        summary = self._run(
            [_finding()],
            [_dissent("owner/repo#999", [FP])],
            {"repos": {}},
        )
        self.assertEqual(summary["rule_metrics"][RULE]["maintainer_rejected"], 1)

    def test_unattributed_dissent_splits_legacy_from_live(self) -> None:
        """A repo with findings whose dissent has none is a live bug."""
        summary = self._run(
            [_finding(repo="owner/repo")],
            [
                # Repo has findings, record has none -> live, actionable.
                _dissent("owner/repo#500", []),
                # Repo never reached the findings log -> pre-sidecar legacy.
                _dissent("legacy/target#12", []),
            ],
            {"repos": {}},
        )
        self.assertEqual(summary["dissent_unattributed_live"], 1)
        self.assertEqual(summary["dissent_unattributed_legacy"], 1)

    def test_hand_attributed_record_supersedes_the_empty_original(self) -> None:
        """Append-only means the empty record stays; it must not double-count."""
        summary = self._run(
            [_finding()],
            [
                _dissent("owner/repo#340", []),
                _dissent("owner/repo#340", [FP]),
            ],
            _registry(340, "rejected"),
        )
        self.assertEqual(summary["rule_metrics"][RULE]["maintainer_rejected"], 1)
        self.assertEqual(
            summary["dissent_unattributed_live"],
            0,
            "the empty record is superseded by the attributed one and is "
            "no longer an outstanding gap",
        )


if __name__ == "__main__":
    unittest.main()
