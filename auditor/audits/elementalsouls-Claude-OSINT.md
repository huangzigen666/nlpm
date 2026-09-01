# NLPM Audit: elementalsouls/Claude-OSINT
**Date**: 2026-04-06  |  **Artifacts**: 10  |  **Strategy**: single
**NL Score**: 97/100
**Security**: REVIEW
**Bugs**: 0  |  **Quality Issues**: 11  |  **Security Findings**: 5

## NL Score Summary
| File | Type | Score | Top Issue |
|------|------|-------|-----------|
| skills/offensive-osint/SKILL.md | skill | 93 | 4,556 lines vs. R05's 500-line guideline (9x over); one vague quantifier ("appropriate sources", R01) |
| skills/osint-autopilot/SKILL.md | skill | 93 | Only skill in the pack missing `version:`/`triggers:` frontmatter; also undocumented anywhere else in the repo |
| skills/exposure-risk-quantification/SKILL.md | skill | 95 | Duplicate `14.` numbering in the §13 self-test list; 748 lines over R05 |
| skills/cloud-saas-exposure/SKILL.md | skill | 97 | 802 lines vs. R05's 500-line guideline |
| skills/continuous-exposure-monitoring/SKILL.md | skill | 97 | 811 lines vs. R05's 500-line guideline |
| skills/email-domain-security/SKILL.md | skill | 97 | 589 lines vs. R05's 500-line guideline |
| skills/identity-provider-recon/SKILL.md | skill | 97 | 968 lines vs. R05's 500-line guideline |
| skills/org-attack-surface/SKILL.md | skill | 97 | 1,052 lines vs. R05's 500-line guideline |
| skills/osint-methodology/SKILL.md | skill | 99 | 515 lines, marginally over R05's 500-line guideline |
| .claude/skills/run-claude-osint/SKILL.md | skill | 100 | None found |

## Security Scan
| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 3 |
| Low | 2 |

### Execution Surface Inventory
| Surface | Files |
|---------|-------|
| Hooks | none |
| Scripts | scripts/sync-skill-content.sh; skills/offensive-osint/scripts/secret_scan.py; skills/offensive-osint/scripts/h1_reference.py; skills/osint-autopilot/scripts/build_xlsx.py; skills/osint-autopilot/scripts/host_enum.workflow.js; skills/osint-autopilot/scripts/recon_pipeline.sh; skills/osint-autopilot/scripts/findings_gen.py |
| MCP configs | none |
| Package manifests | none (no `package.json`/`requirements.txt` anywhere in the repo, despite `build_xlsx.py` depending on the third-party `openpyxl` package) |

### Security Findings
| # | Severity | File | Line | Pattern | Description |
|---|----------|------|------|---------|-------------|
| 1 | MEDIUM | skills/osint-autopilot/scripts/recon_pipeline.sh | 7 | unsanitized-path-construction | `ENG="$HOME/Research/engagements/$D"` builds a filesystem path directly from the unsanitized `$D` domain argument (no regex/format validation), then `mkdir -p`/writes evidence files under it — a domain string containing `../` would traverse outside the intended `~/Research/engagements/` tree. Low practical severity since `$D` is operator-supplied in the same trust boundary, but no input validation exists. |
| 2 | MEDIUM | skills/osint-autopilot/scripts/recon_pipeline.sh | 33, 112-118 | active-network-scan | Script fires many outbound network calls (dig/whois/curl/subfinder/crt.sh/gau/waybackurls) and an active `nmap` port scan against IPs resolved from the target domain. This is the tool's documented purpose (authorized external recon per `osint-autopilot.md`/`osint-methodology` §1), not concealed exfiltration — flagged for completeness per the scan checklist. |
| 3 | MEDIUM | skills/offensive-osint/scripts/h1_reference.py | 104-105 | network-call | `urllib.request.urlopen()` POSTs to `https://hackerone.com/graphql`. Read-only public API, no auth token or local data sent — documented, expected functionality (the skill's own driver, `smoke.sh`, calls this by design). |
| 4 | LOW | skills/osint-autopilot/scripts/findings_gen.py | 146 | subprocess-network-call | `subprocess.run(["curl", ...], capture_output=True, ...)` fetches a homepage for WordPress fingerprinting. Uses list-form arguments (no `shell=True`), so no shell-injection risk despite the host value being interpolated into the URL string. |
| 5 | LOW | skills/osint-autopilot/scripts/build_xlsx.py | 5 | undeclared-dependency | `from openpyxl import Workbook` — the repo has no `requirements.txt`/`pyproject.toml` anywhere declaring `openpyxl` as a dependency, so a fresh clone `ImportError`s on this script until the operator manually `pip install`s it. |

No Critical or High findings — no eval-with-variables, curl-pipe-sh, reverse shells, `shell=True`, `os.system()`, sudo usage, PATH modification, or credential-exfiltration patterns anywhere in the seven scripts.

## Bugs (PR-worthy)
| # | File | Issue | Impact |
|---|------|-------|--------|
| — | — | None found | All 10 `SKILL.md` files have complete `name`/`description` frontmatter; every cross-reference checked (offensive-osint §16.8/§16.14/§16.15/§16.17-19/§22/§23/§27.0.1/§28.1/§29.2/§44, osint-methodology §1/§2/§6.2/§6.4/§7.2/§9/§11/§16, org-attack-surface §14/§28 pointer) resolves to a real, present section. No commands/ or agents/ directories exist in this repo, so the allowed-tools/undeclared-tool/numbered-steps/empty-input categories don't apply. |

## Security Fixes (PR-worthy, Medium/Low only)
| # | File | Issue | Suggested Fix |
|---|------|-------|---------------|
| 1 | skills/osint-autopilot/scripts/recon_pipeline.sh | `$D` used unsanitized in a filesystem path (line 7) | Validate `$D` against a domain-name regex (e.g. `^[A-Za-z0-9.-]+$`) and reject/abort on `..` or `/` before constructing `$ENG`. |
| 2 | skills/osint-autopilot/scripts/build_xlsx.py | `openpyxl` imported with no dependency manifest anywhere in the repo | Add a `requirements.txt` (or a line in `osint-autopilot/SKILL.md`'s prerequisites) declaring `openpyxl` as a required pip package. |

## Quality Issues (informational)
| # | File | Issue | Penalty |
|---|------|-------|---------|
| 1 | skills/offensive-osint/SKILL.md | 4,556 lines — 9x over R05's 500-line guideline. The single largest structural-improvement opportunity in the pack (splitting the wordlist/regex/endpoint-catalog sections into scoped sub-skills), since this is the "arsenal" skill loaded in full for any offensive-osint query. | -3 |
| 2 | skills/offensive-osint/SKILL.md | Line 3744: "**theHarvester** with appropriate sources." — vague quantifier (R01), no criteria for which sources, unlike the adjacent line 3646 which specifies `-b linkedin`. | -2 |
| 3 | skills/cloud-saas-exposure/SKILL.md | 802 lines — over R05's 500-line guideline. | -3 |
| 4 | skills/continuous-exposure-monitoring/SKILL.md | 811 lines — over R05's 500-line guideline. | -3 |
| 5 | skills/email-domain-security/SKILL.md | 589 lines — over R05's 500-line guideline. | -3 |
| 6 | skills/exposure-risk-quantification/SKILL.md | 748 lines — over R05's 500-line guideline. | -3 |
| 7 | skills/exposure-risk-quantification/SKILL.md | §13 Skill Self-Test: lines 730 and 731 are both numbered "14." (should be 14 and 15); the list then continues at "15." afterward, so one number is skipped elsewhere in the sequence. | -2 |
| 8 | skills/identity-provider-recon/SKILL.md | 968 lines — over R05's 500-line guideline. | -3 |
| 9 | skills/org-attack-surface/SKILL.md | 1,052 lines — over R05's 500-line guideline. | -3 |
| 10 | skills/osint-methodology/SKILL.md | 515 lines — marginally (3%) over R05's 500-line guideline. | -1 |
| 11 | skills/osint-autopilot/SKILL.md | Frontmatter has only `name`/`description`; every one of the other 9 skills in this pack also declares `version:` and a `triggers:` list (used by the project's own 56-prompt self-test harness), so this file is the sole outlier from the pack's own established convention. | -5 |

## Cross-Component

- **README.md undercounts and omits a real, shipped skill.** README.md line 5 advertises "**8 Claude skills**" and the `## Structure` tree (README.md lines 46-66) enumerates exactly 8 `skills/*/SKILL.md` paths. `skills/osint-autopilot/SKILL.md` exists on disk with its own working scripts (`recon_pipeline.sh`, `host_enum.workflow.js`, `findings_gen.py`, `build_xlsx.py`) but is not mentioned anywhere in `README.md`, `docs/*.md`, `tests/smoke-test-prompts.md`, or `examples/*.md` (verified by a repo-wide grep for "osint-autopilot" outside its own directory — zero hits). `tests/smoke-test-prompts.md` even states its 56-prompt suite explicitly "Covers all 8 skills," so this appears to be a deliberate scope statement for the *knowledge* skills rather than an oversight in that one file — but README.md's own "Structure" tree is a literal disk listing that is simply missing a real directory, which is the part worth fixing.
- No other stale counts, broken relative paths, or terminology drift found: the `docs/`, `examples/`, and `tests/` paths referenced from README.md and from `.claude/skills/run-claude-osint/SKILL.md` all resolve to real files; the `docs/full-skills/` source that `scripts/sync-skill-content.sh` reads is documented as intentionally absent in a fresh clone (both the script's own `⚠ Source missing` message and `run-claude-osint/SKILL.md`'s "Gotchas" section describe this identically) — not a defect.

## Recommendation

**REVIEW** — no Critical or High security findings and no registration-breaking bugs, so it's safe to prepare PRs directly: (1) add `osint-autopilot` to README.md's skill list/structure tree, (2) add `version:`/`triggers:` to `osint-autopilot/SKILL.md` for consistency with its 9 siblings, (3) fix the duplicate `14.` in `exposure-risk-quantification/SKILL.md`'s self-test, (4) validate the domain argument in `recon_pipeline.sh` before it's used in a filesystem path, and (5) declare `openpyxl` as a dependency. Flag the two informational network-call findings (h1_reference.py, recon_pipeline.sh) in the audit issue for the maintainer's awareness rather than opening PRs against them — both are the tool's documented, intended behavior.
