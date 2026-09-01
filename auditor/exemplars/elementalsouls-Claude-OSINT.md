---
slug: elementalsouls-Claude-OSINT
repo: elementalsouls/Claude-OSINT
audited: 2026-08-10
commit_sha: 7d1516291f24a48696a1db7f86ecb15c75249754
score: 97
exemplifies:
  - R04
  - R05
  - R06
  - R07
  - R08
  - R01
---

# Exemplar: elementalsouls/Claude-OSINT

**Score**: 97/100  |  **Date**: 2026-08-10  |  **Commit**: `7d1516291f24a48696a1db7f86ecb15c75249754`

A 10-skill authorized-recon pack (offensive OSINT, attack-surface mapping, cloud/SaaS exposure, identity-provider recon, risk quantification) that shows how a large multi-skill collection stays navigable through disciplined scope notes, and how a build/test skill earns its `SKILL.md` slot by being a concrete runbook rather than a README restatement.

## Per-rule evidence

### R04 — Description is a trigger, not a summary

`.claude/skills/run-claude-osint/SKILL.md` is the pack's build/test skill — it exists purely to let an agent validate the repo, and its description is written entirely as things a user would ask for:

> Real quote from `.claude/skills/run-claude-osint/SKILL.md:3`:
>
> ```
> description: Build, validate, and run the claude-osint skills repo — check SKILL.md frontmatter, run the secret_scan.py and h1_reference.py helpers, run sync-skill-content.sh, run the smoke test. Use when asked to run, build, test, validate, or smoke-test claude-osint or its OSINT skills/scripts.
> ```

There are six named action phrases (build, validate, check frontmatter, run the helpers, run sync, smoke-test) rather than a single adjective-laden sentence, and each one maps to an actual runnable step later in the file. A user typing "smoke-test this repo" or "run secret_scan" hits this skill on the first phrase, not a vague "helps with the repo" summary that only matches by luck.

### R05 — Under 500 lines

The same file is 111 lines against nine sibling `SKILL.md` files that mostly run 589–4,556 lines (per `wc -l`), because it scopes itself to exactly one job — drive the smoke test — instead of re-explaining the OSINT domain knowledge that already lives in the content skills:

> Real quote from `.claude/skills/run-claude-osint/SKILL.md:19-23`:
>
> ```
> `claude-osint` is **not an app** — it's a Claude *skills package*. Its product
> is two `SKILL.md` files (`skills/offensive-osint/`, `skills/osint-methodology/`)
> plus two runnable Python helpers under `skills/offensive-osint/scripts/`. There
> is no GUI, server, or TUI. "Running it" means: the SKILL.md frontmatter parses
> and is complete (that's what Claude loads), and the helper scripts work.
> ```

This is what R05 compliance looks like in a repo where the *content* skills are legitimately long (technique catalogs, wordlists, regex banks): the operational skill stays short because it doesn't try to also be a content skill.

### R06 — Code examples must be runnable

The same file shows the problem (verify a secret-scanner works) then the actual command and actual output, not a description of what the command does:

> Real quote from `.claude/skills/run-claude-osint/SKILL.md:61-64`:
>
> ```
> # Secret scanner — stdin
> printf 'AKIAIOSFODNN7EXAMPLE\n' | python3 skills/offensive-osint/scripts/secret_scan.py
> # -> {"pattern": "AWS_ACCESS_KEY", "severity": "critical", ...}
> ```

The `#` comment isn't a description of intended behavior — it's the literal shape of stdout from having actually run it (per the file's own "Verified this session" heading at line 59), which is exactly the difference between a runnable example and pseudocode.

### R07 — Scope note when related skills exist

Every content skill in the pack opens with a blockquote naming its companions, what section of each companion it depends on, and — critically — what it does *not* re-explain. `continuous-exposure-monitoring/SKILL.md` is the clearest instance, disambiguating against four siblings at once:

> Real quote from `skills/continuous-exposure-monitoring/SKILL.md:62-69`:
>
> ```
> > Companion skills: [`osint-methodology`](../osint-methodology/) (the 5-stage pipeline this skill
> > loops — see its §7.2 "ongoing weekly diff" profile, which this skill fills in with concrete
> > mechanics), [`offensive-osint`](../offensive-osint/) (§29 Threat Intel & IOCs — this skill
> > **deepens** that section's advisory/IOC-feed directory with the continuous adversary-chatter
> > watch loop and CTI-feed cadence it explicitly lacks; use §29 for indicator enrichment and
> > vulnerability-prioritization data sources, this skill for the standing collection loop),
> > [`org-attack-surface`](../org-attack-surface/) (the org-first discovery this skill's re-scans
> > re-run on a schedule), [`exposure-risk-quantification`](../exposure-risk-quantification/) (reads
> > this skill's finding-lifecycle suppression state to compute `risk_trend` and the FAIR score — see
> > its risk-score model). This skill answers a different question than all four: not "what does the
> > target expose right now," but **"is what the target exposes changing, and should anyone be told."**
> ```

This isn't a generic "see also" list — each parenthetical states the specific section (`§7.2`, `§29`) and the specific relationship (loops, deepens, reads state from), so an agent that has already loaded one skill knows whether it needs the other or can skip it. Nine of the ten skills in the pack use this exact pattern, which is what makes a 10-skill, 10,000+ line collection stay disambiguated instead of collapsing into overlapping context.

### R08 — Patterns over theory

`offensive-osint/SKILL.md`'s own description is itself a demonstration of R08 — it doesn't claim to teach OSINT concepts, it enumerates the concrete, reusable artifacts the skill hands back:

> Real quote from `skills/offensive-osint/SKILL.md:3`:
>
> ```
> description: "Operational arsenal for external red-team and bug-bounty reconnaissance. Concrete wordlists (28 Swagger paths, 13 GraphQL paths, 35 high-risk ports, 6 missing-header findings, 15 always-on HTTP checks, 5 SAML paths, cloud bucket permutations, JS guess-paths, vendor product fingerprints for Citrix/F5/Pulse/Fortinet/Cisco/PaloAlto/VMware/Exchange, cloud-native service fingerprints, container/K8s exposure paths, CI/CD platform paths, documentation/wiki leak paths, WHOIS/RDAP, DNS record catalog, Wayback CDX recipes), 80-pattern secret-regex catalog [...] 9 read-only secret validators [...] copy-paste curl/httpie probes for every check [...]"
> ```

Every noun phrase names a specific, countable artifact (28 paths, 35 ports, 80 regexes) instead of a category label like "common vulnerability checks" — the skill's whole value proposition is "here is the list," not "here is how to think about lists."

### R01 — No vague quantifiers without criteria

Where the skill needs to specify a source or a bound, it gives the literal flag or the literal number instead of a hand-wave. `cloud-saas-exposure`'s bucket-permutation description states the exact search space instead of "a range of common prefixes":

> Real quote from `skills/cloud-saas-exposure/SKILL.md:3`:
>
> ```
> description: "...bounded two-class permutation (6 prefixes x 15 suffixes on trusted tokens, bounded target-bound expansion on subdomain stems)..."
> ```

And in the tool-selection tables, a specific CLI flag is given instead of leaving the choice open:

> Real quote from `skills/offensive-osint/SKILL.md:3646`:
>
> ```
> - **theHarvester** with `-b linkedin` source (uses search-engine-driven enum).
> ```

The audit's one R01 penalty (`skills/offensive-osint/SKILL.md:3744`, "theHarvester with appropriate sources") is the exception that proves the pattern — it stands out precisely because line 3646, four lines earlier in the same file, shows what the non-vague version looks like.
