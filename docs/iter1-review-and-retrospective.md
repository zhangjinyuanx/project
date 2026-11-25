# Iteration 1 Review and Retrospective

> **Iteration:** Iteration 1 — Core Security Engine & Executable Acceptance Examples  
> **Author:** Jinyuan Zhang (PM / Scrum Master)  
> **Participants:** Jinyuan Zhang (`zhangjinyuanx`, PM), Jiazhuang Liu (`Tsunami079`, Core Dev), Bochen Zhang (`Zack-zbc`, UI Dev), Cheng Chen (`ccbond-god`, QA Lead)  
> **Status:** `Completed — Merged into main via PR #7 (5e9b0a4) on 2026-11-24`

---

## 1. Iteration 1 Goal & Outcomes Summary

- **Iteration Goal:** Harden the core interception engine (`US-01`–`US-04` / `PB-01`, `PB-02`) for cross-platform Windows/Unix path consistency and non-destructive error fallback, and establish executable acceptance tests based on `docs/iter1-requirements-by-example.md`.
- **Outcome:** Completed. Core hardening (`PB-01`, `PB-02`) and executable example-driven acceptance tests (`EX-01`–`EX-23` + `EX-17b` regression) were verified by all team members and merged into `main` (`5e9b0a4`).

### Traceability Matrix (Requirements → Code → Review → Tests)

| User Story / Item | GitHub Issue | Branch | PR & Author | Reviewers | Key Commit(s) | Automated Test Verification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Baseline Story Map, Examples & Repo Setup (`US-01`–`US-04`) | Planned for #3–#5 | `docs/iter1-story-map-and-examples` | PR #2 & PR #6 (`zhangjinyuanx`) | Merged to `main` (`f7f1a11`, `72330be`) | `30428fb`, `a475553` | N/A (Specification) |
| Core Engine Hardening (`US-01`–`US-04` / `PB-01`, `PB-02`) | Closes #3, #4 | `feature/pb01-pb02-interception-hardening` | PR #7 (`Tsunami079`) | `zhangjinyuanx` (Approved), `Zack-zbc` (Approved + UI contract note), `ccbond-god` (Changes Requested → Re-verified & Approved) | `601b71e` (initial), `01db4db` (QA fix), merged via `5e9b0a4` | Pre-fix `main`: 7 failures → Post-fix: 25/25 + `EX-17b` passing |
| Example-Driven Acceptance Tests (`EX-01`–`EX-23` + `EX-17b`) | Closes #5 | `test/iter1-acceptance-examples` (merged into PR #7 branch) | PR #8 (`ccbond-god`) | Merged via `2aed7ae` into PR #7 → `main` (`5e9b0a4`) | `20a9579` + `2ab0d43` (`EX-17b`) | `cd agent-tool-limitation && npm test`: `27/27 Passed` |

---

## 2. Scope or Plan Adjustments Recorded in Iteration 1

- **Adjustment 1 (Refining Acceptance Criteria into Executable Examples):** Converted high-level Assignment 1 Given-When-Then statements into 23 concrete input/output examples (`EX-01`–`EX-23`) covering Windows `.exe` binaries, backslash paths, uppercase filename bypasses, and non-destructive JSON fallback, plus 1 regression case (`EX-17b`) discovered during QA review.
- **Adjustment 2 (Testing Branch Integration):** PR #8 initially targeted `feature/pb01-pb02-interception-hardening` rather than `main` because pre-hardening `main` (`72330be`) failed 7 of the 25 acceptance tests; it was merged into PR #7's branch (`2aed7ae`) so code hardening and tests integrated atomically into `main`.
- **Adjustment 3 (Deferring CI Automation):** Automated CI workflows were intentionally kept out of Iteration 1 to establish a manual-review baseline prior to evaluating process improvements in Iteration 2.

---

## 3. Iteration 1 Process Metrics Baseline (For Assignment 2 Task 3)

| Metric | Iteration 1 Measured Result | Notes / Conditions |
| :--- | :--- | :--- |
| **PR Count** | `4 PRs (#2, #6, #7, #8)` | Docs/chore baseline (#2, #6), Core hardening (#7), QA test suite (#8) |
| **PR #7 Lead Time (Open → Merge)** | `32.0 hours (2026-11-23T06:11Z → 2026-11-24T14:09Z)` | Included 2 review rounds due to blocking `EX-17b` bypass found in manual QA |
| **Time to First QA Review Verdict (PR #7)** | `24.6 hours (2026-11-23T06:11Z → 2026-11-24T06:49Z)` | Asynchronous manual branch checkout and local testing required prior to automated CI |
| **Review Rounds / Rework Commits on Code PR (#7)** | `2 rounds / 1 rework commit (01db4db) + 1 regression-test commit (2ab0d43)` | Round 1: `ccbond-god` requested changes for `..` traversal bypass (`EX-17b`) & `blockedCommands` casing; fixed in `01db4db` |
| **Cross-Platform Verification Mode** | `Manual local checkout (single OS only; exact hands-on minutes not stopwatched; no automated Linux + Windows check)` | QA checked out branches manually on local machine without dual-OS CI verification |
| **Automated CI Check Coverage** | `0% (No .github/workflows/ci.yml or PR template in Iter 1)` | Pre-merge verification relied solely on local execution and human inspection |
| **Defects / Contract Gaps Caught in Review** | `1 blocking security bypass (EX-17b) + 2 non-blocking + 1 UI persistence contract gap` | `EX-17b` & `blockedCommands` fixed in `01db4db`; `Zack-zbc`'s `saveConfigFile` boolean feedback scheduled for Iter 2 (`PB-04`); unquoted space-in-Windows-path without `.exe` logged as fail-closed follow-up |

---

## 4. Iteration 1 Retrospective

### What Went Well
1. **Specification by Example clarity:** Concrete examples (`EX-01`–`EX-23`) in `docs/iter1-requirements-by-example.md` aligned Core Dev and QA on exact expected rule codes (`CONFIG_TAMPER_BLOCKED`, `SHELL_CHAINING_BLOCKED`, `ARG_NOT_IN_WHITELIST`). Running PR #8 against pre-hardening `main` (`72330be`) immediately produced 7 red failures and 25/25 green passes on PR #7, proving the tests locked real specification gaps.
2. **High-value cross-role peer reviews:** QA review (`ccbond-god`) caught a real fail-open path-traversal bypass (`cat .dsh/x/../profiles/default.json` and `write`/`edit` on the same path), while UI review (`Zack-zbc`) caught a frontend-backend persistence contract gap (`update_policy` discarding `saveConfigFile()`'s boolean return value), directly informing Iteration 2 backlog items.

### What Didn't Go Well (Evidence-Backed Collaboration Problems)
1. **Slow manual cross-platform verification & absence of pre-merge CI gate:** Without automated Windows/Unix runners on GitHub, QA Lead had to manually check out `feature/pb01-pb02-interception-hardening`, run local scripts, and coordinate asynchronously via PR comments (taking 24.6 hours to first QA verdict and 32.0 hours total lead time). Additionally, QA discovered during local test execution that `apply()`'s live `fs.watch` handle caused `node --test` to hang for >60s unless mocked—a testability/CI issue that only surfaced late in manual testing.
2. **No standardized PR checklist:** PR descriptions varied in format and did not enforce checking `plugin.config.json` cleanliness or syntax checks across `index.mjs` and `client.js` prior to review.

### Concrete Process Improvement Action Plan for Iteration 2
To directly resolve these problems in Iteration 2:
1. **Add Dual-Platform GitHub Actions CI (`.github/workflows/ci.yml`):** Automatically run `node --check` on `index.mjs` and `client.js`, JSON validation on `plugin.config.json`, `npm test` (including Iter 1 acceptance + Iter 2 security/performance suites), and `git diff --exit-code agent-tool-limitation/plugin.config.json` on both `ubuntu-latest` and `windows-latest` for every PR targeting `main`.
2. **Add Standardized PR Checklist (`.github/pull_request_template.md`):** Require every PR author to link the related Issue (`Closes #...`), confirm local `npm test` execution, check test levels covered, and verify green dual-platform CI before requesting peer review.
3. **Evaluation Plan:** Re-measure PR lead time, time to automated feedback, review rework rounds, and cross-platform defect catch rate during Iteration 2 (`PB-03`, `PB-04`, `PB-05`, security/perf benchmarks) while explicitly accounting for workload and task-type differences between Iteration 1 (core engine hardening) and Iteration 2 (CI + Web API/GUI).
