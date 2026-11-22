# User Story Map — DeepSeek Harness Agent Tool Limitation Plugin

> **Project:** Security and Capability Limitation Plugin for Autonomous Agents in DeepSeek Harness (DSH)  
> **Owner:** Jinyuan Zhang (PM / Scrum Master)  
> **Course Context:** Contemporary Issues in Software Engineering (Assignment 2)  
> **Traceability:** Maps Assignment 1 Product Backlog (`PB-01`–`PB-05`) to User Stories (`US-01`–`US-07`) across two collaborative iterations.

---

## 1. Visual Story Map (Backbone & Horizontal Release Slices)

```text
====================================================================================================
USER ACTIVITIES   | 1. Policy Configuration       | 2. Tool & Arg Interception    | 3. Self-Protection & Quality
(Backbone)        |    & Management               |    (Runtime Guard)            |    Verification
====================================================================================================
USER TASKS        | Load JSON policy              | Intercept shell/tool calls    | Protect plugin config & secrets
                  | Handle malformed config       | Block shell chaining/injection| Run automated example tests
                  | Edit rules visually (Web GUI) | Enforce cross-platform args   | Verify cross-platform CI & docs
----------------------------------------------------------------------------------------------------
RELEASE 1:        | [US-04] Retain last-known-    | [US-01] Default-deny command  | [US-03] Cross-platform anti-
Iteration 1       | good policy on malformed JSON | & argument whitelist (PB-01)  | tampering blacklist (PB-02)
(Core Security    | without overwriting disk file |                               |
 Engine & Tests)  | (PB-02)                       | [US-02] Block shell chaining  | [US-03/01] Executable example
                  |                               | operators & injection (PB-01) | acceptance test suite (node:test)
----------------------------------------------------------------------------------------------------
RELEASE 2:        | [US-05] Embedded Web GUI      | [US-06] Dynamic hot-reload    | [US-07] Dual-platform CI gate,
Iteration 2       | rule editor & schema          | from GUI saves without DSH    | security/perf benchmarks &
(Web GUI, CI &    | validation (PB-03)            | restarts (PB-04)              | reproducible setup guide (PB-05)
 Hardening)       |                               |                               |
====================================================================================================
```

---

## 2. Formal User Stories

### Iteration 1 Scope: Core Security Engine & Executable Examples

- **US-01 (Maps to `PB-01`: Tool Interception Hook)**  
  **As an** AI agent developer,  
  **I want** the plugin to intercept DSH tool calls and enforce a default-deny command and argument whitelist across Windows and Unix executable paths before OS execution,  
  **so that** an autonomous agent cannot execute destructive binaries or unauthorized parameters on my host machine.

- **US-02 (Maps to `PB-01`: Shell Injection Prevention)**  
  **As a** security-conscious developer,  
  **I want** the plugin to block shell chaining, command substitution, and redirection operators (`;`, `|`, `&`, `` ` ``, `$()`, `>`, `>>`) inside command inputs,  
  **so that** an agent cannot piggyback malicious payloads onto an approved command such as `git status`.

- **US-03 (Maps to `PB-02`: Cross-Platform Self-Protection Blacklist)**  
  **As an** AI agent developer working on Windows or Unix,  
  **I want** the plugin to block any command or file `write`/`edit` tool targeting `plugin.config.json`, plugin source paths, or sensitive credential files regardless of slash direction or letter casing,  
  **so that** an autonomous agent cannot tamper with its own restrictions or exfiltrate host credentials.

- **US-04 (Maps to `PB-02`: Non-Destructive Policy Fallback)**  
  **As a** developer maintaining security rules,  
  **I want** the plugin to retain its fallback / last-known-good policy in memory without overwriting the user's configuration file on disk when malformed JSON is encountered,  
  **so that** an accidental syntax error never crashes DeepSeek Harness, wipes existing rules, or leaves the agent unprotected.

---

### Iteration 2 Scope: Web GUI, Process Improvement & Hardening

- **US-05 (Maps to `PB-03`: Web GUI Rule Management)**  
  **As a** plugin administrator,  
  **I want** to inspect, toggle, and edit tool rules via the embedded Web GUI with client-side schema validation,  
  **so that** I can adjust agent permissions visually without introducing JSON syntax errors.

- **US-06 (Maps to `PB-04`: Dynamic Hot-Reloading via GUI)**  
  **As a** developer iterating on agent prompts,  
  **I want** policy changes saved from the Web GUI or disk to reload dynamically into memory,  
  **so that** updated security boundaries take effect immediately without restarting DeepSeek Harness.

- **US-07 (Maps to `PB-05` & A2 Process Improvement: Automated CI & Reproducible Setup)**  
  **As a** QA engineer and course evaluator,  
  **I want** a clear setup/testing guide and automated dual-platform GitHub Actions checks (`ubuntu-latest` + `windows-latest`),  
  **so that** every pull request is verified consistently on both operating systems and the project is easy to reproduce.

---

## 3. Iteration 1 Scope Boundaries & Deliberate Deferrals

To keep Iteration 1 focused on validating the core security engine and establishing a measurable collaboration baseline:
1. **Included in Iteration 1:** Cross-platform binary/path hardening (`US-01`–`US-03`), non-destructive malformed JSON fallback (`US-04`), and local `node:test` example-based acceptance tests (`PB-01`, `PB-02`).
2. **Deferred to Iteration 2:** Web GUI visual refactoring/schema checks (`US-05`, `US-06`), security/performance stress benchmarks, user documentation polish (`PB-05`), and **GitHub Actions CI automation** (`US-07`, deliberately introduced in Iteration 2 as our data-driven process improvement after Iteration 1 retrospective).

