# Agent Tool Limitation Plugin for DeepSeek Harness (DSH)

A security and capability control plugin for autonomous AI agents within the DeepSeek Harness (DSH) runtime. It enforces fine-grained access control over agent tool invocations through a default-deny command and argument whitelist, a cross-platform self-protection blacklist, dynamic configuration hot-reloading, and an embedded Web GUI.

> **Course:** Contemporary Issues in Software Engineering — Assignment 2  
> **Team:** Jinyuan Zhang (25305422), Jiazhuang Liu (25293517), Bochen Zhang (25307703), Cheng Chen (25307667)  
> **Repository:** https://github.com/zhangjinyuanx/project (Branch: `main`)

---

## 1. Quick Start & Usage

### Prerequisites
- **Node.js v22 or later (v22 LTS / v24+):** Required so `node --test tests/*.test.mjs` natively expands glob patterns across both Linux/macOS and Windows `cmd.exe`. *(Pinned during Iteration 2 CI setup after Node.js 20 failed glob expansion on Windows `cmd.exe`.)*
- **No third-party npm packages required to run the test suite:** All 100 tests use Node.js built-in modules (`node:test`, `node:assert/strict`, `node:vm`, `node:fs`).
- **DeepSeek Harness (Desktop / Web App):** Required when installing and using the live plugin GUI/runtime; not needed for running automated verification checks.

### Installing into DeepSeek Harness (Recommended for Live Use)
1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/zhangjinyuanx/project.git
   cd project
   ```
2. Open the **DeepSeek Harness** desktop/web application.
3. Click **Plugins** (`插件`) in the left sidebar, then click **+ Add Plugin** (`+ 添加插件`) in the top-right corner.
4. Copy and paste the **absolute local path** to the plugin subdirectory inside this repository (for example, `.../project/agent-tool-limitation`) into the input box and click **Install** (`安装`).  
   > **Important:** Because the plugin package files (`package.json`, `index.mjs`, `client.js`) reside inside the `agent-tool-limitation/` subdirectory rather than the repository root, install via the cloned **local subdirectory path** (`.../project/agent-tool-limitation`)—do **not** enter the top-level GitHub repository URL directly.
5. Open any workspace conversation and click the **🛡️ Tool Limitation Policy** (`工具限制策略`) button in the top toolbar or floating dock to inspect rules, test commands, and trigger hot reloads.

### Where to Configure Rules (Web GUI vs. Disk Configuration)
- **Editable in the Web GUI (`client.js`):**
  - Toggle the global guard switch (`enabled`) and shell chaining protection (`blockShellChaining`).
  - Add tools/commands and configure per-command whitelist rules (`commandRules`: `allowed`, `argWhitelistEnabled`, and `allowedArgs`), run interactive command tests, and click **🔄 热重载策略 (Hot Reload)**.
- **Read-Only in the Web GUI (Edit `agent-tool-limitation/plugin.config.json` on Disk):**
  - **`mode`** (`"whitelist"` vs. `"blacklist"`), **`blockedCommands`**, and **`forbiddenPaths`** are displayed read-only in the GUI **Self-Protection** summary card (`Section 4`). To change them, edit `agent-tool-limitation/plugin.config.json` directly on disk and click **Hot Reload** (or rely on automatic `fs.watch` hot-reloading without restarting DSH).
- **Hardcoded Anti-Tampering Locks (`agent-tool-limitation/index.mjs`):**
  - Core self-protection paths (`DEFAULT_ACCESS_POLICY.protectedConfigPaths`: `plugin.config.json`, `cordis.yml`, `cordis.patch.yml`, `agent-tool-limitation`, `.dsh/profiles`, and plugin API routes) are enforced in source code so autonomous agents cannot disable or overwrite the plugin.

### Running Automated Verification Tests (Windows, Linux & macOS)
Run all static checks and **100 zero-dependency tests across 8 suites** from the cloned repository root (no `npm install` needed):
```bash
node -v
node --check agent-tool-limitation/index.mjs
node --check agent-tool-limitation/client.js
node -e "JSON.parse(require('fs').readFileSync('agent-tool-limitation/plugin.config.json', 'utf8')); console.log('plugin.config.json OK')"
cd agent-tool-limitation
npm test
cd ..
git diff --exit-code agent-tool-limitation/plugin.config.json
```

---

## 2. Key Capabilities & Architecture

- **Core Interception Hook (`index.mjs`):** Intercepts `bash`, `web_fetch`, `read`, `write`, `edit`, and `plugin_manager` dispatches via `ctx.tools.guard` before host execution, returning `AEGIS_ACCESS_DENIED` on blocked calls without crashing DSH.
- **Cross-Platform Path & Binary Guard:**
  - `normalizeExecutableName(rawToken)`: Normalizes quoted/unquoted Unix (`/`) and Windows (`\`) paths and strips `.exe`/`.cmd`/`.bat` suffixes before whitelist/blacklist evaluation.
  - `findProtectedTarget(input, forbiddenPaths)`: Applies dot-segment resolution (`path.posix.normalize`) and case-insensitive separator normalization (`CONFIG_TAMPER_BLOCKED` before `SENSITIVE_PATH_BLOCKED`) to stop agents tampering with `plugin.config.json`, plugin sources, or `.dsh/profiles`.
- **Non-Destructive Fail-Safe Config & Schema Validation:**
  - `loadConfigFile(fallbackPolicy)` preserves malformed `plugin.config.json` files on disk and retains the active fallback/last-known-good policy in memory across cold start and hot reloads.
  - `validatePolicyPatch(patch)` validates `mode`, command names (rejecting whitespace, shell metacharacters, and prototype keys), and `/.../` regular expressions before mutating memory or disk (`HTTP 400` on invalid input; `HTTP 500` with `inMemoryUpdated: true, persisted: false` on disk write failure).
- **Embedded Web GUI (`client.js`):** Visual whitelist rule editor with client-side command/regex validation, three-state persistence feedback (persisted vs. memory-only warning vs. error), manual Hot Reload button with timestamp, and a read-only blacklist/self-protection summary card.

---

## 3. Directory Structure

```text
├── .github/
│   ├── pull_request_template.md              # Standardized PR verification checklist
│   └── workflows/ci.yml                      # Dual-platform CI (ubuntu-latest & windows-latest, Node 22)
├── agent-tool-limitation/                    # Plugin package directory (paste this path in DSH)
│   ├── client.js                             # Embedded React Web GUI client bundle
│   ├── cordis.patch.yml                      # Cordis framework patch configuration
│   ├── index.mjs                             # Core interception engine, config loader & Web API
│   ├── package.json                          # Plugin manifest and zero-dependency `npm test` script
│   ├── plugin.config.json                    # Standalone access control policy configuration
│   ├── locale/                               # Localization resources
│   └── tests/                                # Zero-dependency Node.js test suites (100 tests total)
│       ├── acceptance-iter1.test.mjs         # EX-01–EX-23 + EX-17b regression acceptance suite (27 tests)
│       ├── security-and-perf.test.mjs        # Adversarial security, performance & Web API suite (63 tests)
│       └── ui-contract.test.mjs              # Web GUI VM/hooks validation & toast contract suite (10 tests)
├── docs/                                     # Process & requirements traceability documentation
│   ├── user-story-map.md                     # User Story Map across Iteration 1 and Iteration 2
│   ├── iter1-requirements-by-example.md      # Specification by Example baseline (EX-01–EX-23)
│   ├── iter1-review-and-retrospective.md     # Iteration 1 metrics & retrospective
│   └── iter2-review-and-retrospective.md     # Iteration 2 metrics, Iter 1 vs Iter 2 comparison & retro
├── .gitignore
└── README.md
```

---

## 4. Test Suites & Quality Benchmarks

| Suite File | Level & Focus | Tests | What It Verifies |
| :--- | :--- | :---: | :--- |
| `tests/acceptance-iter1.test.mjs` | Unit, Integration & Acceptance (`US-01`–`US-04`) | 27 | `EX-01`–`EX-23` specification examples + `EX-17b` dot-segment traversal regression + `apply(mockCtx)` & `loadConfigFile` fallback |
| `tests/security-and-perf.test.mjs` | Acceptance Quality & Web API Integration (`PR #12`, `US-05`–`US-07`) | 63 | 26 malicious vs. 14 benign vectors (`100%` blocked / `0%` false positives), throughput (5,000 decisions) + 40 KB input latency + 100-entry bounded audit log, Web API `400`/`500`/`200` error paths |
| `tests/ui-contract.test.mjs` | UI Contract via Node `vm` + minimal React hooks harness (`PB-03`/`PB-04`) | 10 | Command-name/regex validation, lowercase normalization, duplicate block, manual hot reload, three-state persistence feedback |

---

## 5. Dual-Platform Continuous Integration (`.github/workflows/ci.yml`)

Every push to `main` and every Pull Request automatically runs on GitHub Actions across both **`ubuntu-latest`** and **`windows-latest`** (Node.js 22):
1. `node --check` syntax checks on `index.mjs` and `client.js`
2. JSON syntax validation on `plugin.config.json`
3. Full `npm test` execution (100/100 tests)
4. `git diff --exit-code agent-tool-limitation/plugin.config.json` cleanliness gate

---

## 6. Known Limitations

1. **No Live Browser E2E Verification Against DeepSeek Harness:** Because standalone CI has no live DSH server or headless browser runner, DOM layout rendering in `client.js` is verified via `node --check` and a `node:vm` hooks harness (`ui-contract.test.mjs`) rather than headless browser E2E tests (e.g., Playwright).
2. **Conservative Substring Matching on Protected Paths (Fail-Closed):** `findProtectedTarget()` intentionally uses substring containment against protected identifiers (e.g., `agent-tool-limitation`, `plugin.config.json`) to block indirect bypasses, which can conservatively deny benign commands whose arguments contain those exact strings (e.g., `grep agent-tool-limitation README.md`).
3. **Unquoted Windows Paths Containing Spaces Without `.exe`:** Space-separated tokenization rejects unquoted Windows executable paths containing spaces that omit an `.exe`/`.cmd`/`.bat` suffix (failing closed with `COMMAND_NOT_IN_WHITELIST`), whereas quoted paths and `.exe` paths are normalized accurately.
