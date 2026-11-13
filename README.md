# Agent Tool Limitation Plugin for DeepSeek Harness (DSH)

A security and capability control plugin for autonomous AI agents within the DeepSeek Harness (DSH) runtime. It enforces fine-grained access control over agent tool invocations through a default-deny whitelist, a protected-target blacklist, and dynamic configuration hot-reloading.

> **Course:** Contemporary Issues in Software Engineering — Assignment 1  
> **Team:** Jinyuan Zhang (25305422), Jiazhuang Liu (25293517), Bochen Zhang (25307703), Cheng Chen (25307667)  
> **Submission Commit:** `b638857` (Branch: `main`)

---

## 1. Project Overview

- **Core Engine:** Intercepts agent tool execution (such as `bash` / `run_command` and file operations) via DSH's native `ctx.tools.guard` hook.
- **Dual-Layer Validation:**
  - **Target Blacklist:** Protects sensitive system paths and the plugin's own configuration (`plugin.config.json`) from agent tampering.
  - **Tool & Arg Whitelist:** Restricts allowed commands and arguments according to defined policies.
- **Dynamic Hot-Reloading:** Watchers reload access rules into memory cache upon configuration changes without restarting DSH.

---

## 2. Directory Structure

```text
├── agent-tool-limitation/        # Plugin source directory
│   ├── client.js                 # Web GUI client-side bundle
│   ├── cordis.patch.yml          # Cordis framework patch configuration
│   ├── index.mjs                 # Core plugin entry & interception guard hook
│   ├── package.json              # Plugin manifest and DSH extension declaration
│   ├── plugin.config.json        # Access control policy configuration
│   └── locale/                   # i18n localization resources
├── .gitignore                    # Git ignore file
└── README.md                     # Project documentation & setup instructions
```

---

## 3. Setup and Installation

### Prerequisites
- Node.js (v18 or later)
- DeepSeek Harness (`@deepseek-ai/dsh`) environment

### Installation Steps
1. Clone this repository:
   ```bash
   git clone https://github.com/zhangjinyuanx/project.git
   cd project
   ```
2. Navigate into the plugin directory and install dependencies:
   ```bash
   cd agent-tool-limitation
   npm install
   ```
3. Link or register the plugin with your DSH runtime:
   ```bash
   npx @deepseek-ai/dsh plugin add ./agent-tool-limitation
   ```

---

## 4. Testing Instructions

### Verifying Tool Interception & Access Control
1. **Benign Command Test (Allowed):**
   - Prompt the agent to run an approved command on the whitelist (e.g., `git status` or `ls`).
   - Expected Result: Command executes normally through the execution bridge.
2. **Forbidden Command Test (Blocked):**
   - Prompt the agent to execute an unapproved executable (e.g., `rm -rf /` or unauthorized network fetches).
   - Expected Result: Interceptor blocks execution and returns an `AEGIS_ACCESS_DENIED` security error to the agent.
3. **Anti-Tampering Test (Self-Protection):**
   - Prompt the agent to overwrite or edit `plugin.config.json`.
   - Expected Result: Target blacklist triggers immediately, rejecting the file modification call.
4. **Dynamic Hot-Reloading Test:**
   - Update an entry in `plugin.config.json` manually or via the GUI.
   - Expected Result: Changes take effect immediately in the runtime cache without requiring a DSH server restart.
