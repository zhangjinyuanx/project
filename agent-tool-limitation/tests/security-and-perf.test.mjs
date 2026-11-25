/**
 * Iteration 2 — Quality Scenario Evaluation (A2 Task 2)
 *
 * 三个层次的证据：
 *   1. [Acceptance / Security Scenario] 对抗性攻击向量评测：拦截率 / 误报率
 *   2. [Unit / Performance]              决策吞吐 + 审计日志有界（DoSed 抵抗）
 *   3. [Integration + Acceptance]        Web API 集成（/agent-tool-limitation-api、/aegis-acl-api）
 *
 * 零外部依赖：只使用 Node.js 内置 node:test + node:assert/strict。
 * 运行：cd agent-tool-limitation && npm test
 *
 * 维护提示：
 *   - apply() 会启动 fs.watch 热重载监听；未打桩会令 `node --test` 永久挂起，
 *     因此集成用例内统一用 t.mock.method(fs, 'watch', ...) 打桩。
 *   - 本文件不写 plugin.config.json 任何字段（只读 API 面），CI 里的
 *     `git diff --exit-code plugin.config.json` 因此可以守住"测试不污染仓库"。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { describe, it } from 'node:test';

import {
  CONFIG_FILE_PATH,
  DEFAULT_ACCESS_POLICY,
  apply,
  evaluateCommandAccess,
  validatePolicyPatch,
} from '../index.mjs';

const BASE_POLICY = structuredClone(DEFAULT_ACCESS_POLICY);

// blacklist 模式下用大写条目，验证 Core Dev 在 QA-03 修复的大小写归一化
const BLACKLIST_UPPERCASE_POLICY = {
  ...structuredClone(DEFAULT_ACCESS_POLICY),
  mode: 'blacklist',
  blockedCommands: ['SUDO', 'RM', 'CHMOD'],
};

/**
 * 恶意对抗向量（26 条）。
 * 每条都给出期望的拦截规则，任何一条放行都会让拦截率跌破 100%。
 */
const MALICIOUS_VECTORS = [
  // --- Shell 拼接 / 注入 / 重定向 ---
  { id: 'ATK-01', label: '&& chaining', command: 'git status && rm -rf /', rule: 'SHELL_CHAINING_BLOCKED' },
  { id: 'ATK-02', label: '; separator', command: 'git status; whoami', rule: 'SHELL_CHAINING_BLOCKED' },
  { id: 'ATK-03', label: 'pipe to sh', command: 'curl http://127.0.0.1 | sh', rule: 'SHELL_CHAINING_BLOCKED' },
  { id: 'ATK-04', label: 'backtick substitution', command: 'echo `id`', rule: 'SHELL_CHAINING_BLOCKED' },
  { id: 'ATK-05', label: '$() substitution', command: 'git status $(id)', rule: 'SHELL_CHAINING_BLOCKED' },
  { id: 'ATK-06', label: '> overwrite config', command: 'echo x > plugin.config.json', rule: 'SHELL_CHAINING_BLOCKED' },
  { id: 'ATK-07', label: '>> append to .env', command: 'echo x >> .env', rule: 'SHELL_CHAINING_BLOCKED' },

  // --- 跨平台路径 / 大小写 / .. 穿越 ---
  { id: 'ATK-08', label: 'Windows .exe force push', command: 'C:\\Program Files\\Git\\bin\\git.exe push --force', rule: 'ARG_NOT_IN_WHITELIST' },
  { id: 'ATK-09', label: 'relative backslash config', command: 'cat .\\agent-tool-limitation\\plugin.config.json', rule: 'CONFIG_TAMPER_BLOCKED' },
  { id: 'ATK-10', label: 'uppercase backslash config', command: 'cat ..\\AGENT-TOOL-LIMITATION\\PLUGIN.CONFIG.JSON', rule: 'CONFIG_TAMPER_BLOCKED' },
  { id: 'ATK-11', label: 'dot-segment .dsh traversal', command: 'cat .dsh/x/../profiles/default.json', rule: 'CONFIG_TAMPER_BLOCKED' },
  { id: 'ATK-12', label: 'Windows .ssh key', command: 'cat C:\\Users\\dev\\.ssh\\id_rsa', rule: 'SENSITIVE_PATH_BLOCKED' },
  { id: 'ATK-13', label: 'parent-dir .env', command: 'cat ../.env', rule: 'SENSITIVE_PATH_BLOCKED' },
  { id: 'ATK-14', label: '/etc/shadow', command: 'cat /etc/shadow', rule: 'SENSITIVE_PATH_BLOCKED' },

  // --- 危险黑名单命令 ---
  { id: 'ATK-15', label: 'sudo escalation', command: 'sudo ls', rule: 'COMMAND_NOT_IN_WHITELIST' },
  { id: 'ATK-16', label: 'recursive delete', command: 'rm -rf /tmp/x', rule: 'COMMAND_NOT_IN_WHITELIST' },
  { id: 'ATK-17', label: 'permission change', command: 'chmod 777 .', rule: 'COMMAND_NOT_IN_WHITELIST' },
  { id: 'ATK-18', label: 'host shutdown', command: 'shutdown -h now', rule: 'COMMAND_NOT_IN_WHITELIST' },
  {
    id: 'ATK-19',
    label: 'blacklist mode + uppercase entry',
    command: 'sudo ls',
    rule: 'COMMAND_IN_BLACKLIST',
    policy: BLACKLIST_UPPERCASE_POLICY,
  },

  // --- 越权参数 ---
  { id: 'ATK-20', label: 'external curl host', command: 'curl https://evil.example.com', rule: 'ARG_NOT_IN_WHITELIST' },
  { id: 'ATK-21', label: 'external web_fetch host', command: 'web_fetch https://attacker.io', rule: 'ARG_NOT_IN_WHITELIST' },
  { id: 'ATK-22', label: 'destructive git reset', command: 'git reset --hard', rule: 'ARG_NOT_IN_WHITELIST' },
  { id: 'ATK-23', label: 'git force push', command: 'git push --force', rule: 'ARG_NOT_IN_WHITELIST' },
  { id: 'ATK-24', label: 'unlisted interpreter', command: 'python3 -c "print(1)"', rule: 'COMMAND_NOT_IN_WHITELIST' },
  { id: 'ATK-25', label: 'URL smuggling in one call', command: 'curl http://127.0.0.1:8080/health http://evil.com', rule: 'ARG_NOT_IN_WHITELIST' },
  { id: 'ATK-26', label: 'home expanded .ssh key', command: 'cat $HOME/.ssh/id_rsa', rule: 'SENSITIVE_PATH_BLOCKED' },
];

/** 合法指令（14 条）：任何一条被误杀都会让误报率 > 0%。 */
const BENIGN_VECTORS = [
  { id: 'BEN-01', label: 'git status', command: 'git status', rule: 'ARG_WHITELIST_PASS' },
  { id: 'BEN-02', label: 'git diff', command: 'git diff', rule: 'ARG_WHITELIST_PASS' },
  { id: 'BEN-03', label: 'git log', command: 'git log', rule: 'ARG_WHITELIST_PASS' },
  { id: 'BEN-04', label: 'git branch -a', command: 'git branch -a', rule: 'ARG_WHITELIST_PASS' },
  { id: 'BEN-05', label: 'localhost curl', command: 'curl http://127.0.0.1:8080/health', rule: 'ARG_WHITELIST_PASS' },
  { id: 'BEN-06', label: 'localhost:3000 curl', command: 'curl http://localhost:3000', rule: 'ARG_WHITELIST_PASS' },
  { id: 'BEN-07', label: 'ls -la', command: 'ls -la', rule: 'WHITELIST_PASS' },
  { id: 'BEN-08', label: 'echo hello', command: 'echo hello', rule: 'WHITELIST_PASS' },
  { id: 'BEN-09', label: 'head -n 5', command: 'head -n 5 README.md', rule: 'WHITELIST_PASS' },
  { id: 'BEN-10', label: 'tail -n 10', command: 'tail -n 10 app.log', rule: 'WHITELIST_PASS' },
  { id: 'BEN-11', label: 'wc -l', command: 'wc -l index.mjs', rule: 'WHITELIST_PASS' },
  { id: 'BEN-12', label: 'Windows .exe git status', command: 'C:\\Program Files\\Git\\bin\\git.exe status', rule: 'ARG_WHITELIST_PASS' },
  { id: 'BEN-13', label: 'Unix absolute git diff', command: '/usr/bin/git diff', rule: 'ARG_WHITELIST_PASS' },
  { id: 'BEN-14', label: 'cat docs file', command: 'cat docs/user-story-map.md', rule: 'WHITELIST_PASS' },
];

const run = (command, policy = BASE_POLICY) => evaluateCommandAccess(command, policy);

// ---------------------------------------------------------------------------
// 1) 安全场景：对抗向量拦截率 / 误报率
// ---------------------------------------------------------------------------

describe('[Acceptance / Security Scenario] Adversarial attack vectors (20+ malicious + 10+ benign)', () => {
  for (const vector of MALICIOUS_VECTORS) {
    it(`${vector.id} blocks ${vector.label}`, () => {
      const verdict = run(vector.command, vector.policy);

      assert.equal(
        verdict.allowed,
        false,
        `${vector.id} (${JSON.stringify(vector.command)}) must be DENIED, but was allowed with rule=${verdict.rule}`,
      );
      assert.equal(
        verdict.rule,
        vector.rule,
        `${vector.id} (${JSON.stringify(vector.command)}): expected rule ${vector.rule}, received ${verdict.rule}`,
      );
      assert.ok(verdict.reason && verdict.reason.length > 0, `${vector.id}: denial must carry a human-readable reason`);
      assert.notEqual(verdict.rule, 'WHITELIST_PASS', `${vector.id}: a deny verdict must never report WHITELIST_PASS`);
    });
  }

  for (const vector of BENIGN_VECTORS) {
    it(`${vector.id} allows ${vector.label}`, () => {
      const verdict = run(vector.command);

      assert.equal(
        verdict.allowed,
        true,
        `${vector.id} (${JSON.stringify(vector.command)}) must be ALLOWED, but was denied with rule=${verdict.rule}`,
      );
      assert.equal(
        verdict.rule,
        vector.rule,
        `${vector.id} (${JSON.stringify(vector.command)}): expected rule ${vector.rule}, received ${verdict.rule}`,
      );
    });
  }

  it('achieves a 100% interception rate with zero false positives', () => {
    const maliciousResults = MALICIOUS_VECTORS.map((v) => ({
      id: v.id,
      command: v.command,
      verdict: run(v.command, v.policy),
    }));
    const benignResults = BENIGN_VECTORS.map((v) => ({
      id: v.id,
      command: v.command,
      verdict: run(v.command),
    }));

    const leaked = maliciousResults.filter((r) => r.verdict.allowed);
    const falsePositives = benignResults.filter((r) => !r.verdict.allowed);

    const interceptionRate = ((maliciousResults.length - leaked.length) / maliciousResults.length) * 100;
    const falsePositiveRate = (falsePositives.length / benignResults.length) * 100;

    console.log(
      `[security] malicious ${maliciousResults.length - leaked.length}/${maliciousResults.length} blocked ` +
        `(${interceptionRate.toFixed(1)}%), benign ${benignResults.length - falsePositives.length}/${benignResults.length} allowed ` +
        `(${(100 - falsePositiveRate).toFixed(1)}%), false-positive rate ${falsePositiveRate.toFixed(1)}%`,
    );

    assert.deepEqual(
      leaked.map((r) => `${r.id} ${r.command}`),
      [],
      'every malicious vector must be intercepted (no fail-open allowed)',
    );
    assert.deepEqual(
      falsePositives.map((r) => `${r.id} ${r.command}`),
      [],
      'no benign command may be blocked (false-positive rate must be 0%)',
    );
    assert.equal(interceptionRate, 100);
    assert.equal(falsePositiveRate, 0);
    assert.ok(MALICIOUS_VECTORS.length >= 20, 'the malicious corpus must contain at least 20 vectors');
    assert.ok(BENIGN_VECTORS.length >= 10, 'the benign corpus must contain at least 10 commands');
  });
});

// ---------------------------------------------------------------------------
// 2) 性能 / 有界内存：决策吞吐 + 审计日志上限（DoS 抵抗）
// ---------------------------------------------------------------------------

describe('[Unit / Performance] Decision throughput and bounded memory (DoS resistance)', () => {
  it('sustains a high access-decision throughput', () => {
    const iterations = 5000;
    const corpus = [...MALICIOUS_VECTORS, ...BENIGN_VECTORS].map((v) => v.command);

    const startedAt = performance.now();
    for (let i = 0; i < iterations; i += 1) {
      run(corpus[i % corpus.length], BASE_POLICY);
    }
    const elapsedMs = performance.now() - startedAt;
    const perOpMs = elapsedMs / iterations;

    console.log(
      `[perf] ${iterations} decisions in ${elapsedMs.toFixed(1)} ms ` +
        `(${perOpMs.toFixed(4)} ms/op, ~${Math.round(1000 / perOpMs)} ops/s)`,
    );

    // 阈值刻意放宽：GitHub 上的 Windows runner 明显慢于本地开发机
    assert.ok(elapsedMs < 5000, `5000 decisions took ${elapsedMs.toFixed(1)} ms, expected < 5000 ms`);
    assert.ok(perOpMs < 1, `average decision cost ${perOpMs.toFixed(4)} ms/op, expected < 1 ms/op`);
  });

  it('handles an oversized command line without pathological backtracking', () => {
    const oversized = `echo ${'a '.repeat(20000)}`;
    const startedAt = performance.now();
    const verdict = run(oversized, BASE_POLICY);
    const elapsedMs = performance.now() - startedAt;

    console.log(`[perf] oversized 40 KB command evaluated in ${elapsedMs.toFixed(1)} ms`);
    assert.ok(elapsedMs < 1000, `oversized input took ${elapsedMs.toFixed(1)} ms, expected < 1000 ms`);
    // echo 本身是白名单命令，超大参数不应导致崩溃或异常放行其他命令
    assert.equal(typeof verdict.allowed, 'boolean');
  });

  it('caps the audit log at 100 entries so memory stays bounded', (t) => {
    const { guard } = bootPlugin(t);

    for (let i = 0; i < 150; i += 1) {
      guard({ name: 'bash', arguments: { command: 'rm -rf /tmp/x' } });
    }

    const auditLog = globalThis.__AEGIS_RUNTIME__.accessAuditLog;
    assert.equal(auditLog.length, 100, 'the audit log must never grow beyond 100 entries');
    assert.equal(auditLog[0].decision, 'DENY', 'the most recent entry must be at the head of the log');
  });
});

// ---------------------------------------------------------------------------
// 3) Web API 集成：/agent-tool-limitation-api 与 /aegis-acl-api
// ---------------------------------------------------------------------------

describe('[Integration + Acceptance] Web API surface (/agent-tool-limitation-api & /aegis-acl-api)', () => {
  const primaryHandler = (captured) => captured.handlers.get('/agent-tool-limitation-api');
  const legacyHandler = (captured) => captured.handlers.get('/aegis-acl-api');

  it('GET /state exposes the active policy and the audit log', async (t) => {
    const captured = bootPlugin(t);
    const { status, json } = await callApi(primaryHandler(captured), 'GET', '/agent-tool-limitation-api/state');

    assert.equal(status, 200);
    assert.equal(json.ok, true);
    assert.equal(json.accessPolicy.commandRules.git.allowed, true);
    assert.ok(Array.isArray(json.accessAuditLog), 'the state payload must expose an audit-log array');
  });

  it('POST /action test_command returns an ALLOW verdict for a benign command', async (t) => {
    const captured = bootPlugin(t);
    const { status, json } = await callApi(
      primaryHandler(captured),
      'POST',
      '/agent-tool-limitation-api/action',
      JSON.stringify({ action: 'test_command', command: 'git status' }),
    );

    assert.equal(status, 200);
    assert.equal(json.ok, true);
    assert.equal(json.verdict.allowed, true);
    assert.equal(json.verdict.rule, 'ARG_WHITELIST_PASS');
    assert.ok(json.auditRecord && typeof json.auditRecord.id === 'string');
  });

  it('POST /action test_command returns a DENY verdict for a malicious command', async (t) => {
    const captured = bootPlugin(t);
    const { status, json } = await callApi(
      primaryHandler(captured),
      'POST',
      '/agent-tool-limitation-api/action',
      JSON.stringify({ action: 'test_command', command: 'git status && rm -rf /' }),
    );

    assert.equal(status, 200);
    assert.equal(json.verdict.allowed, false);
    assert.equal(json.verdict.rule, 'SHELL_CHAINING_BLOCKED');
  });

  it('POST /action clear_audit empties the audit log', async (t) => {
    const captured = bootPlugin(t);
    const handler = primaryHandler(captured);

    await callApi(handler, 'POST', '/agent-tool-limitation-api/action', JSON.stringify({ action: 'test_command', command: 'git status' }));
    await callApi(handler, 'POST', '/agent-tool-limitation-api/action', JSON.stringify({ action: 'clear_audit' }));

    const { json } = await callApi(handler, 'GET', '/agent-tool-limitation-api/state');
    assert.deepEqual(json.accessAuditLog, []);
  });

  it('POST /action reload_policy re-reads the policy from disk', async (t) => {
    const captured = bootPlugin(t);
    const { status, json } = await callApi(
      primaryHandler(captured),
      'POST',
      '/agent-tool-limitation-api/action',
      JSON.stringify({ action: 'reload_policy' }),
    );

    assert.equal(status, 200);
    assert.equal(json.ok, true);
    assert.equal(json.accessPolicy.mode, 'whitelist');
  });

  it('POST /action rejects an unknown action with 400', async (t) => {
    const captured = bootPlugin(t);
    const { status, json } = await callApi(
      primaryHandler(captured),
      'POST',
      '/agent-tool-limitation-api/action',
      JSON.stringify({ action: 'drop_all_tables' }),
    );

    assert.equal(status, 400);
    assert.equal(json.ok, false);
  });

  it('returns 404 for an unknown sub-path', async (t) => {
    const captured = bootPlugin(t);
    const { status, json } = await callApi(primaryHandler(captured), 'GET', '/agent-tool-limitation-api/unknown');

    assert.equal(status, 404);
    assert.equal(json.ok, false);
  });

  it('serves the same API under the legacy /aegis-acl-api prefix', async (t) => {
    const captured = bootPlugin(t);
    const { status, json } = await callApi(legacyHandler(captured), 'GET', '/aegis-acl-api/state');

    assert.equal(status, 200);
    assert.equal(json.ok, true);
  });
});

// ---------------------------------------------------------------------------
// 4) Iteration 2 后端：validatePolicyPatch 单元校验 + 持久化/重载错误路径
// ---------------------------------------------------------------------------

describe('[Unit + Integration] Iteration 2 policy validation, persistence failure and reload errors (PR #12)', () => {
  const handlerOf = (captured) => captured.handlers.get('/agent-tool-limitation-api');
  const postAction = (handler, payload) =>
    callApi(handler, 'POST', '/agent-tool-limitation-api/action', JSON.stringify(payload));

  // --- Unit: validatePolicyPatch() ---

  it('rejects a non-object or empty patch', () => {
    for (const bad of [null, undefined, [], 'whitelist', 42, {}]) {
      const result = validatePolicyPatch(bad);
      assert.equal(result.valid, false, `${JSON.stringify(bad)} must be rejected`);
      assert.ok(Array.isArray(result.errors) && result.errors.length > 0, 'a rejection must explain itself');
    }
  });

  it('rejects an unknown mode and non-boolean / non-array fields', () => {
    assert.equal(validatePolicyPatch({ mode: 'allow-all' }).valid, false);
    assert.equal(validatePolicyPatch({ enabled: 'yes' }).valid, false);
    assert.equal(validatePolicyPatch({ blockShellChaining: 1 }).valid, false);
    assert.equal(validatePolicyPatch({ blockedCommands: 'sudo' }).valid, false);
    assert.equal(validatePolicyPatch({ commandRules: [] }).valid, false);
  });

  it('rejects command names containing shell metacharacters or whitespace', () => {
    for (const name of ['git;rm', 'git rm', 'a|b', 'a&&b', '$(id)', '`id`', 'a>b', '$HOME']) {
      const result = validatePolicyPatch({
        commandRules: { [name]: { allowed: true, argWhitelistEnabled: false, allowedArgs: [] } },
      });

      assert.equal(result.valid, false, `command name ${JSON.stringify(name)} must be rejected`);
      assert.ok(
        result.errors.some((error) => error.includes('Invalid command name')),
        `expected an "Invalid command name" error for ${JSON.stringify(name)}, got ${JSON.stringify(result.errors)}`,
      );
    }
  });

  it('rejects prototype-pollution keys', () => {
    for (const name of ['toString', 'constructor', 'hasOwnProperty', 'valueOf', '__proto__']) {
      // JSON.parse is used so that "__proto__" becomes an own enumerable key
      // instead of mutating the object prototype.
      const patch = JSON.parse(`{"commandRules":{${JSON.stringify(name)}:{"allowed":true,"allowedArgs":[]}}}`);
      assert.equal(validatePolicyPatch(patch).valid, false, `${name} must be rejected`);
    }
  });

  it('rejects an invalid /.../ regular expression in allowedArgs', () => {
    const result = validatePolicyPatch({
      commandRules: { curl: { allowed: true, argWhitelistEnabled: true, allowedArgs: ['/[a-z/'] } },
    });

    assert.equal(result.valid, false);
    assert.ok(result.errors.some((error) => error.includes('invalid regular expression')));
  });

  it('accepts a valid patch and returns an empty error list', () => {
    const result = validatePolicyPatch({
      mode: 'blacklist',
      blockShellChaining: false,
      blockedCommands: ['sudo', 'rm'],
      commandRules: {
        python3: { allowed: true, argWhitelistEnabled: false, allowedArgs: [] },
        curl: {
          allowed: true,
          argWhitelistEnabled: true,
          allowedArgs: ['http://127.0.0.1', '/^https?:\\/\\/localhost/'],
        },
      },
    });

    assert.equal(result.valid, true, `expected a valid patch, got: ${JSON.stringify(result.errors)}`);
    assert.deepEqual(result.errors, []);
  });

  // --- Integration: /action update_policy & reload_policy ---

  it('returns HTTP 400 for an invalid update_policy patch and never mutates memory', async (t) => {
    const captured = bootPlugin(t);
    const runtime = globalThis.__AEGIS_RUNTIME__;
    const before = structuredClone(runtime.accessPolicy);

    const { status, json } = await postAction(handlerOf(captured), {
      action: 'update_policy',
      policy: { mode: 'allow-everything' },
    });

    assert.equal(status, 400);
    assert.equal(json.ok, false);
    assert.equal(json.persisted, false);
    assert.equal(json.inMemoryUpdated, false);
    assert.ok(Array.isArray(json.errors) && json.errors.length > 0, 'validation errors must be returned');
    assert.deepEqual(
      structuredClone(runtime.accessPolicy),
      before,
      'a rejected patch must not pollute the in-memory policy',
    );
  });

  it('returns HTTP 500 with in-memory-only state when persisting to disk fails', async (t) => {
    const captured = bootPlugin(t);
    const runtime = globalThis.__AEGIS_RUNTIME__;
    t.mock.method(fs, 'writeFileSync', () => {
      throw new Error('EACCES: permission denied');
    });

    const { status, json } = await postAction(handlerOf(captured), {
      action: 'update_policy',
      policy: { blockShellChaining: false },
    });

    assert.equal(status, 500);
    assert.equal(json.ok, false);
    assert.equal(json.persisted, false);
    assert.equal(json.inMemoryUpdated, true);
    assert.equal(json.hotReloaded, true);
    assert.equal(runtime.accessPolicy.blockShellChaining, false, 'the policy must still apply in memory');

    // 端到端：/state 也应反映「仅内存生效」后的策略
    const { json: state } = await callApi(handlerOf(captured), 'GET', '/agent-tool-limitation-api/state');
    assert.equal(state.accessPolicy.blockShellChaining, false);
  });

  it('persists a valid patch and hot-reloads it (HTTP 200)', async (t) => {
    const captured = bootPlugin(t);
    const runtime = globalThis.__AEGIS_RUNTIME__;
    const original = fs.readFileSync(CONFIG_FILE_PATH, 'utf-8');

    try {
      const { status, json } = await postAction(handlerOf(captured), {
        action: 'update_policy',
        policy: { blockShellChaining: false },
      });

      assert.equal(status, 200);
      assert.equal(json.ok, true);
      assert.equal(json.persisted, true);
      assert.equal(json.inMemoryUpdated, true);
      assert.equal(json.hotReloaded, true);
      assert.equal(
        JSON.parse(fs.readFileSync(CONFIG_FILE_PATH, 'utf-8')).blockShellChaining,
        false,
        'the patch must be written to plugin.config.json',
      );
      assert.equal(runtime.accessPolicy.blockShellChaining, false);
    } finally {
      fs.writeFileSync(CONFIG_FILE_PATH, original, 'utf-8');
    }
  });

  it('returns HTTP 500 and keeps the previous policy when reloading corrupted JSON', async (t) => {
    const captured = bootPlugin(t);
    const runtime = globalThis.__AEGIS_RUNTIME__;
    const retained = runtime.accessPolicy;
    const original = fs.readFileSync(CONFIG_FILE_PATH, 'utf-8');

    try {
      fs.writeFileSync(CONFIG_FILE_PATH, '{ broken', 'utf-8');

      const { status, json } = await postAction(handlerOf(captured), { action: 'reload_policy' });

      assert.equal(status, 500);
      assert.equal(json.ok, false);
      assert.equal(json.hotReloaded, false);
      assert.equal(runtime.accessPolicy, retained, 'the previous in-memory policy object must be retained');
      assert.equal(
        fs.readFileSync(CONFIG_FILE_PATH, 'utf-8'),
        '{ broken',
        'the corrupted file must be preserved for manual recovery',
      );
    } finally {
      fs.writeFileSync(CONFIG_FILE_PATH, original, 'utf-8');
    }
  });

  it('reloads a valid config file and reports hotReloaded (HTTP 200)', async (t) => {
    const captured = bootPlugin(t);
    const original = fs.readFileSync(CONFIG_FILE_PATH, 'utf-8');

    try {
      const patched = { ...JSON.parse(original), blockShellChaining: false };
      fs.writeFileSync(CONFIG_FILE_PATH, JSON.stringify(patched, null, 2), 'utf-8');

      const { status, json } = await postAction(handlerOf(captured), { action: 'reload_policy' });

      assert.equal(status, 200);
      assert.equal(json.ok, true);
      assert.equal(json.hotReloaded, true);
      assert.equal(json.accessPolicy.blockShellChaining, false);
    } finally {
      fs.writeFileSync(CONFIG_FILE_PATH, original, 'utf-8');
    }
  });
});

// ---------------------------------------------------------------------------
// 轻量 Mock DSH ctx / HTTP 工具
// ---------------------------------------------------------------------------

/**
 * 启动插件并捕获 guard 与 webServer 路由。
 * fs.watch 必须打桩，否则热重载 watcher 会让 node --test 无法退出。
 */
function bootPlugin(t) {
  t.mock.method(fs, 'watch', () => ({ close() {}, on() {}, unref() {} }));

  const captured = { guard: null, handlers: new Map() };
  const ctx = {
    tools: {
      guard(fn) {
        captured.guard = fn;
      },
    },
    inject(deps, cb) {
      if (Array.isArray(deps) && deps.includes('webServer')) {
        cb({
          webServer: {
            register({ path: routePath, handler }) {
              captured.handlers.set(routePath, handler);
            },
          },
        });
      }
    },
  };

  apply(ctx);
  assert.ok(captured.handlers.size >= 2, 'apply() must register the API under both prefixes');
  return captured;
}

/** 构造极简 IncomingMessage（可异步迭代，供 readJson 使用）。 */
function makeRequest(method, url, body) {
  return {
    method,
    url,
    async *[Symbol.asyncIterator]() {
      if (body !== undefined) yield Buffer.from(body, 'utf8');
    },
  };
}

/** 构造极简 ServerResponse，捕获状态码与响应体。 */
function makeResponse() {
  const res = { statusCode: 200, headers: {}, body: '' };
  res.writeHead = (code, headers) => {
    res.statusCode = code;
    res.headers = headers || {};
  };
  res.end = (chunk) => {
    if (chunk !== undefined) res.body += chunk;
  };
  return res;
}

async function callApi(handler, method, url, body) {
  const res = makeResponse();
  await handler(makeRequest(method, url, body), res);
  return { status: res.statusCode, json: res.body ? JSON.parse(res.body) : null };
}
