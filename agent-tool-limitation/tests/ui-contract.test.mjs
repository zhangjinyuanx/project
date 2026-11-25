/**
 * UI contract tests for agent-tool-limitation/client.js (PB-03 / PB-04).
 *
 * client.js is a browser bundle (it registers itself on window.__ModuleLoader__ and
 * requires react/react-dom), so it cannot be imported like a normal module. This test
 * loads the real file in a VM sandbox with a minimal hooks runtime, then drives the
 * component the way the Web GUI does: mock /state + /action responses, fire handlers,
 * and assert on the rendered tree.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const CLIENT_PATH = path.resolve(here, "..", "client.js");
const SOURCE = fs.readFileSync(CLIENT_PATH, "utf8");

const BASE_POLICY = {
  enabled: true,
  mode: "whitelist",
  blockShellChaining: true,
  commandRules: {
    curl: {
      allowed: true,
      argWhitelistEnabled: true,
      allowedArgs: ["http://127.0.0.1", "localhost"],
      description: "网络请求工具",
    },
    git: { allowed: true, argWhitelistEnabled: true, allowedArgs: ["status", "diff"], description: "版本管理" },
    ls: { allowed: true, argWhitelistEnabled: false, allowedArgs: [], description: "列目录" },
  },
  blockedCommands: ["sudo", "rm", "chmod"],
  forbiddenPaths: ["/etc/shadow", ".ssh", ".env"],
};

/** Minimal React hooks runtime: enough for AccessControlModal (useState/useEffect/useCallback/useRef). */
function createReact() {
  const state = { cursor: 0, slots: [], dirty: false, effects: [] };
  const changed = (a, b) => {
    if (!a || !b || a.length !== b.length) return true;
    return a.some((v, i) => !Object.is(v, b[i]));
  };
  const react = {
    Fragment: "Fragment",
    createElement(type, props, ...children) {
      return { type, props: props || {}, children };
    },
    useState(initial) {
      const i = state.cursor++;
      if (!state.slots[i]) state.slots[i] = { v: typeof initial === "function" ? initial() : initial };
      const slot = state.slots[i];
      return [
        slot.v,
        (next) => {
          const value = typeof next === "function" ? next(slot.v) : next;
          if (!Object.is(slot.v, value)) {
            slot.v = value;
            state.dirty = true;
          }
        },
      ];
    },
    useRef(initial) {
      const i = state.cursor++;
      if (!state.slots[i]) state.slots[i] = { ref: { current: initial } };
      return state.slots[i].ref;
    },
    useCallback(fn, deps) {
      const i = state.cursor++;
      if (!state.slots[i] || changed(state.slots[i].deps, deps)) state.slots[i] = { fn, deps };
      return state.slots[i].fn;
    },
    useEffect(fn, deps) {
      const i = state.cursor++;
      if (!state.slots[i] || changed(state.slots[i].deps, deps)) {
        state.slots[i] = { deps, impl: fn };
        state.effects.push(fn);
      }
    },
  };
  return { react, state };
}

function loadClient() {
  const { react, state } = createReact();
  let captured = null;
  let postResponder = () => ({ ok: true, accessPolicy: BASE_POLICY });
  const requests = [];

  const sandbox = {
    window: {
      __ModuleLoader__: { load: (def) => { captured = def; } },
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => {},
    },
    fetch: async (_url, opts) => {
      if (!opts || opts.method !== "POST") {
        return { json: async () => ({ ok: true, accessPolicy: BASE_POLICY, accessAuditLog: [] }) };
      }
      const body = JSON.parse(opts.body || "{}");
      requests.push(body);
      return { json: async () => postResponder(body) };
    },
    console,
    setTimeout: () => 0,
    clearTimeout: () => {},
    setInterval: () => 0,
    clearInterval: () => {},
  };
  vm.createContext(sandbox);

  // Expose the internal component for testing by hooking the exports block, so the
  // test keeps working even if surrounding whitespace/formatting changes.
  const INJECT = "exports.__test = { AccessControlModal };";
  const marker = /exports\.inject\s*=\s*inject;/;
  const patched = marker.test(SOURCE)
    ? SOURCE.replace(marker, (m) => `${m}\n    ${INJECT}`)
    : null;
  assert.ok(
    patched && patched.includes(INJECT),
    "could not instrument client.js (exports block changed?)"
  );
  vm.runInContext(patched, sandbox);

  const mod = captured.factory((name) => {
    if (name === "react") return react;
    if (name === "react-dom") return { createRoot: () => ({ render: () => {} }) };
    throw new Error(`unexpected require: ${name}`);
  });
  const Modal = mod.__test.AccessControlModal;

  const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
  const render = () => {
    state.cursor = 0;
    state.effects = [];
    const tree = Modal({ onClose: () => {} });
    state.effects.forEach((fn) => fn());
    state.effects = [];
    return tree;
  };
  let tree = render();

  const flush = async () => {
    for (let i = 0; i < 8; i += 1) {
      if (state.dirty) {
        state.dirty = false;
        await tick();
        tree = render();
      }
      await tick();
    }
  };

  const textOf = (node) => {
    if (node === null || node === undefined || node === false) return "";
    if (typeof node === "string" || typeof node === "number") return String(node);
    if (Array.isArray(node)) return node.map(textOf).join("");
    if (node && node.type) return (node.children || []).map(textOf).join("");
    return "";
  };
  const walk = (node, out = []) => {
    if (Array.isArray(node)) node.forEach((n) => walk(n, out));
    else if (node && node.type) {
      out.push(node);
      walk(node.children, out);
    }
    return out;
  };

  return {
    flush,
    requests,
    text: () => textOf(tree),
    elements: () => walk(tree),
    button: (needle) => walk(tree).find((el) => el.type === "button" && textOf(el).includes(needle)),
    inputByPlaceholder: (needle) =>
      walk(tree).find((el) => el.type === "input" && String(el.props.placeholder || "").includes(needle)),
    inputByDefaultValue: (needle) =>
      walk(tree).find((el) => el.type === "input" && String(el.props.defaultValue || "").includes(needle)),
    setPostResponder: (fn) => { postResponder = fn; },
    async act(fn) {
      const out = fn();
      if (out && typeof out.then === "function") await out;
      await flush();
    },
  };
}

test("client.js loads and registers the two GUI slots", () => {
  const ui = loadClient();
  assert.ok(ui.text().includes("agent-tool-limitation"));
});

test("PB-03: panel shows mode, hot-reload entry and self-protection summary", async () => {
  const ui = loadClient();
  await ui.flush();
  const text = ui.text();
  assert.ok(text.includes("白名单（默认拦截，仅放行列表内命令）"), "mode is visible");
  assert.ok(text.includes("最近热重载：尚未执行"), "hot reload timestamp placeholder");
  assert.ok(text.includes("热重载策略 (Hot Reload)"), "hot reload button");
  assert.ok(text.includes("黑名单命令 & 防自篡改保护（Self-Protection）"), "self-protection card");
  for (const chip of ["sudo", "chmod", ".ssh", "/etc/shadow", "plugin.config.json", ".dsh/profiles"]) {
    assert.ok(text.includes(chip), `self-protection card renders ${chip}`);
  }
  assert.ok(
    text.includes("⚠️ 当前为白名单模式，该列表不参与判定"),
    "whitelist mode explains that blockedCommands is inert"
  );
});

test("PB-04: success path reports persisted + hot reloaded", async () => {
  const ui = loadClient();
  await ui.flush();
  ui.setPostResponder(() => ({ ok: true, persisted: true, accessPolicy: BASE_POLICY }));
  await ui.act(() => ui.button("总开关").props.onClick());
  assert.ok(ui.text().includes("✅ 策略已持久化并热重载生效（无需重启 DSH）"));
  assert.ok(!ui.text().includes("最近热重载：尚未执行"));
});

test("PB-04: disk write failure is surfaced as in-memory-only", async () => {
  const ui = loadClient();
  await ui.flush();
  ui.setPostResponder(() => ({
    ok: true,
    persisted: false,
    inMemoryUpdated: true,
    accessPolicy: BASE_POLICY,
    message: "EACCES: permission denied",
  }));
  await ui.act(() => ui.button("阻断命令拼接").props.onClick());
  assert.ok(ui.text().includes("⚠️ 仅内存生效（磁盘写入失败，重启后将回滚）：EACCES: permission denied"));
});

test("PB-04: failure is reported and never faked as '已更新'", async () => {
  const ui = loadClient();
  await ui.flush();
  ui.setPostResponder(() => ({
    ok: false,
    inMemoryUpdated: false,
    message: "配置校验失败",
    errors: ["commandRules.curl.allowedArgs[0] 非法正则"],
  }));
  await ui.act(() => ui.button("✓ 允许执行").props.onClick());
  const text = ui.text();
  assert.ok(text.includes("❌ 保存失败：配置校验失败（commandRules.curl.allowedArgs[0] 非法正则）"));
  assert.ok(!text.includes("已更新 [curl]"), "must not claim success when the save failed");
});

test("US-05: command name validation blocks empty / shell metacharacters / duplicates", async () => {
  const ui = loadClient();
  await ui.flush();

  const before = ui.requests.length;
  await ui.act(() => ui.inputByPlaceholder("新增工具/命令").props.onChange({ target: { value: "Git; rm" } }));
  await ui.act(() => ui.button("+ 添加工具").props.onClick());
  assert.ok(ui.text().includes("⚠️ 命令名不合法：不能包含空格或 Shell 特殊符号"));
  assert.equal(ui.requests.length, before, "invalid name must not hit the API");

  await ui.act(() => ui.inputByPlaceholder("新增工具/命令").props.onChange({ target: { value: "   " } }));
  await ui.act(() => ui.button("+ 添加工具").props.onClick());
  assert.ok(ui.text().includes("⚠️ 命令名不能为空"));

  await ui.act(() => ui.inputByPlaceholder("新增工具/命令").props.onChange({ target: { value: "CURL" } }));
  await ui.act(() => ui.button("+ 添加工具").props.onClick());
  assert.ok(ui.text().includes("⚠️ 命令已存在，请直接在下方列表中编辑"));
  assert.equal(ui.requests.length, before, "duplicate must not hit the API");
});

test("US-05: valid command is normalised to lower case", async () => {
  const ui = loadClient();
  await ui.flush();
  ui.setPostResponder(() => ({ ok: true, persisted: true, accessPolicy: BASE_POLICY }));
  await ui.act(() => ui.inputByPlaceholder("新增工具/命令").props.onChange({ target: { value: "Python3" } }));
  await ui.act(() => ui.button("+ 添加工具").props.onClick());
  const body = ui.requests[ui.requests.length - 1];
  assert.ok(body && body.action === "update_policy");
  assert.ok(body.policy.commandRules.python3, "payload key must be lower-cased");
});

test("US-05: invalid regex in allowedArgs is blocked before submit", async () => {
  const ui = loadClient();
  await ui.flush();
  const before = ui.requests.length;
  const target = {
    value: "/[a-z/",
    classList: { add() {}, remove() {} },
  };
  await ui.act(() => ui.inputByDefaultValue("http://127.0.0.1").props.onBlur({ target }));
  assert.ok(ui.text().includes("非法正则表达式：/[a-z/"));
  assert.equal(ui.requests.length, before, "invalid regex must not be submitted");
  assert.equal(target.value, "http://127.0.0.1, localhost", "input is restored");
});

test("US-05: valid regex in allowedArgs is submitted unchanged", async () => {
  const ui = loadClient();
  await ui.flush();
  const before = ui.requests.length;
  const target = {
    value: "/^https?:\\/\\/127\\.0\\.0\\.1/",
    classList: { add() {}, remove() {} },
  };
  await ui.act(() => ui.inputByDefaultValue("http://127.0.0.1").props.onBlur({ target }));
  const body = ui.requests[ui.requests.length - 1];
  assert.equal(ui.requests.length, before + 1);
  assert.equal(body.policy.commandRules.curl.allowedArgs[0], "/^https?:\\/\\/127\\.0\\.0\\.1/");
});

test("PB-04: manual hot reload calls reload_policy and reports the result", async () => {
  const ui = loadClient();
  await ui.flush();
  ui.setPostResponder(() => ({ ok: true, accessPolicy: { ...BASE_POLICY, blockShellChaining: false } }));
  await ui.act(() => ui.button("热重载策略").props.onClick());
  assert.equal(ui.requests[ui.requests.length - 1].action, "reload_policy");
  assert.ok(ui.text().includes("🔄 已从 plugin.config.json 重新载入策略，热重载生效（无需重启 DSH）"));

  ui.setPostResponder(() => ({ ok: false, message: "配置文件解析失败" }));
  await ui.act(() => ui.button("热重载策略").props.onClick());
  assert.ok(ui.text().includes("❌ 热重载失败：配置文件解析失败"));
});
