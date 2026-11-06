/**
 * @aegis/dsh-plugin-access-control
 *
 * 通用工具/命令与参数白名单访问控制插件（DeepSeek Harness 独立插件）
 *
 * 核心设计：
 * 1. 工具/命令级控制（allowed）：决定某个命令或工具是否允许被调用；
 * 2. 按工具独立开关的参数白名单（argWhitelistEnabled + allowedArgs）：
 *    - 若某个工具/命令开启了 argWhitelistEnabled: true，则其后面的参数（如请求目标地址、操作文件路径、子命令）
 *      必须命中该命令专属的 allowedArgs 白名单；
 *    - 若某个工具/命令设为 argWhitelistEnabled: false（不开启），则跳过该命令的参数白名单检查，不限制其操作对象。
 * 3. 全局底线防护：可选阻断危险 Shell 拼接符（; | & $() >）与系统高危敏感路径（/etc/shadow, .ssh 等）。
 */

export const name = 'aegis-access-control';
export const inject = ['tools'];

/**
 * 默认工具与命令访问控制策略
 * 每个命令都可以独立配置：
 * - allowed: 是否允许执行该命令
 * - argWhitelistEnabled: 是否开启该命令后面的参数/目标地址白名单检查
 * - allowedArgs: 开启参数白名单时允许的目标地址、路径前缀、子命令或正则表达式
 */
export const DEFAULT_ACCESS_POLICY = {
  enabled: true,
  mode: 'whitelist', // 'whitelist'（仅允许 commandRules 中 allowed:true 的命令）| 'blacklist'（除 blockedCommands 外默认放行）
  blockShellChaining: true,
  commandRules: {
    curl: {
      allowed: true,
      argWhitelistEnabled: true,
      allowedArgs: ['http://127.0.0.1', 'http://localhost', '127.0.0.1', 'localhost'],
      description: '网络请求工具（开启参数白名单以限制允许访问的目标地址）',
    },
    web_fetch: {
      allowed: true,
      argWhitelistEnabled: true,
      allowedArgs: ['http://127.0.0.1', 'http://localhost', '127.0.0.1', 'localhost'],
      description: '内置网页抓取工具（限制允许抓取的目标地址）',
    },
    git: {
      allowed: true,
      argWhitelistEnabled: true,
      allowedArgs: ['status', 'diff', 'log', 'branch', 'show'],
      description: '代码版本管理（开启参数白名单时仅允许只读子命令，禁止 push --force 等）',
    },
    cat: {
      allowed: true,
      argWhitelistEnabled: false,
      allowedArgs: ['runs/', './logs/', 'docs/'],
      description: '查看文件内容（开启参数白名单时可限制仅允许读取的目录/文件）',
    },
    read: {
      allowed: true,
      argWhitelistEnabled: false,
      allowedArgs: ['runs/', './logs/', 'docs/'],
      description: '内置文件读取工具（开启参数白名单时可限制仅允许读取的目录/文件）',
    },
    grep: {
      allowed: true,
      argWhitelistEnabled: false,
      allowedArgs: ['runs/', './logs/'],
      description: '文本检索工具',
    },
    head: {
      allowed: true,
      argWhitelistEnabled: false,
      allowedArgs: [],
      description: '查看文件头部',
    },
    tail: {
      allowed: true,
      argWhitelistEnabled: false,
      allowedArgs: [],
      description: '查看文件尾部',
    },
    wc: {
      allowed: true,
      argWhitelistEnabled: false,
      allowedArgs: [],
      description: '行数与字符统计',
    },
    ls: {
      allowed: true,
      argWhitelistEnabled: false,
      allowedArgs: [],
      description: '列出目录内容',
    },
    jq: {
      allowed: true,
      argWhitelistEnabled: false,
      allowedArgs: [],
      description: 'JSON 解析工具',
    },
    awk: {
      allowed: true,
      argWhitelistEnabled: false,
      allowedArgs: [],
      description: '文本列处理工具',
    },
    sed: {
      allowed: true,
      argWhitelistEnabled: false,
      allowedArgs: [],
      description: '流式文本处理工具',
    },
    echo: {
      allowed: true,
      argWhitelistEnabled: false,
      allowedArgs: [],
      description: '输出文本',
    },
  },
  blockedCommands: [
    'sudo',
    'su',
    'rm',
    'mkfs',
    'dd',
    'shutdown',
    'reboot',
    'chmod',
    'chown',
  ],
  forbiddenPaths: [
    '/etc/shadow',
    '/etc/passwd',
    '.credentials.yaml',
    'auth.json',
    '.ssh',
    '.env',
  ],
  // 防自篡改保护路径：严禁 AI 通过命令行、write/edit 工具或本地接口修改插件配置与源码
  protectedConfigPaths: [
    'cordis.patch.yml',
    'cordis.yml',
    'aegis-access-control',
    '.dsh/profiles',
    '/aegis-acl-api',
    '/aegis-api/action',
  ],
};

// 常见的带参数值的短选项（例如 curl -X POST -H "Accept: */*" 中的 POST 和 Header 值本身不是目标地址对象）
const VALUE_TAKING_FLAGS = new Set([
  '-X',
  '--request',
  '-H',
  '--header',
  '-d',
  '--data',
  '--data-raw',
  '-m',
  '--max-time',
  '-A',
  '--user-agent',
  '-n',
  '-e',
  '-E',
  '-F',
]);

/**
 * 归一化策略配置（兼容旧版 allowedCommands / allowedHosts 字段，统一转换为 commandRules）
 */
export function normalizeAccessPolicy(input = {}) {
  const baseRules = {};
  for (const [k, v] of Object.entries(DEFAULT_ACCESS_POLICY.commandRules)) {
    baseRules[k] = {
      allowed: Boolean(v.allowed),
      argWhitelistEnabled: Boolean(v.argWhitelistEnabled),
      allowedArgs: Array.isArray(v.allowedArgs) ? [...v.allowedArgs] : [],
      description: v.description || '',
    };
  }

  // 若传入了旧版 allowedCommands 数组，按数组同步各命令的 allowed 状态
  if (Array.isArray(input.allowedCommands) && !input.commandRules) {
    const allowedSet = new Set(input.allowedCommands);
    for (const k of Object.keys(baseRules)) {
      if (k !== 'web_fetch' && k !== 'read') {
        baseRules[k].allowed = allowedSet.has(k);
      }
    }
    for (const cmd of input.allowedCommands) {
      if (!baseRules[cmd]) {
        baseRules[cmd] = {
          allowed: true,
          argWhitelistEnabled: false,
          allowedArgs: [],
          description: '自定义命令',
        };
      }
    }
  }

  // 若传入了旧版 allowedHosts，同步给 curl 和 web_fetch 的 allowedArgs
  if (Array.isArray(input.allowedHosts) && !input.commandRules) {
    const hostPatterns = input.allowedHosts.flatMap((h) =>
      h.startsWith('http') ? [h] : [`http://${h}`, `https://${h}`, h]
    );
    if (baseRules.curl) {
      baseRules.curl.argWhitelistEnabled = hostPatterns.length > 0;
      baseRules.curl.allowedArgs = hostPatterns;
    }
    if (baseRules.web_fetch) {
      baseRules.web_fetch.argWhitelistEnabled = hostPatterns.length > 0;
      baseRules.web_fetch.allowedArgs = hostPatterns;
    }
  }

  // 合并显式传入的 commandRules
  if (input.commandRules && typeof input.commandRules === 'object') {
    for (const [cmd, rule] of Object.entries(input.commandRules)) {
      if (!rule || typeof rule !== 'object') continue;
      const prev = baseRules[cmd] || {
        allowed: true,
        argWhitelistEnabled: false,
        allowedArgs: [],
        description: '',
      };
      baseRules[cmd] = {
        allowed: rule.allowed !== undefined ? Boolean(rule.allowed) : prev.allowed,
        argWhitelistEnabled:
          rule.argWhitelistEnabled !== undefined
            ? Boolean(rule.argWhitelistEnabled)
            : prev.argWhitelistEnabled,
        allowedArgs: Array.isArray(rule.allowedArgs)
          ? rule.allowedArgs.map((s) => String(s).trim()).filter(Boolean)
          : prev.allowedArgs,
        description: rule.description ?? prev.description ?? '',
      };
    }
  }

  const allowedCommands = Object.entries(baseRules)
    .filter(([, r]) => r.allowed)
    .map(([cmd]) => cmd);

  return {
    enabled: input.enabled !== undefined ? Boolean(input.enabled) : DEFAULT_ACCESS_POLICY.enabled,
    mode: input.mode || DEFAULT_ACCESS_POLICY.mode,
    blockShellChaining:
      input.blockShellChaining !== undefined
        ? Boolean(input.blockShellChaining)
        : DEFAULT_ACCESS_POLICY.blockShellChaining,
    commandRules: baseRules,
    allowedCommands,
    blockedCommands: Array.isArray(input.blockedCommands)
      ? [...input.blockedCommands]
      : [...DEFAULT_ACCESS_POLICY.blockedCommands],
    forbiddenPaths: Array.isArray(input.forbiddenPaths)
      ? [...input.forbiddenPaths]
      : [...DEFAULT_ACCESS_POLICY.forbiddenPaths],
  };
}

/**
 * 判断单个参数/目标对象是否匹配某条白名单规则 pattern
 * 支持：
 * 1. 正则表达式：以 / 开头和结尾，如 /^https?:\/\/127\.0\.0\.1/
 * 2. 通配符：包含 *，如 http://127.0.0.1:* 或 *.log
 * 3. URL / 主机名匹配：如 pattern 为 127.0.0.1 或 http://127.0.0.1，自动匹配 http://127.0.0.1:18080/api
 * 4. 路径前缀 / 子命令精确或前缀匹配：如 runs/ 匹配 runs/2026/a.log，status 匹配 status
 */
export function matchArgPattern(targetArg, rawArgs, pattern) {
  const pat = String(pattern ?? '').trim();
  const arg = String(targetArg ?? '').trim();
  if (!pat || !arg) return false;

  // 1. 正则模式 /.../
  if (pat.length > 2 && pat.startsWith('/') && pat.endsWith('/')) {
    try {
      const re = new RegExp(pat.slice(1, -1), 'i');
      return re.test(arg) || re.test(rawArgs);
    } catch {
      return false;
    }
  }

  // 2. 通配符模式 *
  if (pat.includes('*')) {
    const escaped = pat.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    const re = new RegExp(`^${escaped}$`, 'i');
    return re.test(arg) || re.test(rawArgs);
  }

  // 3. URL 与主机地址匹配
  if (/^https?:\/\//i.test(arg)) {
    try {
      const parsedArg = new URL(arg);
      if (arg.toLowerCase().startsWith(pat.toLowerCase())) return true;
      if (parsedArg.hostname.toLowerCase() === pat.toLowerCase()) return true;
      if (parsedArg.host.toLowerCase() === pat.toLowerCase()) return true;
    } catch {
      return false;
    }
  }

  // 4. 精确匹配或前缀匹配（如目录前缀 runs/、URL 前缀、子命令）
  if (arg === pat || arg.startsWith(pat)) return true;
  if (rawArgs === pat || rawArgs.startsWith(`${pat} `)) return true;

  return false;
}

/**
 * 当某个命令开启了 argWhitelistEnabled: true 时，校验其后面的参数与操作对象是否在白名单中
 */
export function checkCommandArgWhitelist(bin, tokens, rawArgs, allowedArgs = []) {
  const cleanAllowed = (allowedArgs || []).map((s) => String(s).trim()).filter(Boolean);
  if (cleanAllowed.length === 0) {
    return {
      allowed: false,
      rule: 'ARG_WHITELIST_EMPTY',
      reason: `访问控制拦截：工具 "${bin}" 已开启参数白名单检查，但白名单列表为空（未放行任何参数）`,
    };
  }

  const argTokens = tokens.slice(1);
  if (argTokens.length === 0) {
    return {
      allowed: false,
      rule: 'ARG_REQUIRED_BY_WHITELIST',
      reason: `访问控制拦截：工具 "${bin}" 已开启参数白名单（仅允许参数/目标: ${cleanAllowed.join(', ')}），禁止无参调用`,
    };
  }

  // 提取命令行中的目标对象参数（排除选项开关如 -i, -s 以及带值选项如 -X GET 的紧随值）
  const targetObjects = [];
  for (let i = 0; i < argTokens.length; i += 1) {
    const tok = argTokens[i];
    if (VALUE_TAKING_FLAGS.has(tok)) {
      i += 1; // 跳过该选项紧跟的参数值
      continue;
    }
    if (tok.startsWith('-')) {
      continue; // 常规短/长选项开关
    }
    // 去掉首尾引号
    const unquoted = tok.replace(/^['"]|['"]$/g, '');
    if (unquoted) targetObjects.push(unquoted);
  }

  // 若全是选项开关而没有任何操作对象，直接检查整个 rawArgs 是否在白名单中
  if (targetObjects.length === 0) {
    const matchedRaw = cleanAllowed.some((pat) => matchArgPattern(rawArgs, rawArgs, pat));
    if (!matchedRaw) {
      return {
        allowed: false,
        rule: 'ARG_NOT_IN_WHITELIST',
        reason: `访问控制拦截：工具 "${bin}" 已开启参数白名单，参数 "${rawArgs}" 不在允许列表中（仅允许: ${cleanAllowed.join(', ')}）`,
      };
    }
    return {
      allowed: true,
      rule: 'ARG_WHITELIST_PASS',
      reason: `参数白名单校验通过：工具 "${bin}" 的参数符合白名单规则`,
    };
  }

  // 若第一个位置参数是子命令（如 git status diff），且命中白名单中的纯单词子命令，则放行该子命令
  const firstTarget = targetObjects[0];
  const matchedSubcommand = cleanAllowed.find(
    (pat) => /^[a-z0-9_-]+$/i.test(pat) && firstTarget === pat
  );

  // 检查命令行中出现的所有 URL 目标是否全部在白名单内（防止 curl http://127.0.0.1 http://evil.com 夹带私货）
  const urlMatches = rawArgs.match(/https?:\/\/[^\s'"]+/gi) || [];
  for (const url of urlMatches) {
    const ok = cleanAllowed.some((pat) => matchArgPattern(url, rawArgs, pat));
    if (!ok) {
      return {
        allowed: false,
        rule: 'TARGET_ADDR_NOT_IN_WHITELIST',
        reason: `访问控制拦截：工具 "${bin}" 已开启参数白名单，目标地址 "${url}" 不在白名单中（仅允许: ${cleanAllowed.join(', ')}）`,
      };
    }
  }

  if (matchedSubcommand) {
    return {
      allowed: true,
      rule: 'ARG_WHITELIST_PASS',
      reason: `参数白名单校验通过：工具 "${bin}" 的子命令 "${matchedSubcommand}" 在允许列表中`,
    };
  }

  // 对所有目标对象（如请求地址、文件路径、主机名）逐一校验，必须全部命中该工具的 allowedArgs 白名单
  for (const target of targetObjects) {
    const ok = cleanAllowed.some((pat) => matchArgPattern(target, rawArgs, pat));
    if (!ok) {
      return {
        allowed: false,
        rule: 'ARG_NOT_IN_WHITELIST',
        reason: `访问控制拦截：工具 "${bin}" 已开启参数白名单，目标参数 "${target}" 不在允许列表中（仅允许: ${cleanAllowed.join(', ')}）`,
      };
    }
  }

  return {
    allowed: true,
    rule: 'ARG_WHITELIST_PASS',
    reason: `参数白名单校验通过：工具 "${bin}" 的目标参数 (${targetObjects.join(', ')}) 均在允许列表中`,
  };
}

/**
 * 校验单条命令与参数是否符合访问控制策略
 * @param {string} rawCommand 待执行的命令行字符串
 * @param {object} rawPolicy 当前生效的访问控制策略
 * @returns {{ allowed: boolean, bin: string, rule: string, reason: string }}
 */
export function evaluateCommandAccess(rawCommand, rawPolicy = DEFAULT_ACCESS_POLICY) {
  const policy = normalizeAccessPolicy(rawPolicy);
  const cmdLine = String(rawCommand ?? '').trim();
  if (!cmdLine) {
    return {
      allowed: false,
      bin: '(empty)',
      rule: 'EMPTY_CMD',
      reason: '访问控制拦截：禁止执行空命令',
    };
  }

  const tokens = cmdLine.split(/\s+/);
  const bin = tokens[0].replace(/^.*\//, '');
  const rawArgs = cmdLine.slice(tokens[0].length).trim();

  if (!policy.enabled) {
    return {
      allowed: true,
      bin,
      rule: 'POLICY_DISABLED',
      reason: '访问控制总开关已临时关闭（放行）',
    };
  }

  // 第 1 关：拦截危险的命令拼接、后台执行、命令替换与写盘重定向
  if (policy.blockShellChaining && /[;&|`]|(\$\()|>>?/.test(cmdLine)) {
    return {
      allowed: false,
      bin,
      rule: 'SHELL_CHAINING_BLOCKED',
      reason: `访问控制拦截：参数包含非法的命令拼接、替换或重定向符号 -> "${cmdLine}"`,
    };
  }

  // 第 2 关：检查工具/命令本身是否被允许执行
  const cmdRule = policy.commandRules?.[bin];
  const mode = policy.mode || 'whitelist';

  if (mode === 'blacklist') {
    const blacklist = new Set(policy.blockedCommands || DEFAULT_ACCESS_POLICY.blockedCommands);
    if (blacklist.has(bin) || cmdRule?.allowed === false) {
      return {
        allowed: false,
        bin,
        rule: 'COMMAND_IN_BLACKLIST',
        reason: `访问控制拦截：命令 "${bin}" 已被禁止执行`,
      };
    }
  } else {
    if (!cmdRule || !cmdRule.allowed) {
      const allowedList = Object.entries(policy.commandRules || {})
        .filter(([, r]) => r.allowed)
        .map(([k]) => k);
      return {
        allowed: false,
        bin,
        rule: 'COMMAND_NOT_IN_WHITELIST',
        reason: `访问控制拦截：命令 "${bin}" 不在允许执行的工具白名单中（当前允许: ${allowedList.join(', ')}）`,
      };
    }
  }

  // 第 3 关：敏感系统路径与防自篡改（防止 AI 偷偷修改配置文件或调用控制接口给自己提权）
  for (const protectedItem of DEFAULT_ACCESS_POLICY.protectedConfigPaths) {
    if (cmdLine.includes(protectedItem)) {
      return {
        allowed: false,
        bin,
        rule: 'CONFIG_TAMPER_BLOCKED',
        reason: `访问控制防篡改拦截：严禁智能体访问或修改访问控制插件配置与管理接口 "${protectedItem}"`,
      };
    }
  }

  for (const sensitive of policy.forbiddenPaths || DEFAULT_ACCESS_POLICY.forbiddenPaths) {
    if (cmdLine.includes(sensitive)) {
      return {
        allowed: false,
        bin,
        rule: 'SENSITIVE_PATH_BLOCKED',
        reason: `访问控制拦截：参数试图访问受保护的敏感路径 "${sensitive}"`,
      };
    }
  }

  // 第 4 关：按工具独立判断——是否开启了该工具的参数白名单检查（argWhitelistEnabled）
  // 如果未开启（argWhitelistEnabled: false），则不对该工具后面的参数做白名单限制！
  if (cmdRule && cmdRule.argWhitelistEnabled) {
    const argCheck = checkCommandArgWhitelist(bin, tokens, rawArgs, cmdRule.allowedArgs);
    if (!argCheck.allowed) {
      return {
        allowed: false,
        bin,
        rule: argCheck.rule,
        reason: argCheck.reason,
      };
    }
    return {
      allowed: true,
      bin,
      rule: argCheck.rule,
      reason: argCheck.reason,
    };
  }

  return {
    allowed: true,
    bin,
    rule: 'WHITELIST_PASS',
    reason: `访问控制校验通过：命令 "${bin}" 允许执行（该命令未开启参数白名单限制，参数直接放行）`,
  };
}

export function apply(ctx, config = {}) {
  const runtime = (globalThis.__AEGIS_RUNTIME__ ??= {});
  runtime.accessPolicy = normalizeAccessPolicy(config);
  runtime.accessAuditLog ??= [];
  runtime.evaluateCommandAccess = (cmd) => evaluateCommandAccess(cmd, runtime.accessPolicy);
  runtime.normalizeAccessPolicy = normalizeAccessPolicy;

  const recordAudit = (entry) => {
    const row = {
      id: `AC-${runtime.accessAuditLog.length + 1}`,
      time: new Date().toISOString(),
      ...entry,
    };
    runtime.accessAuditLog.unshift(row);
    if (runtime.accessAuditLog.length > 100) runtime.accessAuditLog.length = 100;

    // 若被拦截且存在 Aegis 状态黑板，自动同步写入一条 R# 门禁拦截记录
    if (row.decision === 'DENY' && runtime.store) {
      try {
        runtime.store.addReview({
          stage: 'ADMISSION',
          taskId: row.taskId || 'ACL',
          targetRef: row.command || row.tool || 'cmd',
          verdict: 'REJECT',
          reason: row.reason,
          evidenceIds: [],
        });
      } catch {}
    }
    return row;
  };
  runtime.recordAccessAudit = recordAudit;

  // 核心挂载点：向 DeepSeek Harness 全局工具服务注册 guard 拦截器
  ctx.tools.guard((exec) => {
    const role = runtime.agentRoles?.get(exec.agent?.id) || 'lead';
    const args = exec.arguments || {};

    // 1. 针对命令行执行工具（bash）进行命令白名单 + 按命令独立开关的参数白名单检查
    if (exec.name === 'bash') {
      const cmdLine = String(args.command ?? '');
      const verdict = evaluateCommandAccess(cmdLine, runtime.accessPolicy);
      recordAudit({
        role,
        tool: 'bash',
        command: cmdLine,
        bin: verdict.bin,
        decision: verdict.allowed ? 'ALLOW' : 'DENY',
        rule: verdict.rule,
        reason: verdict.reason,
      });
      if (!verdict.allowed) {
        return `AEGIS_ACCESS_DENIED [${verdict.rule}]: ${verdict.reason}`;
      }
    }

    // 2. 针对网页抓取工具（web_fetch）按 web_fetch（或回退至 curl）的规则检查是否开启了目标地址白名单
    if (exec.name === 'web_fetch' && args.url) {
      const toolKey = runtime.accessPolicy.commandRules?.web_fetch ? 'web_fetch' : 'curl';
      const verdict = evaluateCommandAccess(`${toolKey} ${args.url}`, runtime.accessPolicy);
      recordAudit({
        role,
        tool: 'web_fetch',
        command: `web_fetch ${args.url}`,
        bin: 'web_fetch',
        decision: verdict.allowed ? 'ALLOW' : 'DENY',
        rule: verdict.rule,
        reason: verdict.reason,
      });
      if (!verdict.allowed) {
        return `AEGIS_ACCESS_DENIED [${verdict.rule}]: ${verdict.reason}`;
      }
    }

    // 3. 针对文件读取工具（read）按 read（或回退至 cat）的规则检查敏感路径与可选的文件路径白名单
    if (exec.name === 'read' && args.file_path) {
      const filePath = String(args.file_path);
      const toolKey = runtime.accessPolicy.commandRules?.read ? 'read' : 'cat';
      const verdict = evaluateCommandAccess(`${toolKey} ${filePath}`, runtime.accessPolicy);
      if (!verdict.allowed) {
        recordAudit({
          role,
          tool: 'read',
          command: `read ${filePath}`,
          bin: 'read',
          decision: 'DENY',
          rule: verdict.rule,
          reason: verdict.reason,
        });
        return `AEGIS_ACCESS_DENIED [${verdict.rule}]: ${verdict.reason}`;
      }
    }

    // 4. 针对文件写入/编辑工具（write / edit）及插件管理工具（plugin_manager）防止 AI 修改配置文件或卸载本插件
    if ((exec.name === 'write' || exec.name === 'edit') && args.file_path) {
      const filePath = String(args.file_path);
      for (const protectedItem of [
        ...DEFAULT_ACCESS_POLICY.protectedConfigPaths,
        ...(runtime.accessPolicy.forbiddenPaths || []),
      ]) {
        if (filePath.includes(protectedItem)) {
          const reason = `访问控制防篡改拦截：严禁智能体通过 ${exec.name} 工具修改受保护的配置文件或插件源码 "${protectedItem}"`;
          recordAudit({
            role,
            tool: exec.name,
            command: `${exec.name} ${filePath}`,
            bin: exec.name,
            decision: 'DENY',
            rule: 'CONFIG_TAMPER_BLOCKED',
            reason,
          });
          return `AEGIS_ACCESS_DENIED [CONFIG_TAMPER_BLOCKED]: ${reason}`;
        }
      }
    }

    if (exec.name === 'plugin_manager') {
      const reason = '访问控制防篡改拦截：严禁智能体自行调用 plugin_manager 禁用或卸载安全插件';
      recordAudit({
        role,
        tool: 'plugin_manager',
        command: `plugin_manager ${JSON.stringify(args)}`,
        bin: 'plugin_manager',
        decision: 'DENY',
        rule: 'CONFIG_TAMPER_BLOCKED',
        reason,
      });
      return `AEGIS_ACCESS_DENIED [CONFIG_TAMPER_BLOCKED]: ${reason}`;
    }

    return undefined;
  });

  // 4. 自带独立 Web/Desktop GUI 后端接口（当运行在 Web 或 Desktop 模式且存在 webServer 服务时自动挂载）
  ctx.inject(['webServer'], (webCtx) => {
    const sendJson = (res, data, status = 200) => {
      res.writeHead(status, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
      });
      res.end(JSON.stringify(data));
    };

    const readJson = async (req) => {
      let body = '';
      for await (const chunk of req) {
        body += chunk;
        if (body.length > 256 * 1024) throw new Error('Body too large');
      }
      return body ? JSON.parse(body) : {};
    };

    webCtx.webServer.register({
      kind: 'prefix',
      path: '/aegis-acl-api',
      handler: async (req, res) => {
        try {
          const parsedUrl = new URL(req.url ?? '/aegis-acl-api/state', 'http://127.0.0.1');
          const subPath = parsedUrl.pathname.replace(/^\/aegis-acl-api/, '') || '/state';

          if (req.method === 'GET' && subPath === '/state') {
            return sendJson(res, {
              ok: true,
              accessPolicy: runtime.accessPolicy,
              accessAuditLog: runtime.accessAuditLog || [],
            });
          }

          if (req.method === 'POST' && subPath === '/action') {
            const body = await readJson(req);
            const action = body.action;

            if (action === 'update_policy') {
              const patch = body.policy || {};
              runtime.accessPolicy = normalizeAccessPolicy({
                ...runtime.accessPolicy,
                ...patch,
                commandRules: {
                  ...(runtime.accessPolicy?.commandRules || {}),
                  ...(patch.commandRules || {}),
                },
              });
              return sendJson(res, { ok: true, accessPolicy: runtime.accessPolicy });
            }

            if (action === 'test_command') {
              const cmd = String(body.command ?? '');
              const verdict = evaluateCommandAccess(cmd, runtime.accessPolicy);
              const row = recordAudit({
                role: 'ui-tester',
                taskId: 'ACL-UI',
                tool: 'bash',
                command: cmd,
                bin: verdict.bin,
                decision: verdict.allowed ? 'ALLOW' : 'DENY',
                rule: verdict.rule,
                reason: verdict.reason,
              });
              return sendJson(res, { ok: true, verdict, auditRecord: row });
            }

            if (action === 'clear_audit') {
              runtime.accessAuditLog = [];
              return sendJson(res, { ok: true });
            }

            return sendJson(res, { ok: false, message: `Unknown action: ${action}` }, 400);
          }

          return sendJson(res, { ok: false, message: 'Not Found' }, 404);
        } catch (err) {
          return sendJson(res, { ok: false, message: err.message }, 500);
        }
      },
    });
  });
}
