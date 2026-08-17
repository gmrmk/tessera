#!/usr/bin/env node
/**
 * Tessera Harden runtime for Claude Code hooks.
 *
 * This file is copied into `.claude/hooks/` by `tessera harden apply`. It uses
 * only Node built-ins, stores no raw command or file content in receipts, and
 * emits only Claude Code's documented JSON decision shapes on stdout.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SCHEMA_VERSION = 2;
const DEFAULT_POLICY = {
  schema_version: SCHEMA_VERSION,
  protected_path_globs: [
    ".env", ".env.*", "**/.env", "**/.env.*", "**/credentials",
    "**/credentials.*", "**/*credential*.json", "**/*secret*.json",
    "**/*.pem", "**/*.key", "**/id_rsa", "**/id_ed25519",
    "**/.aws/credentials", "**/.ssh/*",
  ],
  protected_path_exceptions: [
    ".env.example", ".env.sample", ".env.template",
    "**/.env.example", "**/.env.sample", "**/.env.template",
  ],
  governance_path_globs: [
    "CLAUDE.md", ".claude/CLAUDE.md", ".claude/settings.json",
    ".claude/settings.local.json", ".claude/tessera-policy.json",
    ".claude/hooks/**", ".claude/rules/**", ".mcp.json", "policy/**",
    ".tessera/install-manifest.json", ".tessera/governance-inventory.json",
    ".tessera/rule-to-hook-map.md", ".tessera/verification.json",
    ".tessera/receipts/**", ".tessera/backups/**",
  ],
  production_markers: [
    "production", "--prod", "--environment prod", "--environment=prod",
    "-e prod", "namespace/prod", "context prod",
  ],
  test_command_patterns: [
    "pytest", "python -m pytest", "npm test", "npm run test", "pnpm test",
    "yarn test", "bun test", "cargo test", "go test", "dotnet test",
    "mvn test", "gradle test", "./gradlew test",
  ],
  max_test_reminders: 2,
  receipt_path: ".tessera/receipts/hooks.jsonl",
  verification_receipt_path: ".tessera/receipts/verification-hooks.jsonl",
  state_dir: ".tessera/state",
};

const SECRET_PATTERNS = [
  ["Anthropic key", /\bsk-ant-[A-Za-z0-9_-]{20,}\b/],
  ["OpenAI key", /\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b/],
  ["AWS access key id", /\bAKIA[0-9A-Z]{16}\b/],
  ["GitHub token", /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ["Slack token", /\bxox[bpars]-[A-Za-z0-9-]{10,}\b/],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/],
  ["private key block", /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/],
  ["credential-bearing URL", /\bhttps?:\/\/[^/\s:@]+:[^/\s@]+@/],
];
const ASSIGNMENT_PATTERN = /\b(secret|token|passwd|password|api[_-]?key|access[_-]?key|client[_-]?secret)\s*[:=]\s*['"]([^'"]{12,})['"]/i;
const BENIGN_ASSIGNMENT = /^(?:example|sample|test|testing|dummy|placeholder|changeme|replace[_-]?me|your[_-].*|<.*>|\$\{.*\})$/i;

const DESTRUCTIVE_PATTERNS = [
  ["git reset --hard", /\bgit\s+reset\s+--hard\b/i],
  ["git clean force", /\bgit\s+clean\b[^;&\n]*(?:-[A-Za-z]*f[A-Za-z]*|--force)\b/i],
  ["git branch force-delete", /\bgit\s+branch\s+-D\b/],
  ["unleased force push", /\bgit\s+push\b[^;&\n]*(?:--force(?!-with-lease)\b|\s-f\b)/i],
  ["recursive forced rm", /\brm\b(?=[^;&\n]*(?:-[A-Za-z]*r|--recursive))(?=[^;&\n]*(?:-[A-Za-z]*f|--force))[^;&\n]*/i],
  ["PowerShell recursive forced delete", /\bRemove-Item\b[^\n]*(?=-[^\n]*Recurse)(?=-[^\n]*Force)/i],
  ["Windows recursive quiet delete", /\b(?:del|rmdir|rd)\b[^\n]*(?:\/s[^\n]*\/q|\/q[^\n]*\/s)/i],
  ["SQL destructive DDL", /\b(?:DROP|TRUNCATE)\s+(?:TABLE|DATABASE|SCHEMA)\b/i],
  ["Terraform destroy", /\bterraform\s+destroy\b/i],
  ["Kubernetes namespace deletion", /\bkubectl\s+delete\s+(?:namespace|ns)\b/i],
  ["recursive S3 deletion", /\baws\s+s3\s+rm\b[^\n]*--recursive\b/i],
  ["Docker system prune", /\bdocker\s+system\s+prune\b[^\n]*(?:--force|-f)\b/i],
];
const PRODUCTION_MUTATION = /\b(deploy|release|terraform\s+apply|pulumi\s+up|kubectl\s+(?:apply|delete|patch|replace|scale)|helm\s+(?:upgrade|install|uninstall)|aws\s+(?:cloudformation|ecs|lambda|rds)|gcloud\s+(?:deploy|run)|az\s+(?:deployment|webapp|functionapp))\b/i;
const WRITEISH_SHELL = /(?:^|[;&|]\s*)(?:rm|mv|cp|install|touch|mkdir|tee|sed\s+-i|perl\s+-pi|python(?:3)?\s+-c|powershell|pwsh|Set-Content|Add-Content|Out-File|Remove-Item|Move-Item|Copy-Item)\b|(?:>>?|2>)/i;
const ABSOLUTE_CLAIM = /\b(100%|fully (?:sanitized|clean|fixed|removed|gone)|all (?:clean|gone|removed|fixed|sanitized|purged)|nothing (?:personal|left|remains)|no\s+pii(?: anywhere)?|zero pii|guaranteed|definitely (?:safe|clean|gone|removed)|verified safe|totally clean|completely (?:fixed|safe|clean|removed|purged)|never fails|cannot fail|fully resolved)\b/i;
const PROOF_SIGNAL = /\b(grep|verified by|exit 0|exit code|returns? (?:empty|zero|0|404|none|nothing)|re-?checked|second signal|tested|test output|harness|confirmed by|sha-?256|content-?match|all green)\b/i;

const DIRECT_PATH_KEYS = ["file_path", "path", "notebook_path"];
const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);
const READ_TOOLS = new Set(["Read", "NotebookRead"]);
const SHELL_TOOLS = new Set(["Bash", "PowerShell"]);

function nowIso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function projectRoot(payload) {
  return path.resolve(String(process.env.CLAUDE_PROJECT_DIR || payload.cwd || process.cwd()));
}

function loadPolicy(root) {
  const file = path.join(root, ".claude", "tessera-policy.json");
  let loaded = {};
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) loaded = parsed;
  } catch { /* defaults are intentionally fail-safe */ }
  const merged = { ...DEFAULT_POLICY };
  for (const key of Object.keys(DEFAULT_POLICY)) {
    if (Object.prototype.hasOwnProperty.call(loaded, key)) merged[key] = loaded[key];
  }
  return merged;
}

function expandEnvironment(value) {
  let text = String(value);
  if (text === "~" || text.startsWith("~/") || text.startsWith("~\\")) {
    text = path.join(os.homedir(), text.slice(2));
  }
  return text
    .replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%/g,
      (_m, a, b, c) => process.env[a || b || c] || "");
}

function normalizePath(raw, root) {
  const expanded = expandEnvironment(raw);
  const candidate = path.isAbsolute(expanded) ? expanded : path.join(root, expanded);
  let resolved;
  try {
    resolved = fs.realpathSync.native(candidate);
  } catch {
    try {
      resolved = path.join(fs.realpathSync.native(path.dirname(candidate)), path.basename(candidate));
    } catch {
      resolved = path.resolve(candidate);
    }
  }
  const rel = path.relative(root, resolved);
  const inside = rel === "" || (!rel.startsWith(`..${path.sep}`) && rel !== ".." && !path.isAbsolute(rel));
  return (inside ? rel || "." : resolved).replaceAll("\\", "/");
}

function globRegex(pattern) {
  const p = String(pattern).replaceAll("\\", "/").replace(/^\.\//, "").toLowerCase();
  let out = "^";
  for (let i = 0; i < p.length; i += 1) {
    const ch = p[i];
    if (ch === "*" && p[i + 1] === "*") {
      if (p[i + 2] === "/") { out += "(?:.*/)?"; i += 2; }
      else { out += ".*"; i += 1; }
    } else if (ch === "*") out += "[^/]*";
    else if (ch === "?") out += "[^/]";
    else out += ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`${out}$`, "i");
}

function matchesAny(filePath, patterns) {
  const normalized = String(filePath).replaceAll("\\", "/").replace(/^\.\//, "").toLowerCase();
  const basename = normalized.split("/").at(-1) || normalized;
  return (Array.isArray(patterns) ? patterns : []).some((pattern) => {
    const regex = globRegex(pattern);
    return regex.test(normalized) || regex.test(basename);
  });
}

function protectedPath(filePath, policy) {
  if (matchesAny(filePath, policy.protected_path_exceptions)) return false;
  return matchesAny(filePath, policy.protected_path_globs);
}

function governancePath(filePath, policy) {
  return matchesAny(filePath, policy.governance_path_globs);
}

function directPaths(toolInput) {
  const paths = [];
  for (const key of DIRECT_PATH_KEYS) {
    if (typeof toolInput[key] === "string" && toolInput[key]) paths.push(toolInput[key]);
  }
  if (Array.isArray(toolInput.edits)) {
    for (const edit of toolInput.edits) {
      if (!edit || typeof edit !== "object") continue;
      for (const key of DIRECT_PATH_KEYS) {
        if (typeof edit[key] === "string" && edit[key]) paths.push(edit[key]);
      }
    }
  }
  return paths;
}

function introducedText(toolInput) {
  const parts = [];
  for (const key of ["content", "new_string", "new_source", "command", "cell", "source"]) {
    if (typeof toolInput[key] === "string") parts.push(toolInput[key]);
  }
  if (Array.isArray(toolInput.edits)) {
    for (const edit of toolInput.edits) {
      if (!edit || typeof edit !== "object") continue;
      for (const key of ["content", "new_string", "new_source"]) {
        if (typeof edit[key] === "string") parts.push(edit[key]);
      }
    }
  }
  return parts.join("\n");
}

function secretHit(text) {
  for (const [label, regex] of SECRET_PATTERNS) {
    const match = text.match(regex);
    if (match) return [label, match[0].length];
  }
  const assignment = text.match(ASSIGNMENT_PATTERN);
  if (assignment && !BENIGN_ASSIGNMENT.test(assignment[2].trim())) {
    return ["hardcoded credential assignment", assignment[2].trim().length];
  }
  return null;
}

function shellTokens(command) {
  const matches = String(command).match(/"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s;&|()<>]+/g) || [];
  return matches.map((token) => token.replace(/^["'`,]+|["'`,;|()\[\]{}<>]+$/g, "")).filter(Boolean);
}

function shellPaths(command, root) {
  const found = [];
  for (const token of shellTokens(command)) {
    if (/^https?:\/\//i.test(token) || token.startsWith("-")) continue;
    if (/[\\/]/.test(token) || token.startsWith(".") || /\.(?:env|pem|key|json|ya?ml|toml|md)$/i.test(token)) {
      found.push(normalizePath(token, root));
    }
  }
  const embedded = /(CLAUDE\.md|\.mcp\.json|\.env(?:\.[A-Za-z0-9_.-]+)?|\.claude[\\/][A-Za-z0-9_./\\-]+|\.tessera[\\/][A-Za-z0-9_./\\-]+|policy[\\/][A-Za-z0-9_./\\-]+)/gi;
  for (const match of String(command).matchAll(embedded)) {
    found.push(normalizePath(match[1].replace(/[.,:;\])}]+$/, ""), root));
  }
  return [...new Set(found)];
}

function deobfuscateCommand(command) {
  return String(command)
    .replace(/["'`]/g, "")
    .replace(/\\(?=[A-Za-z])/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function productionMarked(command, policy) {
  const lower = String(command).toLowerCase();
  return (Array.isArray(policy.production_markers) ? policy.production_markers : [])
    .some((marker) => String(marker).trim() && lower.includes(String(marker).toLowerCase()));
}

function testCommand(command, policy) {
  const normalized = deobfuscateCommand(command).toLowerCase();
  return (Array.isArray(policy.test_command_patterns) ? policy.test_command_patterns : [])
    .some((pattern) => normalized.includes(String(pattern).toLowerCase()));
}

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value), "utf8");
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function atomicJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = `${file}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  try {
    fs.writeFileSync(temp, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    try {
      fs.renameSync(temp, file);
    } catch (error) {
      // Windows does not consistently replace an existing destination with rename.
      if (!error || !["EEXIST", "EPERM", "EACCES"].includes(error.code)) throw error;
      fs.rmSync(file, { force: true });
      fs.renameSync(temp, file);
    }
  } finally {
    try { fs.rmSync(temp, { force: true }); } catch { /* best effort */ }
  }
}

function localProjectPath(root, configured, fallback) {
  const selected = typeof configured === "string" && configured ? configured : fallback;
  const candidate = path.resolve(root, selected);
  const rel = path.relative(root, candidate);
  const inside = rel === "" || (!rel.startsWith(`..${path.sep}`) && rel !== ".." && !path.isAbsolute(rel));
  if (inside) return candidate;
  return fallback ? path.resolve(root, fallback) : null;
}

function sessionStatePath(root, policy, payload) {
  const raw = String(payload.session_id || "unknown");
  const safe = raw.replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 120) || "unknown";
  const stateDir = localProjectPath(root, policy.state_dir, DEFAULT_POLICY.state_dir);
  return path.join(stateDir, `${safe}.json`);
}

function readState(root, policy, payload) {
  try {
    const parsed = JSON.parse(fs.readFileSync(sessionStatePath(root, policy, payload), "utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch { return {}; }
}

function writeState(root, policy, payload, state) {
  try { atomicJson(sessionStatePath(root, policy, payload), state); } catch { /* evidence is best effort */ }
}

function receipt(root, policy, payload, decision, ruleId, details = {}) {
  const verification = process.env.TESSERA_HARDEN_VERIFICATION === "1";
  const configured = verification ? policy.verification_receipt_path : policy.receipt_path;
  const fallback = verification ? DEFAULT_POLICY.verification_receipt_path : DEFAULT_POLICY.receipt_path;
  const file = localProjectPath(root, configured, fallback);
  if (!file) return;
  const record = {
    schema_version: SCHEMA_VERSION,
    at: nowIso(),
    mode: verification ? "verification" : "operational",
    event: payload.hook_event_name || null,
    tool: payload.tool_name || null,
    decision,
    rule_id: ruleId,
    session_sha256: sha256(String(payload.session_id || "unknown")),
    input_sha256: sha256(stable(payload)),
    ...details,
  };
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600 });
  } catch { /* never change enforcement because receipt storage failed */ }
}

function preToolDecision(root, policy, payload, decision, ruleId, reason) {
  receipt(root, policy, payload, decision, ruleId);
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision,
      permissionDecisionReason: `[${ruleId}] ${reason}`,
    },
  };
}

function evaluatePreTool(payload, root, policy) {
  const tool = String(payload.tool_name || "");
  const toolInput = payload.tool_input && typeof payload.tool_input === "object" ? payload.tool_input : {};
  const text = introducedText(toolInput);
  const secret = secretHit(text);
  if (secret) {
    const [label, length] = secret;
    return preToolDecision(root, policy, payload, "deny", "TESSERA-SEC-001",
      `High-confidence ${label} detected (${length} characters; value withheld). Remove it or use an environment variable or secret manager.`);
  }

  const direct = directPaths(toolInput).map((value) => normalizePath(value, root));
  if (READ_TOOLS.has(tool) || WRITE_TOOLS.has(tool)) {
    const protectedFile = direct.find((file) => protectedPath(file, policy));
    if (protectedFile) {
      return preToolDecision(root, policy, payload, "deny", "TESSERA-SEC-001",
        `Access to protected secret path '${protectedFile}' is blocked. Use a sanitized example or an approved secret workflow.`);
    }
  }
  if (WRITE_TOOLS.has(tool)) {
    const governanceFile = direct.find((file) => governancePath(file, policy));
    if (governanceFile) {
      return preToolDecision(root, policy, payload, "ask", "TESSERA-GOV-001",
        `This modifies the enforcement surface at '${governanceFile}'. Review the exact change and approve it explicitly.`);
    }
  }

  if (!SHELL_TOOLS.has(tool)) return null;
  const command = String(toolInput.command || "");
  if (!command) return null;
  const normalizedCommand = deobfuscateCommand(command);
  for (const [label, regex] of DESTRUCTIVE_PATTERNS) {
    if (regex.test(normalizedCommand)) {
      return preToolDecision(root, policy, payload, "deny", "TESSERA-DESTRUCTIVE-001",
        `Catastrophic operation blocked: ${label}. Use a reversible, scoped alternative with an independently verified backup or rollback path.`);
    }
  }

  const paths = shellPaths(command, root);
  const protectedFile = paths.find((file) => protectedPath(file, policy));
  if (protectedFile) {
    return preToolDecision(root, policy, payload, "deny", "TESSERA-SEC-001",
      `Shell access to protected secret path '${protectedFile}' is blocked. Use a sanitized example or an approved secret workflow.`);
  }
  if (WRITEISH_SHELL.test(normalizedCommand)) {
    const governanceFile = paths.find((file) => governancePath(file, policy));
    if (governanceFile) {
      return preToolDecision(root, policy, payload, "ask", "TESSERA-GOV-001",
        `This shell command may modify the enforcement surface at '${governanceFile}'. Review and approve it explicitly.`);
    }
  }
  if (PRODUCTION_MUTATION.test(normalizedCommand) && productionMarked(normalizedCommand, policy)) {
    return preToolDecision(root, policy, payload, "ask", "TESSERA-PROD-001",
      "Likely production mutation detected. Confirm target, change window, rollback path, and accountable approver before continuing.");
  }
  const claim = normalizedCommand.match(ABSOLUTE_CLAIM);
  if (/\bgit\s+commit\b/i.test(normalizedCommand) && claim && !PROOF_SIGNAL.test(normalizedCommand)) {
    return preToolDecision(root, policy, payload, "ask", "TESSERA-CLOSURE-001",
      `Commit message makes an absolute claim ('${claim[0]}') without naming an independent proving signal. Qualify it or cite the test or check receipt.`);
  }
  return null;
}

function observePostTool(payload, root, policy) {
  const tool = String(payload.tool_name || "");
  const toolInput = payload.tool_input && typeof payload.tool_input === "object" ? payload.tool_input : {};
  const state = readState(root, policy, payload);
  const at = Date.now();
  if (WRITE_TOOLS.has(tool)) {
    state.changed_at_ms = at;
    state.changed_count = Number(state.changed_count || 0) + 1;
    state.stop_reminders = 0;
    const paths = directPaths(toolInput).map((value) => normalizePath(value, root)).sort();
    state.changed_paths_sha256 = sha256(paths.join("\n"));
    receipt(root, policy, payload, "observe", "TESSERA-TEST-001", { observation: "successful_write" });
  } else if (SHELL_TOOLS.has(tool) && testCommand(String(toolInput.command || ""), policy)) {
    state.test_at_ms = at;
    state.test_command_sha256 = sha256(String(toolInput.command || ""));
    state.stop_reminders = 0;
    receipt(root, policy, payload, "observe", "TESSERA-TEST-001", { observation: "successful_test_command" });
  }
  if (state.changed_at_ms || state.test_at_ms) writeState(root, policy, payload, state);
  return null;
}

function evaluateStop(payload, root, policy) {
  if (Array.isArray(payload.background_tasks) && payload.background_tasks.length) return null;
  const state = readState(root, policy, payload);
  const changed = Number(state.changed_at_ms || 0);
  const tested = Number(state.test_at_ms || 0);
  if (!changed || tested >= changed) return null;

  const max = Math.max(0, Number(policy.max_test_reminders ?? 2));
  const reminders = Number(state.stop_reminders || 0);
  if (reminders < max) {
    state.stop_reminders = reminders + 1;
    writeState(root, policy, payload, state);
    receipt(root, policy, payload, "warn", "TESSERA-TEST-001", { reminder: state.stop_reminders });
    return {
      hookSpecificOutput: {
        hookEventName: "Stop",
        additionalContext: "[TESSERA-TEST-001] Files changed after the last successful test command. Run the relevant tests, inspect the result, and then finish. This is a reminder, not proof that a generic test suite is sufficient.",
      },
    };
  }
  receipt(root, policy, payload, "warn-allow", "TESSERA-TEST-001", { reminders_exhausted: reminders });
  return {
    systemMessage: "[TESSERA-TEST-001] Tessera warning: this session changed files after its last observed successful test command. The warning limit was reached, so the turn is ending without claiming enforcement.",
  };
}

function observeConfigChange(payload, root, policy) {
  const file = typeof payload.file_path === "string" ? normalizePath(payload.file_path, root) : null;
  receipt(root, policy, payload, "observe", "TESSERA-DRIFT-001", {
    source: payload.source || null,
    path_sha256: file ? sha256(file) : null,
  });
  return null;
}

function installationDrift(root) {
  const manifestFile = path.join(root, ".tessera", "install-manifest.json");
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(manifestFile, "utf8")); } catch { return []; }
  if (!manifest || !Array.isArray(manifest.actions)) return [];
  const drift = [];
  for (const action of manifest.actions) {
    if (!action || !["create", "update"].includes(action.action)) continue;
    const rel = String(action.path || "");
    if (!rel || rel === ".claude/settings.json") continue; // settings may legitimately gain unrelated hooks
    const installed = localProjectPath(root, rel, null);
    if (!installed) {
      drift.push(`invalid-path:${sha256(rel).slice(0, 12)}`);
      continue;
    }
    let current = null;
    try { current = sha256(fs.readFileSync(installed)); } catch { current = null; }
    if (current !== (action.after_sha256 || null)) drift.push(rel);
  }
  return drift;
}

function evaluateSessionStart(payload, root, policy) {
  const drift = installationDrift(root);
  if (!drift.length) return null;
  receipt(root, policy, payload, "warn", "TESSERA-DRIFT-001", {
    drift_count: drift.length,
    drift_paths_sha256: sha256(drift.sort().join("\n")),
  });
  return {
    hookSpecificOutput: {
      hookEventName: "SessionStart",
      additionalContext: `[TESSERA-DRIFT-001] Tessera detected ${drift.length} installed hardening artifact(s) whose current hash differs from the install manifest. Run \`tessera harden audit\` and \`tessera harden verify\` before relying on the controls.`,
    },
  };
}

function evaluate(payload) {
  const root = projectRoot(payload);
  const policy = loadPolicy(root);
  switch (payload.hook_event_name) {
    case "PreToolUse": return evaluatePreTool(payload, root, policy);
    case "PostToolUse": return observePostTool(payload, root, policy);
    case "Stop": return evaluateStop(payload, root, policy);
    case "ConfigChange": return observeConfigChange(payload, root, policy);
    case "SessionStart": return evaluateSessionStart(payload, root, policy);
    default: return null;
  }
}

let raw = "";
for await (const chunk of process.stdin) raw += chunk;
let payload = {};
try {
  payload = JSON.parse(raw.replace(/^\uFEFF/, "").trim() || "{}");
} catch {
  process.exit(0);
}
if (!payload || typeof payload !== "object" || Array.isArray(payload)) process.exit(0);
const result = evaluate(payload);
if (result) process.stdout.write(`${JSON.stringify(result)}\n`);
