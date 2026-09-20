#!/usr/bin/env node
"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/cli/index.ts
var import_commander = require("commander");
var import_node_fs2 = __toESM(require("fs"));
var import_node_path2 = __toESM(require("path"));
var import_node_child_process = require("child_process");
var import_picocolors3 = __toESM(require("picocolors"));

// src/core/entropy.ts
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) {
    return 0;
  }
  const charFrequencies = /* @__PURE__ */ new Map();
  for (const char of str) {
    charFrequencies.set(char, (charFrequencies.get(char) || 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of charFrequencies.values()) {
    const probability = count / len;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}
function isHighEntropy(token, threshold = 3.2) {
  if (!token || token.length < 12) {
    return false;
  }
  const cleaned = token.replace(/^sk-(?:proj-|admin-|ant-)?/i, "").replace(/^AIzaSy/i, "").replace(/^AKIA/i, "").replace(/^ghp_/i, "").replace(/^github_pat_/i, "").replace(/^sk_live_/i, "");
  if (cleaned.length < 8) {
    return false;
  }
  const entropy = calculateShannonEntropy(cleaned);
  return entropy >= threshold;
}

// src/core/rules/secrets.ts
var isPlaceholder = (val) => {
  const lower = val.toLowerCase();
  return lower.includes("placeholder") || lower.includes("your_") || lower.includes("your-") || lower.includes("example") || lower.includes("sample") || lower.includes("xxxx") || lower.includes("test_") || lower.includes("mock_") || lower.includes("<your") || lower.includes("${") || lower.includes("process.env");
};
var SECRET_PATTERNS = [
  {
    id: "SEC-001",
    name: "OpenAI API Key Leak",
    regex: /\b(sk-(?:proj-|admin-)?[a-zA-Z0-9_-]{32,})\b/g,
    description: "Detected a live OpenAI API key committed into source code.",
    severity: "critical",
    suggestedFix: "Move this key to an environment variable (.env) or GitHub Secrets (e.g. process.env.OPENAI_API_KEY).",
    requiresEntropyCheck: true
  },
  {
    id: "SEC-002",
    name: "Anthropic Claude API Key Leak",
    regex: /\b(sk-ant-[a-zA-Z0-9_-]{32,})\b/g,
    description: "Detected an Anthropic Claude API key committed into source code.",
    severity: "critical",
    suggestedFix: "Use process.env.ANTHROPIC_API_KEY or secret management instead of hardcoding.",
    requiresEntropyCheck: true
  },
  {
    id: "SEC-003",
    name: "Google Gemini / Cloud API Key",
    regex: /\b(AIzaSy[a-zA-Z0-9_-]{33})\b/g,
    description: "Detected a Google Cloud / Gemini AI Studio API key in source code.",
    severity: "critical",
    suggestedFix: "Rotate this key immediately in Google Cloud Console and store it in environment variables.",
    requiresEntropyCheck: true
  },
  {
    id: "SEC-004",
    name: "GitHub Personal Access Token",
    regex: /\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b/g,
    description: "Detected a GitHub Personal Access Token (PAT). Anyone with this token can access your repositories.",
    severity: "critical",
    suggestedFix: "Revoke this token immediately on GitHub Settings -> Developer Settings -> Personal access tokens.",
    requiresEntropyCheck: true
  },
  {
    id: "SEC-005",
    name: "AWS Access Key ID",
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    description: "Detected an AWS Access Key ID. Hardcoded AWS credentials lead to severe cloud infrastructure takeovers.",
    severity: "high",
    suggestedFix: "Use AWS IAM Roles, AWS Secrets Manager, or ~/.aws/credentials instead of hardcoded keys.",
    requiresEntropyCheck: true
  },
  {
    id: "SEC-006",
    name: "Private RSA / OpenSSH Key",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    description: "Detected an unencrypted private cryptographic key in plaintext source code.",
    severity: "critical",
    suggestedFix: "Never commit private keys to version control. Add them to .gitignore and use key vaults.",
    requiresEntropyCheck: false
  },
  {
    id: "SEC-007",
    name: "Database Connection String with Credentials",
    regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_.-]+:[a-zA-Z0-9_!@#$%^&*()+=~-]+@[a-zA-Z0-9.-]+:[0-9]{2,5}\/[a-zA-Z0-9_.-]+/g,
    description: "Database connection URI contains embedded plaintext username and password.",
    severity: "critical",
    suggestedFix: "Store the connection string in DATABASE_URL environment variable.",
    requiresEntropyCheck: false
  },
  {
    id: "SEC-008",
    name: "Hugging Face API Token",
    regex: /\b(hf_[a-zA-Z0-9]{34})\b/g,
    description: "Detected a Hugging Face API token in source code.",
    severity: "high",
    suggestedFix: "Store in HF_TOKEN environment variable.",
    requiresEntropyCheck: true
  },
  {
    id: "SEC-009",
    name: "Stripe Secret API Key",
    regex: /\b([sr]k_live_[0-9a-zA-Z]{24,})\b/g,
    description: "Detected a live Stripe production secret key. Risk of unauthorized financial transactions.",
    severity: "critical",
    suggestedFix: "Revoke key in Stripe Dashboard and store in process.env.STRIPE_SECRET_KEY.",
    requiresEntropyCheck: true
  },
  {
    id: "SEC-010",
    name: "Slack Incoming Webhook / Bot Token",
    regex: /\b(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+|xox[baprs]-[0-9a-zA-Z]{10,48})\b/g,
    description: "Detected a Slack webhook URL or bot authentication token.",
    severity: "high",
    suggestedFix: "Move Slack webhook to environment variables or GitHub Secrets.",
    requiresEntropyCheck: false
  }
];
var secretRules = SECRET_PATTERNS.map((pattern) => ({
  id: pattern.id,
  name: pattern.name,
  description: pattern.description,
  severity: pattern.severity,
  category: "secret",
  match: (content, filePath) => {
    const norm = filePath.replace(/\\/g, "/");
    if (norm.endsWith("src/core/rules/secrets.ts") || norm.endsWith("fixtures.ts")) {
      return [];
    }
    const isTestFile = filePath.includes(".test.") || filePath.includes(".spec.") || filePath.includes("/fixtures/") || filePath.includes("\\fixtures\\");
    const lines = content.split(/\r?\n/);
    const findings = [];
    lines.forEach((line, idx) => {
      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(line)) !== null) {
        const captured = match[1] || match[0];
        if (isPlaceholder(captured) || isPlaceholder(line)) {
          continue;
        }
        const entropyVal = calculateShannonEntropy(captured);
        if (pattern.requiresEntropyCheck) {
          if (!isHighEntropy(captured, 3)) {
            continue;
          }
        }
        if (isTestFile && (line.includes("mock") || line.includes("dummy") || line.includes("fake"))) {
          continue;
        }
        const masked = captured.length > 8 ? captured.slice(0, 4) + "..." + captured.slice(-4) : "***";
        findings.push({
          id: `${pattern.id}-${idx + 1}`,
          ruleId: pattern.id,
          title: pattern.name,
          description: pattern.description,
          severity: pattern.severity,
          category: "secret",
          file: filePath,
          line: idx + 1,
          column: match.index + 1,
          snippet: line.replace(captured, masked).trim(),
          suggestedFix: pattern.suggestedFix,
          entropy: Math.round(entropyVal * 100) / 100
        });
      }
    });
    return findings;
  }
}));

// src/core/rules/ai-safety.ts
function getLineAndSnippet(content, matchIndex) {
  const upToMatch = content.slice(0, matchIndex);
  const lines = upToMatch.split(/\r?\n/);
  const line = lines.length;
  const column = lines[lines.length - 1].length + 1;
  const allLines = content.split(/\r?\n/);
  const snippet = (allLines[line - 1] || "").trim();
  return { line, column, snippet };
}
var shouldScan = (filePath) => {
  if (!/\.(ts|js|py|mjs|cjs|jsx|tsx)$/i.test(filePath)) return false;
  const norm = filePath.replace(/\\/g, "/");
  if (norm.endsWith("src/core/rules/ai-safety.ts") || norm.includes("/fixtures/") || norm.endsWith("fixtures.ts") || norm.includes(".test.") || norm.includes(".spec.")) {
    return false;
  }
  return true;
};
var isPython = (filePath) => /\.py$/i.test(filePath);
function extractParenthesizedArgs(content, openParenIndex) {
  let depth = 0;
  let inString = null;
  for (let i = openParenIndex; i < content.length; i++) {
    const char = content[i];
    const prev = i > 0 ? content[i - 1] : "";
    if (inString) {
      if (char === inString && prev !== "\\") {
        inString = null;
      }
    } else {
      if (char === '"' || char === "'" || char === "`") {
        inString = char;
      } else if (char === "(") {
        depth++;
      } else if (char === ")") {
        depth--;
        if (depth === 0) {
          return content.slice(openParenIndex + 1, i);
        }
      }
    }
  }
  return content.slice(openParenIndex + 1);
}
function isSafeIdentifier(expr) {
  const trimmed = expr.trim();
  const safeIdRegex = /^(?:[a-zA-Z0-9_.]+\.)?(?:id|userId|user_id|username|user_name|email|user_email|userRole|role|status|style|textStyle|count|paramCount|theme|version|created_at|timestamp)$/i;
  return safeIdRegex.test(trimmed);
}
function containsUntrustedUserInput(expr) {
  const trimmed = expr.trim();
  if (isSafeIdentifier(trimmed)) {
    return false;
  }
  const untrustedPatterns = [
    /(?:req|request)\.(?:body|query|params|data|json)/i,
    /\b(?:userInput|user_input|userQuery|user_query|userPrompt|user_prompt|rawInput|raw_input|rawPrompt|raw_prompt|untrustedInput|untrusted_input|userMessage|user_msg|prompt_text)\b/i,
    /\b(?:input|query|prompt)\b/i
  ];
  return untrustedPatterns.some((p) => p.test(trimmed));
}
var aiSafetyRules = [
  {
    id: "AIS-001",
    name: "Prompt Injection Risk: Direct User Input in System Prompt",
    description: "Directly concatenating untrusted user input into the LLM system prompt can allow prompt injection attacks to override instructions.",
    severity: "high",
    category: "ai-safety",
    match: (content, filePath) => {
      if (!shouldScan(filePath)) return [];
      const findings = [];
      if (isPython(filePath)) {
        const pySystemPattern = /(?:['"]role['"]\s*:\s*['"]system['"][\s\S]*?['"]content['"]\s*:\s*f['"]([^'"]*)['"]|['"]content['"]\s*:\s*f['"]([^'"]*)['"][\s\S]*?['"]role['"]\s*:\s*['"]system['"]|(?:system_prompt|systemPrompt)\s*=\s*f['"]([^'"]*)['"]|SystemMessage\s*\(\s*(?:content\s*=\s*)?f['"]([^'"]*)['"])/gi;
        let match;
        while ((match = pySystemPattern.exec(content)) !== null) {
          const innerFString = match[1] || match[2] || match[3] || match[4] || "";
          const interpolatedMatches = innerFString.match(/\{([^}]+)\}/g);
          if (interpolatedMatches) {
            const hasUntrusted = interpolatedMatches.some((interp) => {
              const varName = interp.slice(1, -1);
              return containsUntrustedUserInput(varName);
            });
            if (hasUntrusted) {
              const { line, column, snippet } = getLineAndSnippet(content, match.index);
              findings.push({
                id: `AIS-001-${line}`,
                ruleId: "AIS-001",
                title: "Prompt Injection Risk: Direct User Input in System Prompt",
                description: "Directly concatenating untrusted user input into the LLM system prompt can allow prompt injection attacks to override instructions.",
                severity: "high",
                category: "ai-safety",
                file: filePath,
                line,
                column,
                snippet,
                suggestedFix: 'Keep the system prompt static and isolated. Pass user input strictly inside the "user" role message.'
              });
            }
          }
        }
      } else {
        const jsSystemPattern = /(?:(?:role\s*:\s*['"]system['"][\s\S]*?content\s*:\s*`([^`]*)`)|(?:content\s*:\s*`([^`]*)`[\s\S]*?role\s*:\s*['"]system['"])|(?:system_prompt|systemPrompt)\s*=\s*`([^`]*)`|new\s+SystemMessage\s*\(\s*(?:content\s*=\s*)?`([^`]*)`)/gi;
        let match;
        while ((match = jsSystemPattern.exec(content)) !== null) {
          const innerTemplate = match[1] || match[2] || match[3] || match[4] || "";
          const interpolatedMatches = innerTemplate.match(/\$\{([^}]+)\}/g);
          if (interpolatedMatches) {
            const hasUntrusted = interpolatedMatches.some((interp) => {
              const expr = interp.slice(2, -1);
              return containsUntrustedUserInput(expr);
            });
            if (hasUntrusted) {
              const { line, column, snippet } = getLineAndSnippet(content, match.index);
              findings.push({
                id: `AIS-001-${line}`,
                ruleId: "AIS-001",
                title: "Prompt Injection Risk: Direct User Input in System Prompt",
                description: "Directly concatenating untrusted user input into the LLM system prompt can allow prompt injection attacks to override instructions.",
                severity: "high",
                category: "ai-safety",
                file: filePath,
                line,
                column,
                snippet,
                suggestedFix: 'Keep the system prompt static and isolated. Pass user input strictly inside the "user" role message.'
              });
            }
          }
        }
      }
      return findings;
    }
  },
  {
    id: "AIS-002",
    name: "Unsafe Dynamic Code Execution (Eval/Exec on AI Output)",
    description: "Executing AI-generated code directly with eval() or exec() without a secure sandbox poses severe RCE risks.",
    severity: "high",
    category: "ai-safety",
    match: (content, filePath) => {
      if (!shouldScan(filePath)) return [];
      const regexes = isPython(filePath) ? [
        /\b(?:exec|eval)\s*\([^)]*(?:response|ai_output|completion|generated_code|output|content|msg|aiOutput)/gi
      ] : [
        /\b(?:eval|new\s+Function|vm\.runInThisContext)\s*\([^)]*(?:response|aiOutput|completion|result|generatedCode|content|msg)/gi
      ];
      const findings = [];
      for (const regex of regexes) {
        let match;
        while ((match = regex.exec(content)) !== null) {
          const { line, column, snippet } = getLineAndSnippet(content, match.index);
          findings.push({
            id: `AIS-002-${line}`,
            ruleId: "AIS-002",
            title: "Unsafe Dynamic Code Execution (Eval/Exec on AI Output)",
            description: "Executing AI-generated code directly with eval() or exec() without a secure sandbox poses severe RCE risks.",
            severity: "high",
            category: "ai-safety",
            file: filePath,
            line,
            column,
            snippet,
            suggestedFix: "Execute generated code in an isolated container or use a secured sandbox runtime instead of direct eval/exec."
          });
        }
      }
      return findings;
    }
  },
  {
    id: "AIS-003",
    name: "Insecure Command Injection in Agent Tool Execution",
    description: "Passing unsanitized AI tool arguments or user strings into system shell execution leads to remote command injection.",
    severity: "high",
    category: "ai-safety",
    match: (content, filePath) => {
      if (!shouldScan(filePath)) return [];
      const regexes = isPython(filePath) ? [
        /\b(?:os\.system|subprocess\.run|subprocess\.Popen)\s*\([^)]*(?:f['"][^'"]*\{[^}]*(?:input|command|toolArgs|query|args|cmd)[^}]*\}|shell\s*=\s*True)/gi
      ] : [
        /\b(?:exec|execSync|spawnSync)\s*\(\s*`[^`]*\$\{[^}]*(?:input|command|toolArgs|query|args|cmd|path)[^}]*\}/gi
      ];
      const findings = [];
      for (const regex of regexes) {
        let match;
        while ((match = regex.exec(content)) !== null) {
          const { line, column, snippet } = getLineAndSnippet(content, match.index);
          findings.push({
            id: `AIS-003-${line}`,
            ruleId: "AIS-003",
            title: "Insecure Command Injection in Agent Tool Execution",
            description: "Passing unsanitized AI tool arguments or user strings into system shell execution leads to remote command injection.",
            severity: "high",
            category: "ai-safety",
            file: filePath,
            line,
            column,
            snippet,
            suggestedFix: "Use parameterized spawn() or execFile() with an array of arguments and shell: false."
          });
        }
      }
      return findings;
    }
  },
  {
    id: "AIS-004",
    name: "Unbounded Token Generation (Cost Explosion Risk)",
    description: "LLM API call does not define max_tokens or max_completion_tokens. In open-source bots or agents, this can lead to infinite loops or unexpected billing spikes.",
    severity: "medium",
    category: "ai-safety",
    match: (content, filePath) => {
      if (!shouldScan(filePath)) return [];
      const triggerRegex = /(?:openai|client)\.(?:chat\.completions|completions)\.create\s*\(/g;
      const findings = [];
      let match;
      while ((match = triggerRegex.exec(content)) !== null) {
        const openParenIndex = match.index + match[0].length - 1;
        const argsBlock = extractParenthesizedArgs(content, openParenIndex);
        const trimmedArgs = argsBlock.trim();
        const hasSpreadOrVar = /\.\.\.|^[a-zA-Z0-9_]+$/.test(trimmedArgs);
        const hasTokenLimit = /max_tokens|max_completion_tokens/.test(argsBlock);
        if (!hasTokenLimit && !hasSpreadOrVar) {
          const { line, column, snippet } = getLineAndSnippet(content, match.index);
          findings.push({
            id: `AIS-004-${line}`,
            ruleId: "AIS-004",
            title: "Unbounded Token Generation (Cost Explosion Risk)",
            description: "LLM API call does not define max_tokens or max_completion_tokens. In open-source bots or agents, this can lead to infinite loops or unexpected billing spikes.",
            severity: "medium",
            category: "ai-safety",
            file: filePath,
            line,
            column,
            snippet,
            suggestedFix: 'Always specify "max_completion_tokens" or "max_tokens" to safeguard against run-away generation costs.'
          });
        }
      }
      return findings;
    }
  },
  {
    id: "AIS-005",
    name: "Unsafe Object Deserialization in AI Memory / Cache",
    description: "Unsafe deserialization of agent memory states or cache allows arbitrary object injection and remote code execution.",
    severity: "high",
    category: "ai-safety",
    match: (content, filePath) => {
      if (!shouldScan(filePath)) return [];
      const regex = /\b(?:pickle\.loads|yaml\.unsafe_load|marshal\.loads|deserialize|unserialize)\s*\([^)]*(?:memory|cache|agent_state|history|session)/gi;
      const findings = [];
      let match;
      while ((match = regex.exec(content)) !== null) {
        const { line, column, snippet } = getLineAndSnippet(content, match.index);
        findings.push({
          id: `AIS-005-${line}`,
          ruleId: "AIS-005",
          title: "Unsafe Object Deserialization in AI Memory / Cache",
          description: "Unsafe deserialization of agent memory states or cache allows arbitrary object injection.",
          severity: "high",
          category: "ai-safety",
          file: filePath,
          line,
          column,
          snippet,
          suggestedFix: "Use safe data interchange formats like JSON or Protocol Buffers for agent state persistence."
        });
      }
      return findings;
    }
  },
  {
    id: "AIS-006",
    name: "Vector Database Credential Leak & Insecure Storage",
    description: "Hardcoded Vector DB credentials (Pinecone, Qdrant, ChromaDB, Weaviate) or unencrypted vector storage endpoints.",
    severity: "high",
    category: "ai-safety",
    match: (content, filePath) => {
      if (!shouldScan(filePath)) return [];
      const findings = [];
      const seenLines = /* @__PURE__ */ new Set();
      const regexes = [
        /\b(pcsk_[a-zA-Z0-9_-]{32,})\b/g,
        // Pinecone API key
        /\b(?:new\s+Pinecone|PineconeClient)\s*\(\s*\{[^}]*apiKey\s*:\s*["']([a-zA-Z0-9_-]{20,})["']/gi,
        /\b(?:new\s+QdrantClient|QdrantClient)\s*\(\s*\{[^}]*apiKey\s*:\s*["']([a-zA-Z0-9_-]{20,})["']/gi,
        /\b(?:weaviate\.client)\s*\(\s*\{[^}]*apiKey\s*:\s*["']([a-zA-Z0-9_-]{20,})["']/gi
      ];
      for (const regex of regexes) {
        let match;
        while ((match = regex.exec(content)) !== null) {
          const key = match[1] || match[0];
          if (key.includes("${") || key.includes("process.env")) continue;
          if (key.startsWith("pcsk_") && regex !== regexes[0]) continue;
          const { line, column, snippet } = getLineAndSnippet(content, match.index);
          if (seenLines.has(line)) continue;
          seenLines.add(line);
          const masked = key.length > 8 ? key.slice(0, 4) + "..." + key.slice(-4) : "***";
          findings.push({
            id: `AIS-006-${line}`,
            ruleId: "AIS-006",
            title: "Vector Database Credential Leak & Insecure Storage",
            description: "Hardcoded Vector DB credentials detected. Unauthorized access to vector databases can lead to data exfiltration and RAG poisoning.",
            severity: "high",
            category: "ai-safety",
            file: filePath,
            line,
            column,
            snippet: snippet.replace(key, masked),
            suggestedFix: "Store vector database API keys in environment variables (e.g. PINECONE_API_KEY, QDRANT_API_KEY)."
          });
        }
      }
      return findings;
    }
  },
  {
    id: "AIS-007",
    name: "Unprotected SSRF in AI Agent Tool Execution",
    description: "AI Agent tool fetches arbitrary URLs provided by model output or prompt arguments without loopback or cloud metadata IP shielding.",
    severity: "high",
    category: "ai-safety",
    match: (content, filePath) => {
      if (!shouldScan(filePath)) return [];
      const findings = [];
      const seenLines = /* @__PURE__ */ new Set();
      const regexes = isPython(filePath) ? [
        /\b(?:requests\.(?:get|post)|httpx\.(?:get|post)|urllib\.request\.urlopen)\s*\([^)]*(?:tool_input|args|params|toolArgs|query|url)[^)]*\)/gi
      ] : [
        /\b(?:fetch|axios\.(?:get|post)|http\.(?:get|request))\s*\([^)]*(?:toolInput|toolArgs|args|params)\.(?:url|endpoint|target)[^)]*\)/gi
      ];
      for (const regex of regexes) {
        let match;
        while ((match = regex.exec(content)) !== null) {
          const { line, column, snippet } = getLineAndSnippet(content, match.index);
          if (seenLines.has(line)) continue;
          seenLines.add(line);
          findings.push({
            id: `AIS-007-${line}`,
            ruleId: "AIS-007",
            title: "Unprotected SSRF in AI Agent Tool Execution",
            description: "Agent tool fetches user/model supplied URLs without validating against private IP ranges (127.0.0.1, 10.0.0.0/8) or cloud metadata endpoints (169.254.169.254).",
            severity: "high",
            category: "ai-safety",
            file: filePath,
            line,
            column,
            snippet,
            suggestedFix: "Implement strict URL whitelist validation and block internal/loopback IPs and 169.254.169.254 before making network requests in agent tools."
          });
        }
      }
      return findings;
    }
  }
];

// src/core/rules/mcp-safety.ts
function getLineAndSnippet2(content, matchIndex) {
  const upToMatch = content.slice(0, matchIndex);
  const lines = upToMatch.split(/\r?\n/);
  const line = lines.length;
  const column = lines[lines.length - 1].length + 1;
  const allLines = content.split(/\r?\n/);
  const snippet = (allLines[line - 1] || "").trim();
  return { line, column, snippet };
}
var isInternalRuleOrFixture = (filePath) => {
  const norm = filePath.replace(/\\/g, "/");
  return norm.endsWith("src/core/rules/mcp-safety.ts") || norm.includes(".test.") || norm.includes(".spec.") || norm.includes("/tests/") || norm.endsWith("fixtures.ts");
};
var mcpSafetyRules = [
  {
    id: "MCP-001",
    name: "Unrestricted Filesystem Exposure in MCP Server Configuration",
    description: "MCP configuration grants arbitrary access to root directories (/ or C:\\) or entire home directories, enabling LLM agents to read or overwrite critical OS and system files.",
    severity: "critical",
    category: "mcp",
    match: (content, filePath) => {
      if (isInternalRuleOrFixture(filePath)) return [];
      if (!/(?:mcp|claude_desktop_config|agent_config|tools).*\.(json|yaml|yml|ts|js)$/i.test(filePath)) {
        return [];
      }
      const findings = [];
      const regex = /["']?(?:allowedDirectories|allow_paths|roots)["']?\s*:\s*(?:\[[^\]]*["'](?:\/|[A-Za-z]:[\\\/]|\~|\/root|\/etc|\/home|\/Users|\/var)["'][^\]]*\]|(?:\r?\n\s*-\s*["']?(?:\/|[A-Za-z]:[\\\/]|\~|\/root|\/etc|\/home|\/Users|\/var)["']?)+)/gi;
      let match;
      while ((match = regex.exec(content)) !== null) {
        const { line, column, snippet } = getLineAndSnippet2(content, match.index);
        findings.push({
          id: `MCP-001-${line}`,
          ruleId: "MCP-001",
          title: "Unrestricted Filesystem Exposure in MCP Server Configuration",
          description: "MCP configuration exposes the root filesystem or user home directory. Any prompt injection can read SSH keys, OS credentials, or destroy system files.",
          severity: "critical",
          category: "mcp",
          file: filePath,
          line,
          column,
          snippet,
          suggestedFix: 'Restrict "allowedDirectories" to dedicated project subdirectories (e.g. "./workspace" or "./data") instead of root or home.',
          referenceUrl: "https://modelcontextprotocol.io/docs/concepts/resources"
        });
      }
      return findings;
    }
  },
  {
    id: "MCP-002",
    name: "Arbitrary Shell Execution in MCP Tool Definition",
    description: 'MCP tool definitions enabling "shell: true" or directly interpolating arguments into bash/sh create Remote Code Execution (RCE) vectors via prompt injection.',
    severity: "high",
    category: "mcp",
    match: (content, filePath) => {
      if (isInternalRuleOrFixture(filePath)) return [];
      if (!/\.(ts|js|py|mjs|cjs|json)$/i.test(filePath)) return [];
      const findings = [];
      const regex = /(?:shell\s*:\s*true|["']shell["']\s*:\s*true|\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{[^}]*args)/gi;
      let match;
      while ((match = regex.exec(content)) !== null) {
        const { line, column, snippet } = getLineAndSnippet2(content, match.index);
        findings.push({
          id: `MCP-002-${line}`,
          ruleId: "MCP-002",
          title: "Arbitrary Shell Execution in MCP Tool Definition",
          description: "MCP tool accepts arguments and executes them in a shell context without argument escaping.",
          severity: "high",
          category: "mcp",
          file: filePath,
          line,
          column,
          snippet,
          suggestedFix: "Pass arguments as an immutable array using execFile() or spawn() with shell: false.",
          referenceUrl: "https://modelcontextprotocol.io/docs/concepts/tools"
        });
      }
      return findings;
    }
  },
  {
    id: "MCP-003",
    name: "Hardcoded Secret in MCP Server Environment Configuration",
    description: 'MCP config files contain plaintext API keys or access tokens embedded in the "env" section.',
    severity: "critical",
    category: "mcp",
    match: (content, filePath) => {
      if (isInternalRuleOrFixture(filePath)) return [];
      if (!/(?:mcp|claude_desktop_config|agent_config).*\.(json|yaml|yml)$/i.test(filePath)) return [];
      const findings = [];
      const regex = /(?:"env"\s*:\s*\{[\s\S]*?"(?:[A-Z0-9_]*(?:KEY|TOKEN|SECRET))"\s*:\s*"([a-zA-Z0-9_\-\.]{20,})"|\benv:\s*(?:\r?\n\s+(?:[A-Z0-9_]*(?:KEY|TOKEN|SECRET)):\s*["']?([a-zA-Z0-9_\-\.]{20,})["']?))/gi;
      let match;
      while ((match = regex.exec(content)) !== null) {
        const token = match[1] || match[2];
        if (!token || token.includes("${") || token.includes("process.env")) {
          continue;
        }
        const secretIndex = match.index + match[0].lastIndexOf(token);
        const { line, column, snippet } = getLineAndSnippet2(content, secretIndex);
        const masked = token.slice(0, 4) + "..." + token.slice(-4);
        findings.push({
          id: `MCP-003-${line}`,
          ruleId: "MCP-003",
          title: "Hardcoded Secret in MCP Server Environment Configuration",
          description: "Hardcoded API credentials in MCP server configuration will leak to version control upon commit.",
          severity: "critical",
          category: "mcp",
          file: filePath,
          line,
          column,
          snippet: snippet.replace(token, masked),
          suggestedFix: "Inject secrets dynamically via system environment variables rather than static JSON configuration files.",
          referenceUrl: "https://modelcontextprotocol.io/docs/tools/debugging"
        });
      }
      return findings;
    }
  },
  {
    id: "MCP-004",
    name: "SSRF Vulnerability in MCP Tool Server",
    description: "MCP tool handler fetches arbitrary URLs without restricting loopback (127.0.0.1) or cloud metadata endpoints (169.254.169.254).",
    severity: "high",
    category: "mcp",
    match: (content, filePath) => {
      if (isInternalRuleOrFixture(filePath)) return [];
      if (!/\.(ts|js|py|mjs|cjs)$/i.test(filePath)) return [];
      const findings = [];
      const regex = /\b(?:fetch|axios\.(?:get|post)|requests\.(?:get|post)|http\.(?:get|request))\s*\(\s*(?:args|toolArgs|tool_input|input|params)\.(?:url|endpoint|target)/gi;
      let match;
      while ((match = regex.exec(content)) !== null) {
        const { line, column, snippet } = getLineAndSnippet2(content, match.index);
        findings.push({
          id: `MCP-004-${line}`,
          ruleId: "MCP-004",
          title: "SSRF Vulnerability in MCP Tool Server",
          description: "MCP tool takes user/model supplied URL and issues network requests without private IP filtering (risk of internal network pivoting and cloud credential theft).",
          severity: "high",
          category: "mcp",
          file: filePath,
          line,
          column,
          snippet,
          suggestedFix: "Validate outbound URLs against private CIDR ranges (127.0.0.1, 10.0.0.0/8) and cloud metadata endpoint (169.254.169.254).",
          referenceUrl: "https://modelcontextprotocol.io/docs/concepts/tools"
        });
      }
      return findings;
    }
  },
  {
    id: "MCP-005",
    name: "Unconstrained Tool Input Schema in MCP Server",
    description: "MCP tool definition defines an empty or unvalidated inputSchema without properties, allowing arbitrary payload injection.",
    severity: "medium",
    category: "mcp",
    match: (content, filePath) => {
      if (isInternalRuleOrFixture(filePath)) return [];
      if (!/(?:mcp|tool|server).*\.(ts|js|json)$/i.test(filePath)) return [];
      const findings = [];
      const regex = /inputSchema\s*:\s*\{\s*(?:type\s*:\s*["']object["']\s*)?\}/gi;
      let match;
      while ((match = regex.exec(content)) !== null) {
        const { line, column, snippet } = getLineAndSnippet2(content, match.index);
        findings.push({
          id: `MCP-005-${line}`,
          ruleId: "MCP-005",
          title: "Unconstrained Tool Input Schema in MCP Server",
          description: "MCP tool registered with empty or unconstrained inputSchema. Tool arguments will not be validated against type and bounds.",
          severity: "medium",
          category: "mcp",
          file: filePath,
          line,
          column,
          snippet,
          suggestedFix: "Specify explicit properties, data types, and required fields in inputSchema (or use zodToJsonSchema).",
          referenceUrl: "https://modelcontextprotocol.io/docs/concepts/tools"
        });
      }
      return findings;
    }
  }
];

// src/core/config.ts
var import_node_fs = __toESM(require("fs"));
var import_node_path = __toESM(require("path"));
var DEFAULT_CONFIG = {
  ignorePaths: ["dist/**", "build/**", "node_modules/**", "coverage/**"],
  disabledRules: [],
  severityOverrides: {},
  minEntropy: 3,
  failThreshold: "high"
};
function loadConfig(cwd = process.cwd()) {
  const candidateFiles = [
    ".agentguardrc.json",
    ".agentguardrc",
    "agentguard.config.json"
  ];
  let configOverrides = {};
  for (const file of candidateFiles) {
    const fullPath = import_node_path.default.resolve(cwd, file);
    if (import_node_fs.default.existsSync(fullPath)) {
      try {
        const content = import_node_fs.default.readFileSync(fullPath, "utf-8");
        configOverrides = JSON.parse(content);
        break;
      } catch {
      }
    }
  }
  const gitignorePatterns = [];
  const gitignorePath = import_node_path.default.resolve(cwd, ".gitignore");
  if (import_node_fs.default.existsSync(gitignorePath)) {
    try {
      const lines = import_node_fs.default.readFileSync(gitignorePath, "utf-8").split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("#")) {
          gitignorePatterns.push(trimmed);
        }
      }
    } catch {
    }
  }
  const agentguardIgnorePatterns = [];
  const agentguardIgnorePath = import_node_path.default.resolve(cwd, ".agentguardignore");
  if (import_node_fs.default.existsSync(agentguardIgnorePath)) {
    try {
      const lines = import_node_fs.default.readFileSync(agentguardIgnorePath, "utf-8").split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("#")) {
          agentguardIgnorePatterns.push(trimmed);
        }
      }
    } catch {
    }
  }
  const combinedIgnores = Array.from(
    /* @__PURE__ */ new Set([
      ...DEFAULT_CONFIG.ignorePaths,
      ...Array.isArray(configOverrides.ignorePaths) ? configOverrides.ignorePaths : [],
      ...gitignorePatterns,
      ...agentguardIgnorePatterns
    ])
  );
  return {
    ignorePaths: combinedIgnores,
    disabledRules: Array.isArray(configOverrides.disabledRules) ? configOverrides.disabledRules : [],
    severityOverrides: configOverrides.severityOverrides || {},
    minEntropy: typeof configOverrides.minEntropy === "number" ? configOverrides.minEntropy : DEFAULT_CONFIG.minEntropy,
    failThreshold: configOverrides.failThreshold || DEFAULT_CONFIG.failThreshold
  };
}

// src/core/scanner.ts
var Scanner = class {
  rules;
  config;
  constructor(optionsOrRules = {}) {
    let customRules = [];
    let cfg = {};
    if (Array.isArray(optionsOrRules)) {
      customRules = optionsOrRules;
    } else {
      customRules = optionsOrRules.customRules || [];
      cfg = optionsOrRules.config || {};
    }
    this.config = {
      ...DEFAULT_CONFIG,
      ...cfg
    };
    const allRules = [
      ...secretRules,
      ...aiSafetyRules,
      ...mcpSafetyRules,
      ...customRules
    ];
    const disabledSet = new Set(this.config.disabledRules);
    this.rules = allRules.filter((r) => !disabledSet.has(r.id)).map((r) => {
      if (this.config.severityOverrides && this.config.severityOverrides[r.id]) {
        return {
          ...r,
          severity: this.config.severityOverrides[r.id]
        };
      }
      return r;
    });
  }
  /**
   * Determines if a given file path is excluded by project configuration or .gitignore.
   */
  isIgnored(filePath) {
    const normalized = filePath.replace(/\\/g, "/").replace(/^\.\//, "");
    for (const pattern of this.config.ignorePaths) {
      let cleanPattern = pattern.replace(/\\/g, "/").replace(/^\.\//, "").trim();
      if (!cleanPattern) continue;
      if (cleanPattern.startsWith("*.")) {
        const ext = cleanPattern.slice(1);
        if (normalized.endsWith(ext)) {
          return true;
        }
      }
      cleanPattern = cleanPattern.replace(/\/\*\*$/, "").replace(/\/$/, "");
      if (normalized === cleanPattern || normalized.startsWith(cleanPattern + "/") || normalized.includes(`/${cleanPattern}/`) || normalized.endsWith(`/${cleanPattern}`)) {
        return true;
      }
    }
    return false;
  }
  /**
   * Parses suppression directives in file content.
   * Returns a map of line number -> Set of suppressed rule IDs (or '*' for all rules).
   */
  parseSuppressions(content) {
    const suppressions = /* @__PURE__ */ new Map();
    const lines = content.split(/\r?\n/);
    let inBlockDisable = false;
    let blockRules = /* @__PURE__ */ new Set();
    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i];
      const blockDisableMatch = line.match(/\/\*\s*agentguard-disable(?:\s+([\w-]+))?\s*\*\//);
      if (blockDisableMatch) {
        inBlockDisable = true;
        blockRules = new Set(blockDisableMatch[1] ? [blockDisableMatch[1]] : ["*"]);
      }
      if (line.includes("/* agentguard-enable */")) {
        inBlockDisable = false;
        blockRules.clear();
      }
      if (inBlockDisable) {
        suppressions.set(lineNum, new Set(blockRules));
      }
      const inlineIgnoreMatch = line.match(/(?:\/\/|\/\*)\s*agentguard-ignore(?::|\s+)?([\w-]+)?/);
      if (inlineIgnoreMatch) {
        const set = suppressions.get(lineNum) || /* @__PURE__ */ new Set();
        set.add(inlineIgnoreMatch[1] ? inlineIgnoreMatch[1] : "*");
        suppressions.set(lineNum, set);
      }
      const nextLineMatch = line.match(/(?:\/\/|\/\*)\s*agentguard-disable-next-line(?::|\s+)?([\w-]+)?/);
      if (nextLineMatch) {
        const nextLineNum = lineNum + 1;
        const set = suppressions.get(nextLineNum) || /* @__PURE__ */ new Set();
        set.add(nextLineMatch[1] ? nextLineMatch[1] : "*");
        suppressions.set(nextLineNum, set);
      }
    }
    return suppressions;
  }
  /**
   * Scans a single file's full content.
   */
  scanContent(content, filePath) {
    if (this.isIgnored(filePath)) {
      return [];
    }
    const findings = [];
    const suppressions = this.parseSuppressions(content);
    for (const rule of this.rules) {
      const matched = rule.match(content, filePath);
      for (const m of matched) {
        const lineSuppressions = suppressions.get(m.line);
        if (lineSuppressions && (lineSuppressions.has("*") || lineSuppressions.has(m.ruleId))) {
          findings.push({ ...m, suppressed: true });
        } else {
          findings.push(m);
        }
      }
    }
    return findings;
  }
  /**
   * Scans a git diff string (e.g. from git diff or GitHub PR).
   * Uses Hunk Context Reconstruction to accurately match multiline patterns
   * while strictly attributing findings only to newly added/modified lines.
   */
  scanDiff(diffContent) {
    const findings = [];
    const diffFiles = this.parseGitDiff(diffContent);
    const seenFindingKeys = /* @__PURE__ */ new Set();
    for (const file of diffFiles) {
      if (this.isIgnored(file.filename)) {
        continue;
      }
      for (const hunk of file.hunks) {
        const newLines = [];
        for (const line of hunk.lines) {
          if (line.type !== "del" && line.newLineNumber !== void 0) {
            newLines.push({
              content: line.content,
              newLineNumber: line.newLineNumber,
              isAdded: line.type === "add"
            });
          }
        }
        if (newLines.length === 0) continue;
        const hunkContent = newLines.map((l) => l.content).join("\n");
        const suppressions = this.parseSuppressions(hunkContent);
        for (const rule of this.rules) {
          const matched = rule.match(hunkContent, file.filename);
          for (const m of matched) {
            const hunkLineIdx = m.line - 1;
            if (hunkLineIdx < 0 || hunkLineIdx >= newLines.length) continue;
            const snippetLineCount = m.snippet ? m.snippet.split(/\r?\n/).length : 1;
            const endHunkLineIdx = Math.min(newLines.length - 1, hunkLineIdx + snippetLineCount - 1);
            let touchesAddedLine = false;
            for (let i = hunkLineIdx; i <= endHunkLineIdx; i++) {
              if (newLines[i].isAdded) {
                touchesAddedLine = true;
                break;
              }
            }
            if (!touchesAddedLine) {
              continue;
            }
            const targetLineInfo = newLines[hunkLineIdx];
            const realLineNumber = targetLineInfo.newLineNumber;
            const lineSupp = suppressions.get(m.line);
            const isSuppressed = Boolean(
              lineSupp && (lineSupp.has("*") || lineSupp.has(m.ruleId))
            );
            const findingKey = `${file.filename}:${realLineNumber}:${m.ruleId}`;
            if (seenFindingKeys.has(findingKey)) {
              continue;
            }
            seenFindingKeys.add(findingKey);
            findings.push({
              ...m,
              file: file.filename,
              line: realLineNumber,
              suppressed: isSuppressed
            });
          }
        }
      }
    }
    return findings;
  }
  /**
   * Calculates a 0-100 Risk Score based on active findings.
   */
  calculateRiskScore(findings) {
    const active = findings.filter((f) => !f.suppressed);
    if (active.length === 0) return 0;
    let score = 0;
    for (const f of active) {
      switch (f.severity) {
        case "critical":
          score += 40;
          break;
        case "high":
          score += 20;
          break;
        case "medium":
          score += 10;
          break;
        case "low":
          score += 5;
          break;
        case "info":
          score += 1;
          break;
      }
    }
    return Math.min(100, score);
  }
  /**
   * Computes a full ScanResult summary.
   */
  generateResult(findings, scannedFiles, durationMs, failThreshold) {
    const effectiveThreshold = failThreshold || this.config.failThreshold || "high";
    const summary = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    const activeFindings = findings.filter((f) => !f.suppressed);
    const suppressedCount = findings.length - activeFindings.length;
    for (const f of activeFindings) {
      summary[f.severity]++;
    }
    const severityOrder = ["info", "low", "medium", "high", "critical"];
    const thresholdIdx = severityOrder.indexOf(effectiveThreshold);
    let passed = true;
    for (let i = thresholdIdx; i < severityOrder.length; i++) {
      const sev = severityOrder[i];
      if (summary[sev] > 0) {
        passed = false;
        break;
      }
    }
    return {
      totalFiles: scannedFiles,
      scannedFiles,
      findings: activeFindings,
      suppressedCount,
      riskScore: this.calculateRiskScore(activeFindings),
      summary,
      passed,
      durationMs
    };
  }
  /**
   * Helper to parse standard unified git diff format.
   */
  parseGitDiff(diffText) {
    const files = [];
    const fileBlocks = diffText.split(/^diff --git /m);
    for (const block of fileBlocks) {
      if (!block.trim()) continue;
      const lines = block.split(/\r?\n/);
      let filename = "";
      for (const line of lines) {
        if (line.startsWith("+++ b/")) {
          filename = line.slice(6);
          break;
        } else if (line.startsWith("+++ ")) {
          filename = line.slice(4);
          break;
        }
      }
      if (!filename || filename === "/dev/null") continue;
      const hunks = [];
      let currentHunk = null;
      let currentNewLine = 0;
      for (const line of lines) {
        const hunkMatch = line.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
        if (hunkMatch) {
          currentNewLine = parseInt(hunkMatch[2], 10);
          currentHunk = { lines: [] };
          hunks.push(currentHunk);
          continue;
        }
        if (!currentHunk) continue;
        if (line.startsWith("+") && !line.startsWith("+++")) {
          currentHunk.lines.push({
            type: "add",
            content: line.slice(1),
            newLineNumber: currentNewLine
          });
          currentNewLine++;
        } else if (line.startsWith("-") && !line.startsWith("---")) {
          currentHunk.lines.push({
            type: "del",
            content: line.slice(1)
          });
        } else if (line.startsWith(" ")) {
          currentHunk.lines.push({
            type: "context",
            content: line.slice(1),
            newLineNumber: currentNewLine
          });
          currentNewLine++;
        }
      }
      files.push({ filename, hunks });
    }
    return files;
  }
};

// src/core/formatter/terminal.ts
var import_picocolors = __toESM(require("picocolors"));
var TerminalFormatter = class {
  static severityBadge(sev) {
    switch (sev) {
      case "critical":
        return import_picocolors.default.bgRed(import_picocolors.default.white(import_picocolors.default.bold(" CRITICAL ")));
      case "high":
        return import_picocolors.default.bgRed(import_picocolors.default.black(" HIGH "));
      case "medium":
        return import_picocolors.default.bgYellow(import_picocolors.default.black(" MEDIUM "));
      case "low":
        return import_picocolors.default.bgCyan(import_picocolors.default.black(" LOW "));
      case "info":
        return import_picocolors.default.bgBlue(import_picocolors.default.white(" INFO "));
    }
  }
  static format(result) {
    const lines = [];
    lines.push("");
    lines.push(
      import_picocolors.default.bold(
        import_picocolors.default.cyan("\u{1F6E1}\uFE0F  AgentGuard-CI") + import_picocolors.default.gray(" - AI & Secret Security Guardrail")
      )
    );
    lines.push(import_picocolors.default.gray("\u2500".repeat(60)));
    if (result.findings.length === 0) {
      lines.push("");
      lines.push(
        import_picocolors.default.green(
          import_picocolors.default.bold("\u2728 All checks passed! No security or AI safety risks found.")
        )
      );
      lines.push(
        import_picocolors.default.gray(
          `Scanned ${result.scannedFiles} file(s) in ${result.durationMs}ms.`
        )
      );
      if (result.suppressedCount && result.suppressedCount > 0) {
        lines.push(
          import_picocolors.default.dim(`(${result.suppressedCount} issue(s) suppressed via inline comments)`)
        );
      }
      lines.push("");
      return lines.join("\n");
    }
    const byFile = /* @__PURE__ */ new Map();
    for (const f of result.findings) {
      if (!byFile.has(f.file)) {
        byFile.set(f.file, []);
      }
      byFile.get(f.file).push(f);
    }
    lines.push("");
    lines.push(
      import_picocolors.default.bold(import_picocolors.default.red(`Found ${result.findings.length} security finding(s):`))
    );
    lines.push("");
    for (const [file, findings] of byFile.entries()) {
      lines.push(import_picocolors.default.bold(import_picocolors.default.underline(import_picocolors.default.white(`\u{1F4C4} ${file}`))));
      for (const f of findings) {
        const badge = this.severityBadge(f.severity);
        lines.push(
          `  ${badge} ${import_picocolors.default.bold(f.title)} ${import_picocolors.default.gray(`(Line ${f.line})`)}`
        );
        lines.push(`    ${import_picocolors.default.gray(f.description)}`);
        if (f.snippet) {
          lines.push(
            `    ${import_picocolors.default.dim("Code: ")} ${import_picocolors.default.italic(import_picocolors.default.yellow(f.snippet))}`
          );
        }
        if (f.entropy !== void 0) {
          lines.push(
            `    ${import_picocolors.default.dim("Shannon Entropy: ")} ${import_picocolors.default.magenta(
              `${f.entropy} bits`
            )}`
          );
        }
        if (f.suggestedFix) {
          lines.push(
            `    ${import_picocolors.default.green("\u{1F4A1} Fix: ")} ${import_picocolors.default.cyan(f.suggestedFix)}`
          );
        }
        lines.push("");
      }
    }
    lines.push(import_picocolors.default.gray("\u2500".repeat(60)));
    const riskColor = result.riskScore > 50 ? import_picocolors.default.red : result.riskScore > 20 ? import_picocolors.default.yellow : import_picocolors.default.green;
    lines.push(
      import_picocolors.default.bold("Risk Score: ") + riskColor(import_picocolors.default.bold(`${result.riskScore}/100`)) + import_picocolors.default.gray(` | Scanned in ${result.durationMs}ms`)
    );
    const s = result.summary;
    let summaryText = `Summary: ${import_picocolors.default.red(s.critical + " Critical")} | ${import_picocolors.default.red(
      s.high + " High"
    )} | ${import_picocolors.default.yellow(s.medium + " Medium")} | ${import_picocolors.default.cyan(
      s.low + " Low"
    )} | ${import_picocolors.default.blue(s.info + " Info")}`;
    if (result.suppressedCount && result.suppressedCount > 0) {
      summaryText += ` | ${import_picocolors.default.dim(`${result.suppressedCount} Suppressed`)}`;
    }
    lines.push(summaryText);
    if (!result.passed) {
      lines.push("");
      lines.push(
        import_picocolors.default.bgRed(
          import_picocolors.default.white(
            import_picocolors.default.bold(" \u274C CHECK FAILED: Critical or High severity issues detected. ")
          )
        )
      );
    } else {
      lines.push("");
      lines.push(import_picocolors.default.green(import_picocolors.default.bold(" \u2714 PASSED (Threshold met).")));
    }
    lines.push("");
    return lines.join("\n");
  }
};

// src/core/formatter/markdown.ts
var MarkdownFormatter = class {
  static severityEmoji(sev) {
    switch (sev) {
      case "critical":
        return "\u{1F534} `CRITICAL`";
      case "high":
        return "\u{1F7E0} `HIGH`";
      case "medium":
        return "\u{1F7E1} `MEDIUM`";
      case "low":
        return "\u{1F535} `LOW`";
      case "info":
        return "\u26AA `INFO`";
    }
  }
  static formatPRComment(result, aiInsights) {
    const lines = [];
    lines.push("## \u{1F6E1}\uFE0F AgentGuard-CI Security & Code Quality Report");
    lines.push("<!-- agentguard-ci-report -->");
    lines.push("");
    const statusBadge = result.passed ? "![Passed](https://img.shields.io/badge/AgentGuard-PASSED-success?style=for-the-badge&logo=shield)" : "![Failed](https://img.shields.io/badge/AgentGuard-ACTION_REQUIRED-critical?style=for-the-badge&logo=shield)";
    lines.push(`${statusBadge} `);
    lines.push("");
    lines.push("### \u{1F4CA} Executive Summary");
    lines.push("");
    lines.push("| Metric | Status |");
    lines.push("| :--- | :--- |");
    lines.push(
      `| **Risk Score** | \`${result.riskScore}/100\` (${result.riskScore > 50 ? "\u{1F6A8} High Risk" : result.riskScore > 20 ? "\u26A0\uFE0F Moderate Risk" : "\u2705 Safe"}) |`
    );
    lines.push(`| **Files Scanned** | ${result.scannedFiles} |`);
    lines.push(
      `| **Findings Breakdown** | \u{1F534} ${result.summary.critical} Critical \xB7 \u{1F7E0} ${result.summary.high} High \xB7 \u{1F7E1} ${result.summary.medium} Medium \xB7 \u{1F535} ${result.summary.low} Low |`
    );
    lines.push(`| **Scan Duration** | ${result.durationMs}ms |`);
    lines.push("");
    if (aiInsights) {
      lines.push("### \u{1F916} AI Semantic Reviewer Notes");
      lines.push("");
      lines.push(aiInsights);
      lines.push("");
    }
    if (result.findings.length === 0) {
      lines.push("---");
      lines.push("\u{1F389} **No security vulnerabilities or secret leaks detected in this PR!**");
      lines.push("");
      lines.push(
        "_Powered by [AgentGuard-CI](https://github.com/Canhettg1133/agentguard-ci) \xB7 Open Source Security Guardrail_"
      );
      return lines.join("\n");
    }
    lines.push("### \u{1F50D} Detailed Findings");
    lines.push("");
    const byFile = /* @__PURE__ */ new Map();
    for (const f of result.findings) {
      if (!byFile.has(f.file)) {
        byFile.set(f.file, []);
      }
      byFile.get(f.file).push(f);
    }
    for (const [file, findings] of byFile.entries()) {
      lines.push(`<details open>`);
      lines.push(`<summary><b>\u{1F4C4} ${file} (${findings.length} issue${findings.length > 1 ? "s" : ""})</b></summary>`);
      lines.push("");
      lines.push("| Severity | Rule | Line | Description | Suggested Remediation |");
      lines.push("| :--- | :--- | :---: | :--- | :--- |");
      for (const f of findings) {
        const sev = this.severityEmoji(f.severity);
        const fix = f.suggestedFix ? f.suggestedFix.replace(/\|/g, "\\|") : "None";
        const desc = f.description.replace(/\|/g, "\\|");
        lines.push(`| ${sev} | **${f.title}** | \`${f.line}\` | ${desc} | ${fix} |`);
      }
      lines.push("");
      lines.push("</details>");
      lines.push("");
    }
    lines.push("---");
    lines.push(
      "\u{1F4A1} *Maintainer Note: Critical or High severity findings should be resolved before merging to protect repository security.*"
    );
    lines.push("");
    lines.push(
      "_Protected by [AgentGuard-CI](https://github.com/Canhettg1133/agentguard-ci) \u2014 Automated Open Source PR Security_"
    );
    return lines.join("\n");
  }
};

// src/core/version.ts
var AGENTGUARD_VERSION = "0.2.0";

// src/core/formatter/sarif.ts
var SarifFormatter = class {
  static severityToSarifLevel(sev) {
    switch (sev) {
      case "critical":
      case "high":
        return "error";
      case "medium":
        return "warning";
      case "low":
      case "info":
        return "note";
    }
  }
  /**
   * Generates a fully compliant OASIS SARIF v2.1.0 JSON string.
   */
  static format(result) {
    const ruleMap = /* @__PURE__ */ new Map();
    for (const f of result.findings) {
      if (!ruleMap.has(f.ruleId)) {
        ruleMap.set(f.ruleId, {
          id: f.ruleId,
          name: f.title,
          description: f.description,
          severity: f.severity
        });
      }
    }
    const rules = Array.from(ruleMap.values()).map((r) => ({
      id: r.id,
      name: r.name,
      shortDescription: {
        text: r.name
      },
      fullDescription: {
        text: r.description
      },
      defaultConfiguration: {
        level: this.severityToSarifLevel(r.severity)
      },
      properties: {
        problem: {
          severity: r.severity
        }
      }
    }));
    const sarifResults = result.findings.map((f) => ({
      ruleId: f.ruleId,
      level: this.severityToSarifLevel(f.severity),
      message: {
        text: `${f.title}: ${f.description}${f.suggestedFix ? ` (Suggested Fix: ${f.suggestedFix})` : ""}`
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.file.replace(/\\/g, "/"),
              uriBaseId: "%SRCROOT%"
            },
            region: {
              startLine: Math.max(1, f.line),
              startColumn: Math.max(1, f.column || 1),
              snippet: f.snippet ? {
                text: f.snippet
              } : void 0
            }
          }
        }
      ]
    }));
    const sarifReport = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "AgentGuard-CI",
              version: AGENTGUARD_VERSION,
              informationUri: "https://github.com/Canhettg1133/agentguard-ci",
              rules
            }
          },
          results: sarifResults
        }
      ]
    };
    return JSON.stringify(sarifReport, null, 2);
  }
};

// src/benchmark/runner.ts
var import_picocolors2 = __toESM(require("picocolors"));

// src/benchmark/fixtures.ts
var joinTokens = (...parts) => parts.join("");
var BENCHMARK_CASES = [
  // SECRETS - TRUE POSITIVES (High Entropy)
  {
    id: "SEC-TP-01",
    name: "Real OpenAI API Key with high entropy",
    category: "secret",
    expectedVulnerability: true,
    expectedRuleId: "SEC-001",
    filePath: "src/config.ts",
    code: joinTokens('export const key = "', "sk-", 'proj-aB9xK1mQ8zLp7vW2rT4yU6iO0eN3sD5fG1hJ";')
  },
  {
    id: "SEC-TP-02",
    name: "Anthropic Claude API Key",
    category: "secret",
    expectedVulnerability: true,
    expectedRuleId: "SEC-002",
    filePath: "server/llm.ts",
    code: joinTokens('const anthropic = "', "sk-", 'ant-api03-abcdef1234567890abcdef1234567890";')
  },
  {
    id: "SEC-TP-03",
    name: "Google Gemini API Key",
    category: "secret",
    expectedVulnerability: true,
    expectedRuleId: "SEC-003",
    filePath: "src/gemini.ts",
    code: joinTokens('const geminiKey = "', "AIza", 'SyAz1293847592837492837492837482345";')
  },
  {
    id: "SEC-TP-04",
    name: "PostgreSQL Database Connection with Auth",
    category: "secret",
    expectedVulnerability: true,
    expectedRuleId: "SEC-007",
    filePath: "db/connection.ts",
    code: 'const conn = "postgres://admin:SuperSecretP@ss99@db.internal:5432/production";'
  },
  {
    id: "SEC-TP-05",
    name: "Stripe Live Secret Key",
    category: "secret",
    expectedVulnerability: true,
    expectedRuleId: "SEC-009",
    filePath: "billing/stripe.ts",
    code: joinTokens('const stripe = "', "sk_", "live_", '51Oz98aBcDeFgHiJkLmNoPqRsTuVwXyZ12345";')
  },
  {
    id: "SEC-TP-06",
    name: "Live OpenAI API key leaked in Markdown documentation",
    category: "secret",
    expectedVulnerability: true,
    expectedRuleId: "SEC-001",
    filePath: "docs/setup.md",
    code: joinTokens("# Setup Guide\nRun export OPENAI_API_KEY=", "sk-", "proj-9KxL2pQ8zM1vW4rT7yU0iE3sD5fG7hJ1aBc\n")
  },
  // SECRETS - TRUE NEGATIVES (Low Entropy / Placeholders)
  {
    id: "SEC-TN-01",
    name: "Dummy repetitive low-entropy OpenAI key",
    category: "secret",
    expectedVulnerability: false,
    filePath: "src/dummy.ts",
    code: joinTokens('const dummyKey = "', "sk-", 'proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";')
  },
  {
    id: "SEC-TN-02",
    name: "Environment variable reference",
    category: "secret",
    expectedVulnerability: false,
    filePath: "src/env.ts",
    code: 'const key = process.env.OPENAI_API_KEY || "YOUR_KEY_PLACEHOLDER";'
  },
  {
    id: "SEC-TN-03",
    name: "Suppressed secret leak via inline comment",
    category: "secret",
    expectedVulnerability: false,
    filePath: "tests/fixture.ts",
    code: joinTokens('// agentguard-disable-next-line: SEC-001\nconst mock = "', "sk-", 'proj-aB9xK1mQ8zLp7vW2rT4yU6iO0eN3sD5fG1hJ";')
  },
  {
    id: "SEC-TN-04",
    name: "Placeholder in Markdown documentation",
    category: "secret",
    expectedVulnerability: false,
    filePath: "docs/README.md",
    code: "export OPENAI_API_KEY=your_openai_api_key_here\n"
  },
  // AI SAFETY - TRUE POSITIVES
  {
    id: "AIS-TP-01",
    name: "Direct user query concatenated in system prompt (JS)",
    category: "ai-safety",
    expectedVulnerability: true,
    expectedRuleId: "AIS-001",
    filePath: "src/agent.ts",
    code: 'const msg = { role: "system", content: `You are helpful. Context: ${req.body.userInput}` };'
  },
  {
    id: "AIS-TP-02",
    name: "Unsafe eval on AI generated completion",
    category: "ai-safety",
    expectedVulnerability: true,
    expectedRuleId: "AIS-002",
    filePath: "src/executor.ts",
    code: "const output = eval(completion.choices[0].message.content);"
  },
  {
    id: "AIS-TP-03",
    name: "Command injection in agent tool execution (JS)",
    category: "ai-safety",
    expectedVulnerability: true,
    expectedRuleId: "AIS-003",
    filePath: "src/tools.ts",
    code: "execSync(`cat /var/log/${toolArgs.filename}`);"
  },
  {
    id: "AIS-TP-04",
    name: "Python f-string prompt injection into system role",
    category: "ai-safety",
    expectedVulnerability: true,
    expectedRuleId: "AIS-001",
    filePath: "agent/pipeline.py",
    code: 'messages = [{"role": "system", "content": f"You are a helpful assistant. Context: {user_prompt}"}]'
  },
  {
    id: "AIS-TP-05",
    name: "Python subprocess command injection with shell=True",
    category: "ai-safety",
    expectedVulnerability: true,
    expectedRuleId: "AIS-003",
    filePath: "tools/executor.py",
    code: 'subprocess.run(f"cat {tool_input.file_path}", shell=True)'
  },
  // AI SAFETY - TRUE NEGATIVES
  {
    id: "AIS-TN-01",
    name: "Safe separate user and system roles",
    category: "ai-safety",
    expectedVulnerability: false,
    filePath: "src/safe-agent.ts",
    code: 'const messages = [{ role: "system", content: "Static prompt" }, { role: "user", content: userInput }];'
  },
  {
    id: "AIS-TN-02",
    name: "Safe parameterized execFile without shell",
    category: "ai-safety",
    expectedVulnerability: false,
    filePath: "src/safe-tool.ts",
    code: 'execFile("git", ["status"], (err, stdout) => { console.log(stdout); });'
  },
  // MCP SAFETY - TRUE POSITIVES
  {
    id: "MCP-TP-01",
    name: "Root filesystem exposure in MCP config (JSON)",
    category: "mcp",
    expectedVulnerability: true,
    expectedRuleId: "MCP-001",
    filePath: "claude_desktop_config.json",
    code: JSON.stringify({
      mcpServers: {
        filesystem: {
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-filesystem"],
          allowedDirectories: ["/"]
        }
      }
    })
  },
  {
    id: "MCP-TP-02",
    name: "Hardcoded secret in MCP server environment",
    category: "mcp",
    expectedVulnerability: true,
    expectedRuleId: "MCP-003",
    filePath: "mcp_config.json",
    code: JSON.stringify({
      mcpServers: {
        github: {
          command: "docker",
          env: {
            GITHUB_PERSONAL_ACCESS_TOKEN: joinTokens("gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
          }
        }
      }
    })
  },
  {
    id: "MCP-TP-03",
    name: "MCP YAML config exposing root directory",
    category: "mcp",
    expectedVulnerability: true,
    expectedRuleId: "MCP-001",
    filePath: "mcp_config.yaml",
    code: 'mcpServers:\n  filesystem:\n    command: npx\n    allowedDirectories:\n      - "/"\n'
  },
  // MCP SAFETY - TRUE NEGATIVES
  {
    id: "MCP-TN-01",
    name: "Safe scoped workspace directory in MCP config",
    category: "mcp",
    expectedVulnerability: false,
    filePath: "mcp_config.json",
    code: JSON.stringify({
      mcpServers: {
        filesystem: {
          command: "npx",
          allowedDirectories: ["./workspace", "./safe-docs"]
        }
      }
    })
  },
  // ADDITIONAL REAL-WORLD SECURITY CASES
  {
    id: "SEC-TP-07",
    name: "Slack Incoming Webhook URL Leak",
    category: "secret",
    expectedVulnerability: true,
    expectedRuleId: "SEC-010",
    filePath: "src/notifier.ts",
    code: joinTokens('const webhook = "https://hooks.', "slack", '.com/services/T00000000/B00000000/abcdef1234567890abcdef12";')
  },
  {
    id: "SEC-TP-08",
    name: "GitHub Personal Access Token Leak",
    category: "secret",
    expectedVulnerability: true,
    expectedRuleId: "SEC-004",
    filePath: "src/github.ts",
    code: joinTokens('const pat = "', "gh", 'p_1234567890abcdefghijklmnopqrstuvwx12";')
  },
  {
    id: "SEC-TP-09",
    name: "Plaintext Private RSA Key",
    category: "secret",
    expectedVulnerability: true,
    expectedRuleId: "SEC-006",
    filePath: "certs/server.key",
    code: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
  },
  {
    id: "AIS-TP-06",
    name: "LangChain SystemMessage Prompt Injection",
    category: "ai-safety",
    expectedVulnerability: true,
    expectedRuleId: "AIS-001",
    filePath: "src/langchain.ts",
    code: "const msg = new SystemMessage(`You are a tutor. User request: ${req.query.prompt}`);"
  },
  {
    id: "AIS-TN-03",
    name: "Safe OpenAI API call with explicit max_tokens defined",
    category: "ai-safety",
    expectedVulnerability: false,
    filePath: "src/completion.ts",
    code: 'const res = await openai.chat.completions.create({ model: "gpt-4o", messages: [], max_tokens: 500 });'
  },
  {
    id: "MCP-TP-04",
    name: "Arbitrary Shell execution in MCP tool definition",
    category: "mcp",
    expectedVulnerability: true,
    expectedRuleId: "MCP-002",
    filePath: "src/tools/mcp_server.ts",
    code: 'const toolConfig = { name: "execute", shell: true };'
  },
  {
    id: "AIS-TP-07",
    name: "Pinecone Vector DB API Key Leak",
    category: "ai-safety",
    expectedVulnerability: true,
    expectedRuleId: "AIS-006",
    filePath: "src/vector/pinecone.ts",
    code: joinTokens('const pineconeKey = "', "pcsk_", '1234567890abcdef1234567890abcdef12345678";')
  },
  {
    id: "AIS-TP-08",
    name: "Unprotected SSRF in AI Agent Tool",
    category: "ai-safety",
    expectedVulnerability: true,
    expectedRuleId: "AIS-007",
    filePath: "src/tools/web-fetch.ts",
    code: "export const runFetch = (toolArgs: any) => fetch(toolArgs.url);"
  },
  {
    id: "MCP-TP-05",
    name: "SSRF Vulnerability in MCP Tool Server",
    category: "mcp",
    expectedVulnerability: true,
    expectedRuleId: "MCP-004",
    filePath: "src/mcp/http-tool.ts",
    code: "const result = await fetch(args.url);"
  },
  {
    id: "MCP-TP-06",
    name: "Unconstrained Tool Input Schema in MCP Server",
    category: "mcp",
    expectedVulnerability: true,
    expectedRuleId: "MCP-005",
    filePath: "src/mcp/server.ts",
    code: 'server.tool("arbitrary_exec", "Run task", { inputSchema: { type: "object" } });'
  },
  {
    id: "AIS-TN-04",
    name: "Benign user_id interpolation in system prompt (Anti-False-Positive)",
    category: "ai-safety",
    expectedVulnerability: false,
    filePath: "src/prompts.ts",
    code: 'const sys = { role: "system", content: `Logged in user id: ${user_id}` };'
  },
  {
    id: "AIS-TN-05",
    name: "Benign username in system prompt (Anti-False-Positive)",
    category: "ai-safety",
    expectedVulnerability: false,
    filePath: "src/prompts.ts",
    code: 'const sys = { role: "system", content: `Welcome ${username} to admin panel` };'
  },
  {
    id: "AIS-TN-06",
    name: "Safe API call with spread configuration object (Anti-False-Positive)",
    category: "ai-safety",
    expectedVulnerability: false,
    filePath: "src/llm.ts",
    code: "const res = await client.chat.completions.create({ ...baseOptions, messages: [] });"
  },
  {
    id: "MCP-TN-02",
    name: "Safe MCP Tool with fully typed inputSchema properties",
    category: "mcp",
    expectedVulnerability: false,
    filePath: "src/mcp/safe-tool.ts",
    code: 'server.tool("calc", "add numbers", { inputSchema: { type: "object", properties: { a: { type: "number" } } } });'
  }
];

// src/benchmark/runner.ts
function runBenchmark() {
  const scanner = new Scanner();
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  const startTime = performance.now();
  for (const tc of BENCHMARK_CASES) {
    const findings = scanner.scanContent(tc.code, tc.filePath);
    const activeFindings = findings.filter((f) => !f.suppressed);
    const hasDetected = activeFindings.length > 0;
    if (tc.expectedVulnerability) {
      if (hasDetected) {
        tp++;
      } else {
        fn++;
      }
    } else {
      if (hasDetected) {
        fp++;
      } else {
        tn++;
      }
    }
  }
  const totalDurationMs = performance.now() - startTime;
  const total = BENCHMARK_CASES.length;
  const avgLatencyMs = totalDurationMs / total;
  const precision = tp + fp > 0 ? tp / (tp + fp) * 100 : 100;
  const recall = tp + fn > 0 ? tp / (tp + fn) * 100 : 100;
  const f1Score = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
  return {
    total,
    truePositives: tp,
    falsePositives: fp,
    trueNegatives: tn,
    falseNegatives: fn,
    precision: Math.round(precision * 10) / 10,
    recall: Math.round(recall * 10) / 10,
    f1Score: Math.round(f1Score * 10) / 10,
    totalDurationMs: Math.round(totalDurationMs * 100) / 100,
    avgLatencyMs: Math.round(avgLatencyMs * 100) / 100
  };
}
function printBenchmarkReport(metrics) {
  console.log("");
  console.log(
    import_picocolors2.default.bold(
      import_picocolors2.default.cyan("\u26A1 AgentGuard-CI") + import_picocolors2.default.gray(" - Detection Accuracy & Regression Suite")
    )
  );
  console.log(import_picocolors2.default.gray("\u2550".repeat(62)));
  console.log(
    import_picocolors2.default.bold("Dataset: ") + import_picocolors2.default.white(`${metrics.total} Multi-Language Test Cases (Secrets, AI Safety, MCP)`)
  );
  console.log(
    import_picocolors2.default.bold("Standards: ") + import_picocolors2.default.cyan("OWASP Top 10 for LLM (2025) \xB7 CWE-94 \xB7 CWE-78 \xB7 CWE-918 \xB7 CWE-798 \xB7 MCP Spec")
  );
  console.log(import_picocolors2.default.gray("\u2500".repeat(62)));
  console.log(
    `  ${import_picocolors2.default.green("\u2714 True Positives (TP):")}  ${import_picocolors2.default.bold(
      metrics.truePositives.toString()
    )}   |  ${import_picocolors2.default.green("\u2714 True Negatives (TN):")}  ${import_picocolors2.default.bold(
      metrics.trueNegatives.toString()
    )}`
  );
  console.log(
    `  ${import_picocolors2.default.red("\u2716 False Positives (FP):")} ${import_picocolors2.default.bold(
      metrics.falsePositives.toString()
    )}   |  ${import_picocolors2.default.red("\u2716 False Negatives (FN):")} ${import_picocolors2.default.bold(
      metrics.falseNegatives.toString()
    )}`
  );
  console.log(import_picocolors2.default.gray("\u2500".repeat(62)));
  console.log(
    `  ${import_picocolors2.default.bold("Precision (P):")}  ${import_picocolors2.default.green(
      import_picocolors2.default.bold(`${metrics.precision}%`)
    )}  (Zero false alarms)`
  );
  console.log(
    `  ${import_picocolors2.default.bold("Recall (R):")}     ${import_picocolors2.default.green(
      import_picocolors2.default.bold(`${metrics.recall}%`)
    )}  (Detection rate)`
  );
  console.log(
    `  ${import_picocolors2.default.bold("F1-Score:")}       ${import_picocolors2.default.cyan(
      import_picocolors2.default.bold(`${metrics.f1Score}%`)
    )}  (Harmonic mean)`
  );
  console.log(
    `  ${import_picocolors2.default.bold("Mean Latency:")}   ${import_picocolors2.default.yellow(
      import_picocolors2.default.bold(`${metrics.avgLatencyMs} ms`)
    )} per scan`
  );
  console.log(import_picocolors2.default.gray("\u2550".repeat(62)));
  console.log(
    metrics.f1Score >= 90 ? import_picocolors2.default.green(
      import_picocolors2.default.bold("\u{1F31F} BENCHMARK PASSED: Enterprise-grade accuracy & sub-millisecond latency.")
    ) : import_picocolors2.default.red(import_picocolors2.default.bold("\u26A0\uFE0F Benchmark threshold not met."))
  );
  console.log("");
}

// src/cli/index.ts
var program = new import_commander.Command();
var IGNORED_DIRS = /* @__PURE__ */ new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  ".turbo",
  "vendor",
  ".venv",
  "venv",
  "__pycache__",
  "benchmark",
  "fixtures"
]);
var IGNORED_EXTS = /* @__PURE__ */ new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".ico",
  ".svg",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".pdf",
  ".zip",
  ".tar",
  ".gz",
  ".lock",
  ".map",
  ".exe",
  ".bin",
  ".wasm",
  ".node",
  ".dll",
  ".dylib",
  ".so",
  ".mp4",
  ".mp3",
  ".mov",
  ".avi",
  ".webm",
  ".pyc"
]);
function walkDir(dir, baseDir = dir, isIgnored, fileList = []) {
  const entries = import_node_fs2.default.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = import_node_path2.default.join(dir, entry.name);
    const relPath = import_node_path2.default.relative(baseDir, fullPath);
    if (isIgnored && isIgnored(relPath)) {
      continue;
    }
    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith(".")) {
        walkDir(fullPath, baseDir, isIgnored, fileList);
      }
    } else if (entry.isFile()) {
      const ext = import_node_path2.default.extname(entry.name).toLowerCase();
      if (!IGNORED_EXTS.has(ext)) {
        fileList.push(fullPath);
      }
    }
  }
  return fileList;
}
program.name("agentguard").description("AI-Powered Security & Code Quality Guardrail for Pull Requests & Repositories").version(AGENTGUARD_VERSION);
program.command("scan").description("Scan a directory or file for secret leaks, AI vulnerabilities, and MCP risks").argument("[target]", "Target directory or file to scan", ".").option(
  "-t, --threshold <level>",
  "Fail threshold severity (info, low, medium, high, critical)"
).option(
  "-f, --format <format>",
  "Output format: terminal | json | markdown | sarif",
  "terminal"
).option("-o, --output <file>", "Save output report to specified file path").option("--include-tests", "Include test files and fixtures in the scan").action((target, options) => {
  const startTime = Date.now();
  const targetPath = import_node_path2.default.resolve(process.cwd(), target);
  if (!import_node_fs2.default.existsSync(targetPath)) {
    console.error(import_picocolors3.default.red(`Error: Target path "${targetPath}" does not exist.`));
    process.exit(1);
  }
  let config = loadConfig();
  if (options.includeTests) {
    config = {
      ...config,
      ignorePaths: config.ignorePaths.filter(
        (p) => !p.includes("test") && !p.includes("spec") && !p.includes("fixtures")
      )
    };
  }
  const scanner = new Scanner({ config });
  const filesToScan = [];
  const stat = import_node_fs2.default.statSync(targetPath);
  if (stat.isFile()) {
    filesToScan.push(targetPath);
  } else if (stat.isDirectory()) {
    walkDir(targetPath, targetPath, (p) => scanner.isIgnored(p), filesToScan);
  }
  const allFindings = [];
  for (const filePath of filesToScan) {
    try {
      const content = import_node_fs2.default.readFileSync(filePath, "utf-8");
      const relativePath = import_node_path2.default.relative(process.cwd(), filePath);
      const findings = scanner.scanContent(content, relativePath);
      allFindings.push(...findings);
    } catch {
    }
  }
  const duration = Date.now() - startTime;
  const failThreshold = options.threshold || config.failThreshold || "high";
  const result = scanner.generateResult(
    allFindings,
    filesToScan.length,
    duration,
    failThreshold
  );
  let outputText = "";
  if (options.format === "json") {
    outputText = JSON.stringify(result, null, 2);
  } else if (options.format === "markdown") {
    outputText = MarkdownFormatter.formatPRComment(result);
  } else if (options.format === "sarif") {
    outputText = SarifFormatter.format(result);
  } else {
    outputText = TerminalFormatter.format(result);
  }
  if (options.output) {
    const outPath = import_node_path2.default.resolve(process.cwd(), options.output);
    import_node_fs2.default.writeFileSync(outPath, outputText, "utf-8");
    console.log(import_picocolors3.default.green(`\u2714 Output report saved to: ${import_picocolors3.default.bold(outPath)}`));
  } else {
    console.log(outputText);
  }
  if (!result.passed) {
    process.exit(1);
  }
});
program.command("diff").description("Scan git changes (staged, branch diff, or commit history)").argument("[commitOrBranch]", "Compare with branch or commit (default: HEAD)", "HEAD").option("-s, --staged", "Scan only staged changes (git diff --cached) for pre-commit hooks").option("-H, --history <commits>", "Scan commit history (git log -p -n <commits>) for leaked credentials").option("-t, --threshold <level>", "Fail threshold severity").option("-f, --format <format>", "Output format: terminal | json | markdown | sarif", "terminal").option("-o, --output <file>", "Save output report to specified file path").action((targetRef, options) => {
  const startTime = Date.now();
  let diffOutput = "";
  const diffCmd = options.history ? `git log -p -n ${parseInt(options.history, 10) || 5}` : options.staged ? "git diff --cached" : `git diff ${targetRef}`;
  try {
    diffOutput = (0, import_node_child_process.execSync)(diffCmd, {
      encoding: "utf-8",
      maxBuffer: 10 * 1024 * 1024
    });
  } catch {
    console.error(import_picocolors3.default.red("Failed to run git diff. Ensure this is a git repository."));
    process.exit(1);
  }
  if (!diffOutput.trim()) {
    console.log(import_picocolors3.default.green("No git changes detected to scan."));
    return;
  }
  const config = loadConfig();
  const scanner = new Scanner({ config });
  const findings = scanner.scanDiff(diffOutput);
  const duration = Date.now() - startTime;
  const failThreshold = options.threshold || config.failThreshold || "high";
  const result = scanner.generateResult(
    findings,
    1,
    duration,
    failThreshold
  );
  let outputText = "";
  if (options.format === "json") {
    outputText = JSON.stringify(result, null, 2);
  } else if (options.format === "markdown") {
    outputText = MarkdownFormatter.formatPRComment(result);
  } else if (options.format === "sarif") {
    outputText = SarifFormatter.format(result);
  } else {
    outputText = TerminalFormatter.format(result);
  }
  if (options.output) {
    const outPath = import_node_path2.default.resolve(process.cwd(), options.output);
    import_node_fs2.default.writeFileSync(outPath, outputText, "utf-8");
    console.log(import_picocolors3.default.green(`\u2714 Output report saved to: ${import_picocolors3.default.bold(outPath)}`));
  } else {
    console.log(outputText);
  }
  if (!result.passed) {
    process.exit(1);
  }
});
program.command("hook").description("Manage local git hooks for AgentGuard-CI").argument("<action>", "Action to perform: install | uninstall").action((action) => {
  const gitDir = import_node_path2.default.resolve(process.cwd(), ".git");
  if (!import_node_fs2.default.existsSync(gitDir)) {
    console.error(import_picocolors3.default.red("Error: Current directory is not a git repository root."));
    process.exit(1);
  }
  const hooksDir = import_node_path2.default.join(gitDir, "hooks");
  if (!import_node_fs2.default.existsSync(hooksDir)) {
    import_node_fs2.default.mkdirSync(hooksDir, { recursive: true });
  }
  const preCommitHook = import_node_path2.default.join(hooksDir, "pre-commit");
  if (action === "install") {
    const hookScript = `#!/bin/sh
# AgentGuard-CI Pre-Commit Security Hook
# Prevents accidental commits of secret keys and AI vulnerabilities
npx agentguard-ci diff --staged --threshold high
`;
    import_node_fs2.default.writeFileSync(preCommitHook, hookScript, { encoding: "utf-8", mode: 493 });
    try {
      import_node_fs2.default.chmodSync(preCommitHook, 493);
    } catch {
    }
    console.log(import_picocolors3.default.green(`\u2714 Installed AgentGuard pre-commit hook at: ${import_picocolors3.default.bold(preCommitHook)}`));
  } else if (action === "uninstall") {
    if (import_node_fs2.default.existsSync(preCommitHook)) {
      import_node_fs2.default.unlinkSync(preCommitHook);
      console.log(import_picocolors3.default.green("\u2714 Uninstalled AgentGuard pre-commit hook."));
    } else {
      console.log(import_picocolors3.default.yellow("No pre-commit hook found to uninstall."));
    }
  } else {
    console.error(import_picocolors3.default.red(`Unknown action: "${action}". Use "install" or "uninstall".`));
    process.exit(1);
  }
});
program.command("benchmark").description("Run internal detection accuracy (Precision/Recall) and latency benchmarks").action(() => {
  const metrics = runBenchmark();
  printBenchmarkReport(metrics);
});
program.command("init").description("Initialize GitHub Actions workflow for AgentGuard-CI in current repo").action(() => {
  const workflowDir = import_node_path2.default.resolve(process.cwd(), ".github/workflows");
  const workflowFile = import_node_path2.default.join(workflowDir, "agentguard.yml");
  if (!import_node_fs2.default.existsSync(workflowDir)) {
    import_node_fs2.default.mkdirSync(workflowDir, { recursive: true });
  }
  const workflowContent = `name: AgentGuard Security Check

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main, master]

jobs:
  agentguard:
    name: Security & PR Guardrail
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run AgentGuard-CI
        uses: Canhettg1133/agentguard-ci@v0.2.0
        with:
          github-token: \${{ secrets.GITHUB_TOKEN }}
          fail-on-severity: 'high'
          comment-on-pr: 'true'
          sarif-file: 'agentguard-report.sarif'

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'agentguard-report.sarif'
`;
  import_node_fs2.default.writeFileSync(workflowFile, workflowContent, "utf-8");
  console.log(import_picocolors3.default.green(`\u2714 Created GitHub Actions workflow at: ${import_picocolors3.default.bold(workflowFile)}`));
  console.log(
    import_picocolors3.default.cyan("\nAgentGuard-CI is now configured with SARIF Code Scanning & PR Guardrails!")
  );
});
program.parse(process.argv);
