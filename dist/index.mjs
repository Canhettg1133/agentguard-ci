// src/core/config.ts
import fs from "fs";
import path from "path";
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
    const fullPath = path.resolve(cwd, file);
    if (fs.existsSync(fullPath)) {
      try {
        const content = fs.readFileSync(fullPath, "utf-8");
        configOverrides = JSON.parse(content);
        break;
      } catch {
      }
    }
  }
  const gitignorePatterns = [];
  const gitignorePath = path.resolve(cwd, ".gitignore");
  if (fs.existsSync(gitignorePath)) {
    try {
      const lines = fs.readFileSync(gitignorePath, "utf-8").split(/\r?\n/);
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
  const agentguardIgnorePath = path.resolve(cwd, ".agentguardignore");
  if (fs.existsSync(agentguardIgnorePath)) {
    try {
      const lines = fs.readFileSync(agentguardIgnorePath, "utf-8").split(/\r?\n/);
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
import pc from "picocolors";
var TerminalFormatter = class {
  static severityBadge(sev) {
    switch (sev) {
      case "critical":
        return pc.bgRed(pc.white(pc.bold(" CRITICAL ")));
      case "high":
        return pc.bgRed(pc.black(" HIGH "));
      case "medium":
        return pc.bgYellow(pc.black(" MEDIUM "));
      case "low":
        return pc.bgCyan(pc.black(" LOW "));
      case "info":
        return pc.bgBlue(pc.white(" INFO "));
    }
  }
  static format(result) {
    const lines = [];
    lines.push("");
    lines.push(
      pc.bold(
        pc.cyan("\u{1F6E1}\uFE0F  AgentGuard-CI") + pc.gray(" - AI & Secret Security Guardrail")
      )
    );
    lines.push(pc.gray("\u2500".repeat(60)));
    if (result.findings.length === 0) {
      lines.push("");
      lines.push(
        pc.green(
          pc.bold("\u2728 All checks passed! No security or AI safety risks found.")
        )
      );
      lines.push(
        pc.gray(
          `Scanned ${result.scannedFiles} file(s) in ${result.durationMs}ms.`
        )
      );
      if (result.suppressedCount && result.suppressedCount > 0) {
        lines.push(
          pc.dim(`(${result.suppressedCount} issue(s) suppressed via inline comments)`)
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
      pc.bold(pc.red(`Found ${result.findings.length} security finding(s):`))
    );
    lines.push("");
    for (const [file, findings] of byFile.entries()) {
      lines.push(pc.bold(pc.underline(pc.white(`\u{1F4C4} ${file}`))));
      for (const f of findings) {
        const badge = this.severityBadge(f.severity);
        lines.push(
          `  ${badge} ${pc.bold(f.title)} ${pc.gray(`(Line ${f.line})`)}`
        );
        lines.push(`    ${pc.gray(f.description)}`);
        if (f.snippet) {
          lines.push(
            `    ${pc.dim("Code: ")} ${pc.italic(pc.yellow(f.snippet))}`
          );
        }
        if (f.entropy !== void 0) {
          lines.push(
            `    ${pc.dim("Shannon Entropy: ")} ${pc.magenta(
              `${f.entropy} bits`
            )}`
          );
        }
        if (f.suggestedFix) {
          lines.push(
            `    ${pc.green("\u{1F4A1} Fix: ")} ${pc.cyan(f.suggestedFix)}`
          );
        }
        lines.push("");
      }
    }
    lines.push(pc.gray("\u2500".repeat(60)));
    const riskColor = result.riskScore > 50 ? pc.red : result.riskScore > 20 ? pc.yellow : pc.green;
    lines.push(
      pc.bold("Risk Score: ") + riskColor(pc.bold(`${result.riskScore}/100`)) + pc.gray(` | Scanned in ${result.durationMs}ms`)
    );
    const s = result.summary;
    let summaryText = `Summary: ${pc.red(s.critical + " Critical")} | ${pc.red(
      s.high + " High"
    )} | ${pc.yellow(s.medium + " Medium")} | ${pc.cyan(
      s.low + " Low"
    )} | ${pc.blue(s.info + " Info")}`;
    if (result.suppressedCount && result.suppressedCount > 0) {
      summaryText += ` | ${pc.dim(`${result.suppressedCount} Suppressed`)}`;
    }
    lines.push(summaryText);
    if (!result.passed) {
      lines.push("");
      lines.push(
        pc.bgRed(
          pc.white(
            pc.bold(" \u274C CHECK FAILED: Critical or High severity issues detected. ")
          )
        )
      );
    } else {
      lines.push("");
      lines.push(pc.green(pc.bold(" \u2714 PASSED (Threshold met).")));
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

// src/review/offline-reviewer.ts
var OfflineReviewer = class {
  /**
   * Generates formatted inline PR review comments based on scan findings for offline CI runs.
   */
  static generateInlineComments(findings) {
    return findings.filter((f) => !f.suppressed).map((f) => ({
      path: f.file.replace(/\\/g, "/"),
      line: Math.max(1, f.line),
      body: this.buildCommentBody(f),
      side: "RIGHT"
    }));
  }
  /**
   * Builds an offline comment body for a single finding with remediation advice.
   */
  static buildCommentBody(f) {
    let body = `### \u{1F6E1}\uFE0F AgentGuard-CI: \`[${f.ruleId}]\` ${f.title}

`;
    body += `**Severity:** \`${f.severity.toUpperCase()}\` | **Category:** \`${f.category}\`

`;
    body += `${f.description}

`;
    if (f.suggestedFix) {
      body += `**Recommended Remediation:** ${f.suggestedFix}
`;
    }
    body += `
> _Automated guardrail via AgentGuard-CI (Rule \`${f.ruleId}\`)_`;
    return body;
  }
};

// src/review/ai-reviewer.ts
import OpenAI from "openai";
var AIReviewer = class {
  client = null;
  constructor(apiKey) {
    const key = apiKey || process.env.OPENAI_API_KEY;
    if (key) {
      this.client = new OpenAI({ apiKey: key });
    }
  }
  /**
   * Smart Diff Budgeting: Extracts prioritized context around detected findings
   * and preserves intact hunk boundaries up to maxChars (default 32,000 chars ~ 8,000 tokens).
   */
  budgetDiff(diffText, findings, maxChars = 32e3) {
    if (!diffText) return "";
    if (diffText.length <= maxChars) return diffText;
    const targetFiles = new Set(findings.map((f) => f.file.replace(/\\/g, "/")));
    const fileBlocks = diffText.split(/^diff --git /m);
    const prioritizedBlocks = [];
    const remainingBlocks = [];
    for (const rawBlock of fileBlocks) {
      if (!rawBlock.trim()) continue;
      const block = "diff --git " + rawBlock;
      const firstLine = block.split(/\r?\n/)[0] || "";
      const isTargeted = Array.from(targetFiles).some((tf) => firstLine.includes(tf));
      if (isTargeted) {
        prioritizedBlocks.push(block);
      } else {
        remainingBlocks.push(block);
      }
    }
    let result = "";
    for (const block of prioritizedBlocks) {
      if ((result + "\n" + block).length > maxChars) {
        const available = maxChars - result.length;
        if (available > 500) {
          const partial = block.slice(0, available);
          const lastNewline = partial.lastIndexOf("\n");
          result += "\n" + (lastNewline > 0 ? partial.slice(0, lastNewline) : partial);
          result += "\n\n[... Remaining hunks truncated for token budget ...]";
        }
        break;
      }
      result += (result ? "\n" : "") + block;
    }
    for (const block of remainingBlocks) {
      if ((result + "\n" + block).length > maxChars) {
        result += "\n\n[... Additional non-critical files omitted for token budget ...]";
        break;
      }
      result += "\n" + block;
    }
    return result || diffText.slice(0, maxChars);
  }
  /**
   * Performs dual-pass semantic verification & architectural analysis
   * using OpenAI Strict Structured Outputs (JSON Schema).
   */
  async reviewPullRequest(diffSummary, findings) {
    if (!this.client) {
      return null;
    }
    try {
      const budgetedDiff = this.budgetDiff(diffSummary, findings);
      const hasCandidateFindings = findings.length > 0;
      const prompt = `You are AgentGuard-CI's Principal Security Auditor & OpenAI Codex Reviewer.
Analyze the provided pull request code diff ${hasCandidateFindings ? "and verify the candidate security findings detected by static rules." : "and evaluate the security architecture of the code changes."}

${hasCandidateFindings ? `Tasks:
1. Review each candidate finding against full diff context.
2. Determine verdict: "CONFIRMED_VULNERABILITY" (true threat), "FALSE_POSITIVE" (benign or safe idiom), or "NEEDS_INVESTIGATION".
3. Provide confidence score (0.0 to 1.0) and succinct technical reasoning.
4. For confirmed issues, generate an exact, idiomatic GitHub Suggested Fix code replacement.
5. Provide actionable architectural security guidance for repository maintainers.

Candidate Findings:
${JSON.stringify(
        findings.map((f) => ({
          id: f.id,
          ruleId: f.ruleId,
          file: f.file,
          line: f.line,
          snippet: f.snippet,
          description: f.description
        })),
        null,
        2
      )}` : `Tasks:
1. Review the code changes for subtle application security risks, authorization issues, or insecure AI patterns.
2. Provide high-level architectural recommendations for maintainers.`}

Code Diff:
${budgetedDiff || "(Empty diff)"}`;
      const response = await this.client.chat.completions.create({
        model: process.env.AGENTGUARD_MODEL || "gpt-4o-mini",
        messages: [
          {
            role: "system",
            content: "You are a principal application security engineer and compiler security expert. You always return rigorous, structured JSON audits strictly conforming to the requested schema."
          },
          { role: "user", content: prompt }
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "security_review_report",
            strict: true,
            schema: {
              type: "object",
              properties: {
                summary: {
                  type: "string",
                  description: "High-level assessment of the PR security posture."
                },
                findingsAnalysis: {
                  type: "array",
                  description: "Verification analysis of each finding.",
                  items: {
                    type: "object",
                    properties: {
                      ruleId: { type: "string" },
                      line: { type: "integer" },
                      verdict: {
                        type: "string",
                        enum: [
                          "CONFIRMED_VULNERABILITY",
                          "FALSE_POSITIVE",
                          "NEEDS_INVESTIGATION"
                        ]
                      },
                      confidence: { type: "number" },
                      reasoning: { type: "string" },
                      suggestedPatch: {
                        type: "string",
                        description: "Remediation code replacement or instructions."
                      }
                    },
                    required: [
                      "ruleId",
                      "line",
                      "verdict",
                      "confidence",
                      "reasoning",
                      "suggestedPatch"
                    ],
                    additionalProperties: false
                  }
                },
                architecturalRecommendations: {
                  type: "array",
                  description: "Architectural security advice for repository maintainers.",
                  items: { type: "string" }
                }
              },
              required: [
                "summary",
                "findingsAnalysis",
                "architecturalRecommendations"
              ],
              additionalProperties: false
            }
          }
        },
        max_tokens: 2e3,
        temperature: 0.1
      });
      const rawJson = response.choices[0]?.message?.content;
      if (!rawJson) return null;
      const parsed = JSON.parse(rawJson);
      return {
        summary: parsed.summary || "AI Semantic Review completed.",
        findingsAnalysis: Array.isArray(parsed.findingsAnalysis) ? parsed.findingsAnalysis : [],
        architecturalRecommendations: Array.isArray(parsed.architecturalRecommendations) ? parsed.architecturalRecommendations : []
      };
    } catch (err) {
      return {
        summary: `AI Semantic Review could not complete: ${err.message || "API request failed"}`,
        findingsAnalysis: [],
        architecturalRecommendations: [
          "Verify your OPENAI_API_KEY and network connectivity to enable AI review."
        ]
      };
    }
  }
  /**
   * Helper to format structured AI review into clean GitHub Markdown.
   */
  formatReviewMarkdown(review) {
    const lines = [];
    lines.push("### \u{1F916} OpenAI Codex Semantic Review");
    lines.push("");
    lines.push(`> ${review.summary}`);
    lines.push("");
    if (review.findingsAnalysis.length > 0) {
      lines.push("#### \u{1F52C} AI Finding Verification");
      lines.push("");
      lines.push("| Rule | Line | Verdict | Confidence | AI Assessment |");
      lines.push("| :--- | :---: | :---: | :---: | :--- |");
      for (const item of review.findingsAnalysis) {
        const badge = item.verdict === "CONFIRMED_VULNERABILITY" ? "\u{1F534} `CONFIRMED`" : item.verdict === "FALSE_POSITIVE" ? "\u{1F7E2} `FALSE_POSITIVE`" : "\u{1F7E1} `INVESTIGATE`";
        const conf = `${Math.round(item.confidence * 100)}%`;
        lines.push(
          `| \`${item.ruleId}\` | \`${item.line}\` | ${badge} | ${conf} | ${item.reasoning.replace(
            /\|/g,
            "\\|"
          )} |`
        );
      }
      lines.push("");
      const patches = review.findingsAnalysis.filter((f) => f.suggestedPatch);
      if (patches.length > 0) {
        lines.push("<details><summary><b>\u{1F6E0}\uFE0F AI Suggested Code Fixes</b></summary>");
        lines.push("");
        for (const p of patches) {
          lines.push(`**Rule \`${p.ruleId}\` (Line ${p.line}):**`);
          lines.push("```suggestion");
          lines.push(p.suggestedPatch);
          lines.push("```");
          lines.push("");
        }
        lines.push("</details>");
        lines.push("");
      }
    }
    if (review.architecturalRecommendations.length > 0) {
      lines.push("#### \u{1F3DB}\uFE0F Architectural Best Practices");
      lines.push("");
      for (const rec of review.architecturalRecommendations) {
        lines.push(`* ${rec}`);
      }
      lines.push("");
    }
    return lines.join("\n");
  }
};
export {
  AIReviewer,
  DEFAULT_CONFIG,
  MarkdownFormatter,
  OfflineReviewer,
  SarifFormatter,
  Scanner,
  TerminalFormatter,
  aiSafetyRules,
  calculateShannonEntropy,
  isHighEntropy,
  loadConfig,
  mcpSafetyRules,
  secretRules
};
//# sourceMappingURL=index.mjs.map