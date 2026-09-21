import { Finding, Rule } from '../types.js';

function getLineAndSnippet(
  content: string,
  matchIndex: number
): { line: number; column: number; snippet: string } {
  const upToMatch = content.slice(0, matchIndex);
  const lines = upToMatch.split(/\r?\n/);
  const line = lines.length;
  const column = lines[lines.length - 1].length + 1;

  const allLines = content.split(/\r?\n/);
  const snippet = (allLines[line - 1] || '').trim();

  return { line, column, snippet };
}

const shouldScan = (filePath: string): boolean => {
  if (!/\.(ts|js|py|mjs|cjs|jsx|tsx)$/i.test(filePath)) return false;
  const norm = filePath.replace(/\\/g, '/');
  if (
    norm.endsWith('src/core/rules/ai-safety.ts') ||
    norm.endsWith('fixtures.ts')
  ) {
    return false;
  }
  return true;
};

const isPython = (filePath: string): boolean => /\.py$/i.test(filePath);

function extractParenthesizedArgs(content: string, openParenIndex: number): string {
  let depth = 0;
  let inString: string | null = null;
  for (let i = openParenIndex; i < content.length; i++) {
    const char = content[i];
    const prev = i > 0 ? content[i - 1] : '';

    if (inString) {
      if (char === inString && prev !== '\\') {
        inString = null;
      }
    } else {
      if (char === '"' || char === "'" || char === '`') {
        inString = char;
      } else if (char === '(') {
        depth++;
      } else if (char === ')') {
        depth--;
        if (depth === 0) {
          return content.slice(openParenIndex + 1, i);
        }
      }
    }
  }
  return content.slice(openParenIndex + 1);
}

function isSafeIdentifier(expr: string): boolean {
  const trimmed = expr.trim();
  // Safe identifiers (user ID, username, count, status, style, etc.)
  const safeIdRegex =
    /^(?:[a-zA-Z0-9_.]+\.)?(?:id|userId|user_id|username|user_name|email|user_email|userRole|role|status|style|textStyle|count|paramCount|theme|version|created_at|timestamp)$/i;
  return safeIdRegex.test(trimmed);
}

function containsUntrustedUserInput(expr: string): boolean {
  const trimmed = expr.trim();
  if (isSafeIdentifier(trimmed)) {
    return false;
  }
  const untrustedPatterns = [
    /(?:req|request)\.(?:body|query|params|data|json)/i,
    /(?:input|query|prompt|message|msg)/i,
  ];
  return untrustedPatterns.some((p) => p.test(trimmed));
}

export const aiSafetyRules: Rule[] = [
  {
    id: 'AIS-001',
    name: 'Prompt Injection Risk: Direct User Input in System Prompt',
    description:
      'Directly concatenating untrusted user input into the LLM system prompt can allow prompt injection attacks to override instructions.',
    severity: 'high',
    category: 'ai-safety',
    cweId: 'CWE-94',
    owaspCategory: 'LLM01: Prompt Injection',
    match: (content: string, filePath: string): Finding[] => {
      if (!shouldScan(filePath)) return [];
      const findings: Finding[] = [];

      if (isPython(filePath)) {
        // Python f-string or string concatenation with system role
        const pySystemPattern =
          /(?:['"]role['"]\s*:\s*['"]system['"][^{}]*?['"]content['"]\s*:\s*(?:f"""([\s\S]*?)"""|f'''([\s\S]*?)'''|f['"]([^'"]*)['"])|['"]content['"]\s*:\s*(?:f"""([\s\S]*?)"""|f'''([\s\S]*?)'''|f['"]([^'"]*)['"])[^{}]*?['"]role['"]\s*:\s*['"]system['"]|(?:system_prompt|systemPrompt)\s*=\s*(?:f"""([\s\S]*?)"""|f'''([\s\S]*?)'''|f['"]([^'"]*)['"])|SystemMessage\s*\(\s*(?:content\s*=\s*)?(?:f"""([\s\S]*?)"""|f'''([\s\S]*?)'''|f['"]([^'"]*)['"]))/gi;
        let match: RegExpExecArray | null;
        while ((match = pySystemPattern.exec(content)) !== null) {
          const innerFString = match.slice(1).find((val) => Boolean(val)) || '';
          // Extract variables inside { ... }
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
                ruleId: 'AIS-001',
                title: 'Prompt Injection Risk: Direct User Input in System Prompt',
                description:
                  'Directly concatenating untrusted user input into the LLM system prompt can allow prompt injection attacks to override instructions.',
                severity: 'high',
                category: 'ai-safety',
                cweId: 'CWE-94',
                owaspCategory: 'LLM01: Prompt Injection',
                file: filePath,
                line,
                column,
                snippet,
                suggestedFix:
                  'Keep the system prompt static and isolated. Pass user input strictly inside the "user" role message.',
                referenceUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
              });
            }
          }
        }
      } else {
        // JavaScript / TypeScript template literals in system prompt
        const jsSystemPattern =
          /(?:(?:role\s*:\s*['"]system['"][^{}]*?content\s*:\s*`([^`]*)`)|(?:content\s*:\s*`([^`]*)`[^{}]*?role\s*:\s*['"]system['"])|(?:system_prompt|systemPrompt)\s*=\s*`([^`]*)`|new\s+SystemMessage\s*\(\s*(?:content\s*=\s*)?`([^`]*)`)/gi;
        let match: RegExpExecArray | null;
        while ((match = jsSystemPattern.exec(content)) !== null) {
          const innerTemplate = match.slice(1).find((val) => Boolean(val)) || '';
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
                ruleId: 'AIS-001',
                title: 'Prompt Injection Risk: Direct User Input in System Prompt',
                description:
                  'Directly concatenating untrusted user input into the LLM system prompt can allow prompt injection attacks to override instructions.',
                severity: 'high',
                category: 'ai-safety',
                cweId: 'CWE-94',
                owaspCategory: 'LLM01: Prompt Injection',
                file: filePath,
                line,
                column,
                snippet,
                suggestedFix:
                  'Keep the system prompt static and isolated. Pass user input strictly inside the "user" role message.',
                referenceUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
              });
            }
          }
        }
      }

      return findings;
    },
  },
  {
    id: 'AIS-002',
    name: 'Unsafe Dynamic Code Execution (Eval/Exec on AI Output)',
    description:
      'Executing AI-generated code directly with eval() or exec() without a secure sandbox poses severe RCE risks.',
    severity: 'high',
    category: 'ai-safety',
    cweId: 'CWE-95',
    owaspCategory: 'LLM02: Sensitive Information Disclosure',
    match: (content: string, filePath: string): Finding[] => {
      if (!shouldScan(filePath)) return [];
      const regexes = isPython(filePath)
        ? [
            /\b(?:exec|eval)\s*\([^)]*(?:response|ai_output|completion|generated_code|output|content|msg|aiOutput)/gi,
          ]
        : [
            /\b(?:eval|new\s+Function|vm\.runInThisContext)\s*\([^)]*(?:response|aiOutput|completion|result|generatedCode|content|msg)/gi,
          ];
      const findings: Finding[] = [];

      for (const regex of regexes) {
        let match: RegExpExecArray | null;
        while ((match = regex.exec(content)) !== null) {
          const { line, column, snippet } = getLineAndSnippet(content, match.index);
          findings.push({
            id: `AIS-002-${line}`,
            ruleId: 'AIS-002',
            title: 'Unsafe Dynamic Code Execution (Eval/Exec on AI Output)',
            description:
              'Executing AI-generated code directly with eval() or exec() without a secure sandbox poses severe RCE risks.',
            severity: 'high',
            category: 'ai-safety',
            cweId: 'CWE-95',
            owaspCategory: 'LLM02: Sensitive Information Disclosure',
            file: filePath,
            line,
            column,
            snippet,
            suggestedFix:
              'Execute generated code in an isolated container or use a secured sandbox runtime instead of direct eval/exec.',
            referenceUrl: 'https://cwe.mitre.org/data/definitions/95.html',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AIS-003',
    name: 'Insecure Command Injection in Agent Tool Execution',
    description:
      'Passing unsanitized AI tool arguments or user strings into system shell execution leads to remote command injection.',
    severity: 'high',
    category: 'ai-safety',
    cweId: 'CWE-78',
    owaspCategory: 'LLM02: Sensitive Information Disclosure',
    match: (content: string, filePath: string): Finding[] => {
      if (!shouldScan(filePath)) return [];
      const regexes = isPython(filePath)
        ? [
            /\b(?:os\.system|subprocess\.run|subprocess\.Popen)\s*\([^)]*(?:f['"][^'"]*\{[^}]*(?:input|command|toolArgs|query|args|cmd)[^}]*\}|shell\s*=\s*True)/gi,
          ]
        : [
            /\b(?:exec|execSync|spawnSync)\s*\(\s*`[^`]*\$\{[^}]*(?:input|command|toolArgs|query|args|cmd|path)[^}]*\}/gi,
          ];
      const findings: Finding[] = [];

      for (const regex of regexes) {
        let match: RegExpExecArray | null;
        while ((match = regex.exec(content)) !== null) {
          const { line, column, snippet } = getLineAndSnippet(content, match.index);
          findings.push({
            id: `AIS-003-${line}`,
            ruleId: 'AIS-003',
            title: 'Insecure Command Injection in Agent Tool Execution',
            description:
              'Passing unsanitized AI tool arguments or user strings into system shell execution leads to remote command injection.',
            severity: 'high',
            category: 'ai-safety',
            cweId: 'CWE-78',
            owaspCategory: 'LLM02: Sensitive Information Disclosure',
            file: filePath,
            line,
            column,
            snippet,
            suggestedFix:
              'Use parameterized spawn() or execFile() with an array of arguments and shell: false.',
            referenceUrl: 'https://cwe.mitre.org/data/definitions/78.html',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AIS-004',
    name: 'Unbounded Token Generation (Cost Explosion Risk)',
    description:
      'LLM API call does not define max_tokens or max_completion_tokens. In open-source bots or agents, this can lead to infinite loops or unexpected billing spikes.',
    severity: 'medium',
    category: 'ai-safety',
    cweId: 'CWE-400',
    owaspCategory: 'LLM04: Model Denial of Service',
    match: (content: string, filePath: string): Finding[] => {
      if (!shouldScan(filePath)) return [];
      const triggerRegex = /(?:openai|client)\.(?:chat\.completions|completions)\.create\s*\(/g;
      const findings: Finding[] = [];
      let match: RegExpExecArray | null;

      while ((match = triggerRegex.exec(content)) !== null) {
        const openParenIndex = match.index + match[0].length - 1;
        const argsBlock = extractParenthesizedArgs(content, openParenIndex);
        const trimmedArgs = argsBlock.trim();

        // If parameters are spread (...options) or passed as a variable identifier, skip false positive
        const hasSpreadOrVar = /\.\.\.|^[a-zA-Z0-9_]+$/.test(trimmedArgs);
        const hasTokenLimit = /max_tokens|max_completion_tokens/.test(argsBlock);

        if (!hasTokenLimit && !hasSpreadOrVar) {
          const { line, column, snippet } = getLineAndSnippet(content, match.index);
          findings.push({
            id: `AIS-004-${line}`,
            ruleId: 'AIS-004',
            title: 'Unbounded Token Generation (Cost Explosion Risk)',
            description:
              'LLM API call does not define max_tokens or max_completion_tokens. In open-source bots or agents, this can lead to infinite loops or unexpected billing spikes.',
            severity: 'medium',
            category: 'ai-safety',
            cweId: 'CWE-400',
            owaspCategory: 'LLM04: Model Denial of Service',
            file: filePath,
            line,
            column,
            snippet,
            suggestedFix:
              'Always specify "max_completion_tokens" or "max_tokens" to safeguard against run-away generation costs.',
            referenceUrl: 'https://cwe.mitre.org/data/definitions/400.html',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AIS-005',
    name: 'Unsafe Object Deserialization in AI Memory / Cache',
    description:
      'Unsafe deserialization of agent memory states or cache allows arbitrary object injection and remote code execution.',
    severity: 'high',
    category: 'ai-safety',
    cweId: 'CWE-502',
    owaspCategory: 'LLM02: Sensitive Information Disclosure',
    match: (content: string, filePath: string): Finding[] => {
      if (!shouldScan(filePath)) return [];
      const regex =
        /\b(?:pickle\.loads|yaml\.unsafe_load|marshal\.loads|deserialize|unserialize)\s*\([^)]*(?:memory|cache|agent_state|history|session)/gi;
      const findings: Finding[] = [];
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const { line, column, snippet } = getLineAndSnippet(content, match.index);
        findings.push({
          id: `AIS-005-${line}`,
          ruleId: 'AIS-005',
          title: 'Unsafe Object Deserialization in AI Memory / Cache',
          description:
            'Unsafe deserialization of agent memory states or cache allows arbitrary object injection.',
          severity: 'high',
          category: 'ai-safety',
          cweId: 'CWE-502',
          owaspCategory: 'LLM02: Sensitive Information Disclosure',
          file: filePath,
          line,
          column,
          snippet,
          suggestedFix:
            'Use safe data interchange formats like JSON or Protocol Buffers for agent state persistence.',
          referenceUrl: 'https://cwe.mitre.org/data/definitions/502.html',
        });
      }
      return findings;
    },
  },
  {
    id: 'AIS-006',
    name: 'Vector Database Credential Leak & Insecure Storage',
    description:
      'Hardcoded Vector DB credentials (Pinecone, Qdrant, ChromaDB, Weaviate) or unencrypted vector storage endpoints.',
    severity: 'high',
    category: 'ai-safety',
    cweId: 'CWE-798',
    owaspCategory: 'LLM02: Sensitive Information Disclosure',
    match: (content: string, filePath: string): Finding[] => {
      if (!shouldScan(filePath)) return [];
      const findings: Finding[] = [];
      const seenLines = new Set<number>();
      const regexes = [
        /\b(pcsk_[a-zA-Z0-9_-]{32,})\b/g, // Pinecone API key
        /\b(?:new\s+Pinecone|PineconeClient)\s*\(\s*\{[^}]*apiKey\s*:\s*["']([a-zA-Z0-9_-]{20,})["']/gi,
        /\b(?:new\s+QdrantClient|QdrantClient)\s*\(\s*\{[^}]*apiKey\s*:\s*["']([a-zA-Z0-9_-]{20,})["']/gi,
        /\b(?:weaviate\.client)\s*\(\s*\{[^}]*apiKey\s*:\s*["']([a-zA-Z0-9_-]{20,})["']/gi,
      ];

      for (const regex of regexes) {
        let match: RegExpExecArray | null;
        while ((match = regex.exec(content)) !== null) {
          const key = match[1] || match[0];
          if (key.includes('${') || key.includes('process.env')) continue;
          if (key.startsWith('pcsk_') && regex !== regexes[0]) continue;

          const { line, column, snippet } = getLineAndSnippet(content, match.index);
          if (seenLines.has(line)) continue;
          seenLines.add(line);

          const masked = key.length > 8 ? key.slice(0, 4) + '...' + key.slice(-4) : '***';
          findings.push({
            id: `AIS-006-${line}`,
            ruleId: 'AIS-006',
            title: 'Vector Database Credential Leak & Insecure Storage',
            description:
              'Hardcoded Vector DB credentials detected. Unauthorized access to vector databases can lead to data exfiltration and RAG poisoning.',
            severity: 'high',
            category: 'ai-safety',
            cweId: 'CWE-798',
            owaspCategory: 'LLM02: Sensitive Information Disclosure',
            file: filePath,
            line,
            column,
            snippet: snippet.replace(key, masked),
            suggestedFix:
              'Store vector database API keys in environment variables (e.g. PINECONE_API_KEY, QDRANT_API_KEY).',
            referenceUrl: 'https://cwe.mitre.org/data/definitions/798.html',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AIS-007',
    name: 'Unprotected SSRF in AI Agent Tool Execution',
    description:
      'AI Agent tool fetches arbitrary URLs provided by model output or prompt arguments without loopback or cloud metadata IP shielding.',
    severity: 'high',
    category: 'ai-safety',
    cweId: 'CWE-918',
    owaspCategory: 'LLM02: Sensitive Information Disclosure',
    match: (content: string, filePath: string): Finding[] => {
      if (!shouldScan(filePath)) return [];
      const findings: Finding[] = [];
      const seenLines = new Set<number>();
      const regexes = isPython(filePath)
        ? [
            /\b(?:requests\.(?:get|post)|httpx\.(?:get|post)|urllib\.request\.urlopen)\s*\([^)]*(?:tool_input|args|params|toolArgs|query|url)[^)]*\)/gi,
          ]
        : [
            /\b(?:fetch|axios\.(?:get|post)|http\.(?:get|request))\s*\([^)]*(?:toolInput|toolArgs|args|params)\.(?:url|endpoint|target)[^)]*\)/gi,
          ];

      for (const regex of regexes) {
        let match: RegExpExecArray | null;
        while ((match = regex.exec(content)) !== null) {
          const { line, column, snippet } = getLineAndSnippet(content, match.index);
          if (seenLines.has(line)) continue;
          seenLines.add(line);

          findings.push({
            id: `AIS-007-${line}`,
            ruleId: 'AIS-007',
            title: 'Unprotected SSRF in AI Agent Tool Execution',
            description:
              'Agent tool fetches user/model supplied URLs without validating against private IP ranges (127.0.0.1, 10.0.0.0/8) or cloud metadata endpoints (169.254.169.254).',
            severity: 'high',
            category: 'ai-safety',
            cweId: 'CWE-918',
            owaspCategory: 'LLM02: Sensitive Information Disclosure',
            file: filePath,
            line,
            column,
            snippet,
            suggestedFix:
              'Implement strict URL whitelist validation and block internal/loopback IPs and 169.254.169.254 before making network requests in agent tools.',
            referenceUrl: 'https://cwe.mitre.org/data/definitions/918.html',
          });
        }
      }
      return findings;
    },
  },
];
