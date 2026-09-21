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

const isInternalRuleOrFixture = (filePath: string): boolean => {
  const norm = filePath.replace(/\\/g, '/');
  return (
    norm.endsWith('src/core/rules/mcp-safety.ts') ||
    norm.endsWith('fixtures.ts')
  );
};

export const mcpSafetyRules: Rule[] = [
  {
    id: 'MCP-001',
    name: 'Unrestricted Filesystem Exposure in MCP Server Configuration',
    description:
      'MCP configuration grants arbitrary access to root directories (/ or C:\\) or entire home directories, enabling LLM agents to read or overwrite critical OS and system files.',
    severity: 'critical',
    category: 'mcp',
    cweId: 'CWE-22',
    owaspCategory: 'MCP Security: Filesystem Isolation',
    match: (content: string, filePath: string): Finding[] => {
      if (isInternalRuleOrFixture(filePath)) return [];
      if (!/(?:mcp|claude_desktop_config|agent_config|tools).*\.(json|yaml|yml|ts|js)$/i.test(filePath)) {
        return [];
      }

      const findings: Finding[] = [];
      const regex = /["']?(?:allowedDirectories|allow_paths|roots)["']?\s*:\s*(?:\[[^\]]*["'](?:\/|[A-Za-z]:[\\\/]|\~|\/root|\/etc|\/home|\/Users|\/var)["'][^\]]*\]|(?:\r?\n\s*-\s*["']?(?:\/|[A-Za-z]:[\\\/]|\~|\/root|\/etc|\/home|\/Users|\/var)["']?)+)/gi;
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const { line, column, snippet } = getLineAndSnippet(content, match.index);
        findings.push({
          id: `MCP-001-${line}`,
          ruleId: 'MCP-001',
          title: 'Unrestricted Filesystem Exposure in MCP Server Configuration',
          description:
            'MCP configuration exposes the root filesystem or user home directory. Any prompt injection can read SSH keys, OS credentials, or destroy system files.',
          severity: 'critical',
          category: 'mcp',
          cweId: 'CWE-22',
          owaspCategory: 'MCP Security: Filesystem Isolation',
          file: filePath,
          line,
          column,
          snippet,
          suggestedFix:
            'Restrict "allowedDirectories" to dedicated project subdirectories (e.g. "./workspace" or "./data") instead of root or home.',
          referenceUrl: 'https://modelcontextprotocol.io/docs/concepts/resources',
        });
      }

      return findings;
    },
  },
  {
    id: 'MCP-002',
    name: 'Arbitrary Shell Execution in MCP Tool Definition',
    description:
      'MCP tool definitions enabling "shell: true" or directly interpolating arguments into bash/sh create Remote Code Execution (RCE) vectors via prompt injection.',
    severity: 'high',
    category: 'mcp',
    cweId: 'CWE-78',
    owaspCategory: 'MCP Security: Tool Execution',
    match: (content: string, filePath: string): Finding[] => {
      if (isInternalRuleOrFixture(filePath)) return [];
      if (!/\.(ts|js|py|mjs|cjs|json)$/i.test(filePath)) return [];

      const findings: Finding[] = [];
      const regex = /(?:shell\s*:\s*true|["']shell["']\s*:\s*true|\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{[^}]*args)/gi;
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const { line, column, snippet } = getLineAndSnippet(content, match.index);
        findings.push({
          id: `MCP-002-${line}`,
          ruleId: 'MCP-002',
          title: 'Arbitrary Shell Execution in MCP Tool Definition',
          description:
            'MCP tool accepts arguments and executes them in a shell context without argument escaping.',
          severity: 'high',
          category: 'mcp',
          cweId: 'CWE-78',
          owaspCategory: 'MCP Security: Tool Execution',
          file: filePath,
          line,
          column,
          snippet,
          suggestedFix:
            'Pass arguments as an immutable array using execFile() or spawn() with shell: false.',
          referenceUrl: 'https://modelcontextprotocol.io/docs/concepts/tools',
        });
      }

      return findings;
    },
  },
  {
    id: 'MCP-003',
    name: 'Hardcoded Secret in MCP Server Environment Configuration',
    description:
      'MCP config files contain plaintext API keys or access tokens embedded in the "env" section.',
    severity: 'critical',
    category: 'mcp',
    cweId: 'CWE-798',
    owaspCategory: 'MCP Security: Credential Exposure',
    match: (content: string, filePath: string): Finding[] => {
      if (isInternalRuleOrFixture(filePath)) return [];
      if (!/(?:mcp|claude_desktop_config|agent_config).*\.(json|yaml|yml)$/i.test(filePath)) return [];

      const findings: Finding[] = [];
      const regex = /(?:"env"\s*:\s*\{[\s\S]*?"(?:[A-Z0-9_]*(?:KEY|TOKEN|SECRET))"\s*:\s*"([a-zA-Z0-9_\-\.]{20,})"|\benv:\s*(?:\r?\n\s+(?:[A-Z0-9_]*(?:KEY|TOKEN|SECRET)):\s*["']?([a-zA-Z0-9_\-\.]{20,})["']?))/gi;
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const token = match[1] || match[2];
        if (!token || token.includes('${') || token.includes('process.env')) {
          continue;
        }

        const secretIndex = match.index + match[0].lastIndexOf(token);
        const { line, column, snippet } = getLineAndSnippet(content, secretIndex);
        const masked = token.slice(0, 4) + '...' + token.slice(-4);
        findings.push({
          id: `MCP-003-${line}`,
          ruleId: 'MCP-003',
          title: 'Hardcoded Secret in MCP Server Environment Configuration',
          description:
            'Hardcoded API credentials in MCP server configuration will leak to version control upon commit.',
          severity: 'critical',
          category: 'mcp',
          cweId: 'CWE-798',
          owaspCategory: 'MCP Security: Credential Exposure',
          file: filePath,
          line,
          column,
          snippet: snippet.replace(token, masked),
          suggestedFix:
            'Inject secrets dynamically via system environment variables rather than static JSON configuration files.',
          referenceUrl: 'https://modelcontextprotocol.io/docs/tools/debugging',
        });
      }

      return findings;
    },
  },
  {
    id: 'MCP-004',
    name: 'SSRF Vulnerability in MCP Tool Server',
    description:
      'MCP tool handler fetches arbitrary URLs without restricting loopback (127.0.0.1) or cloud metadata endpoints (169.254.169.254).',
    severity: 'high',
    category: 'mcp',
    cweId: 'CWE-918',
    owaspCategory: 'MCP Security: SSRF in Tools',
    match: (content: string, filePath: string): Finding[] => {
      if (isInternalRuleOrFixture(filePath)) return [];
      if (!/\.(ts|js|py|mjs|cjs)$/i.test(filePath)) return [];

      const findings: Finding[] = [];
      const regex =
        /\b(?:fetch|axios\.(?:get|post)|requests\.(?:get|post)|http\.(?:get|request))\s*\(\s*(?:args|toolArgs|tool_input|input|params)\.(?:url|endpoint|target)/gi;
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const { line, column, snippet } = getLineAndSnippet(content, match.index);
        findings.push({
          id: `MCP-004-${line}`,
          ruleId: 'MCP-004',
          title: 'SSRF Vulnerability in MCP Tool Server',
          description:
            'MCP tool takes user/model supplied URL and issues network requests without private IP filtering (risk of internal network pivoting and cloud credential theft).',
          severity: 'high',
          category: 'mcp',
          cweId: 'CWE-918',
          owaspCategory: 'MCP Security: SSRF in Tools',
          file: filePath,
          line,
          column,
          snippet,
          suggestedFix:
            'Validate outbound URLs against private CIDR ranges (127.0.0.1, 10.0.0.0/8) and cloud metadata endpoint (169.254.169.254).',
          referenceUrl: 'https://modelcontextprotocol.io/docs/concepts/tools',
        });
      }

      return findings;
    },
  },
  {
    id: 'MCP-005',
    name: 'Unconstrained Tool Input Schema in MCP Server',
    description:
      'MCP tool definition defines an empty or unvalidated inputSchema without properties, allowing arbitrary payload injection.',
    severity: 'medium',
    category: 'mcp',
    cweId: 'CWE-20',
    owaspCategory: 'MCP Security: Input Validation',
    match: (content: string, filePath: string): Finding[] => {
      if (isInternalRuleOrFixture(filePath)) return [];
      if (!/(?:mcp|tool|server).*\.(ts|js|json)$/i.test(filePath)) return [];

      const findings: Finding[] = [];
      const regex =
        /inputSchema\s*:\s*\{\s*(?:type\s*:\s*["']object["']\s*)?\}/gi;
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const { line, column, snippet } = getLineAndSnippet(content, match.index);
        findings.push({
          id: `MCP-005-${line}`,
          ruleId: 'MCP-005',
          title: 'Unconstrained Tool Input Schema in MCP Server',
          description:
            'MCP tool registered with empty or unconstrained inputSchema. Tool arguments will not be validated against type and bounds.',
          severity: 'medium',
          category: 'mcp',
          cweId: 'CWE-20',
          owaspCategory: 'MCP Security: Input Validation',
          file: filePath,
          line,
          column,
          snippet,
          suggestedFix:
            'Specify explicit properties, data types, and required fields in inputSchema (or use zodToJsonSchema).',
          referenceUrl: 'https://modelcontextprotocol.io/docs/concepts/tools',
        });
      }

      return findings;
    },
  },
];
