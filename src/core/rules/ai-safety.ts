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
  if (
    filePath.includes('/rules/') ||
    filePath.includes('\\rules\\') ||
    filePath.includes('/fixtures/') ||
    filePath.includes('\\fixtures\\') ||
    filePath.endsWith('fixtures.ts') ||
    filePath.includes('.test.') ||
    filePath.includes('.spec.')
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

export const aiSafetyRules: Rule[] = [
  {
    id: 'AIS-001',
    name: 'Prompt Injection Risk: Direct User Input in System Prompt',
    description:
      'Directly concatenating untrusted user input into the LLM system prompt can allow prompt injection attacks to override instructions.',
    severity: 'high',
    category: 'ai-safety',
    match: (content: string, filePath: string): Finding[] => {
      if (!shouldScan(filePath)) return [];
      const regexes = isPython(filePath)
        ? [
            /(?:['"]role['"]\s*:\s*['"]system['"][\s\S]*?['"]content['"]\s*:\s*(?:f['"][^'"]*\{[^}]*(?:user|input|query|prompt|req|msg)[^}]*\}[^'"]*['"]|['"][^'"]*['"]\s*\+\s*(?:user|input|query|prompt|req))|['"]content['"]\s*:\s*f['"][^'"]*\{[^}]*(?:user|input|query|prompt|req|msg)[^}]*\}[^'"]*['"][\s\S]*?['"]role['"]\s*:\s*['"]system['"])/gi,
            /(?:system_prompt|systemPrompt)\s*=\s*f['"][^'"]*\{[^}]*(?:user|input|query|prompt)[^}]*\}/gi,
            /SystemMessage\s*\(\s*(?:content\s*=\s*)?f['"][^'"]*\{[^}]*(?:user|input|query|prompt)[^}]*\}/gi,
          ]
        : [
            /(?:(?:role\s*:\s*['"]system['"][\s\S]*?content\s*:\s*`[^`]*\$\{[^}]*(?:req|input|user|query|body|param|prompt|text|msg)[^}]*\}`)|(?:content\s*:\s*`[^`]*\$\{[^}]*(?:req|input|user|query|body|param|prompt|text|msg)[^}]*\}`[\s\S]*?role\s*:\s*['"]system['"]))/gi,
            /(?:system_prompt|systemPrompt)\s*=\s*`[^`]*\$\{[^}]*(?:user|input|query|req|prompt)[^}]*\}`/gi,
            /new\s+SystemMessage\s*\(\s*`[^`]*\$\{[^}]*(?:req|input|user|query|body|param|prompt|text|msg)[^}]*\}`/gi,
          ];

      const findings: Finding[] = [];
      for (const regex of regexes) {
        let match: RegExpExecArray | null;
        while ((match = regex.exec(content)) !== null) {
          const { line, column, snippet } = getLineAndSnippet(content, match.index);
          findings.push({
            id: `AIS-001-${line}`,
            ruleId: 'AIS-001',
            title: 'Prompt Injection Risk: Direct User Input in System Prompt',
            description:
              'Directly concatenating untrusted user input into the LLM system prompt can allow prompt injection attacks to override instructions.',
            severity: 'high',
            category: 'ai-safety',
            file: filePath,
            line,
            column,
            snippet,
            suggestedFix:
              'Keep the system prompt static and isolated. Pass user input strictly inside the "user" role message.',
          });
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
            file: filePath,
            line,
            column,
            snippet,
            suggestedFix:
              'Execute generated code in an isolated container or use a secured sandbox runtime instead of direct eval/exec.',
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
            file: filePath,
            line,
            column,
            snippet,
            suggestedFix:
              'Use parameterized spawn() or execFile() with an array of arguments and shell: false.',
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
    match: (content: string, filePath: string): Finding[] => {
      if (!shouldScan(filePath)) return [];
      const triggerRegex = /(?:openai|client)\.(?:chat\.completions|completions)\.create\s*\(/g;
      const findings: Finding[] = [];
      let match: RegExpExecArray | null;

      while ((match = triggerRegex.exec(content)) !== null) {
        const openParenIndex = match.index + match[0].length - 1;
        const argsBlock = extractParenthesizedArgs(content, openParenIndex);
        if (!/max_tokens|max_completion_tokens/.test(argsBlock)) {
          const { line, column, snippet } = getLineAndSnippet(content, match.index);
          findings.push({
            id: `AIS-004-${line}`,
            ruleId: 'AIS-004',
            title: 'Unbounded Token Generation (Cost Explosion Risk)',
            description:
              'LLM API call does not define max_tokens or max_completion_tokens. In open-source bots or agents, this can lead to infinite loops or unexpected billing spikes.',
            severity: 'medium',
            category: 'ai-safety',
            file: filePath,
            line,
            column,
            snippet,
            suggestedFix:
              'Always specify "max_completion_tokens" or "max_tokens" to safeguard against run-away generation costs.',
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
      'Unsafe deserialization of agent memory states or cache allows arbitrary object injection.',
    severity: 'high',
    category: 'ai-safety',
    match: (content: string, filePath: string): Finding[] => {
      if (!shouldScan(filePath)) return [];
      const regex = /\b(?:pickle\.loads|deserialize|unserialize)\s*\([^)]*(?:memory|cache|agent_state)/gi;
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
          file: filePath,
          line,
          column,
          snippet,
          suggestedFix:
            'Use safe data interchange formats like JSON or Protocol Buffers for agent state persistence.',
        });
      }
      return findings;
    },
  },
];
