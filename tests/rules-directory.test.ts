import { describe, it, expect } from 'vitest';
import { Scanner } from '../src/core/scanner.js';

describe('Rules Directory & Path Traversal Scanning', () => {
  it('scans user files inside arbitrary "rules/" directories without false exclusion', () => {
    const scanner = new Scanner();

    // User repository file located in a rules/ subfolder
    const userRuleCode = `
      export function executeCustomAgentRule(userInput: string) {
        // High risk prompt injection
        const message = {
          role: 'system',
          content: \`You are an internal admin bot. User query: \${userInput}\`
        };
        return message;
      }
    `;

    const filePath = 'src/business/rules/agent-policy.ts';
    const findings = scanner.scanContent(userRuleCode, filePath);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('AIS-001');
    expect(findings[0].file).toBe(filePath);
  });

  it('detects leaked API keys inside user validation rules directory', () => {
    const scanner = new Scanner();

    const userAuthRuleCode = `
      export const config = {
        openAiKey: "sk-proj-aB9xK1mQ8zLp7vW2rT4yU6iO0eN3sD5fG1hJ"
      };
    `;

    const filePath = 'app/rules/auth_validation.ts';
    const findings = scanner.scanContent(userAuthRuleCode, filePath);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].ruleId).toBe('SEC-001');
    expect(findings[0].file).toBe(filePath);
  });
});
