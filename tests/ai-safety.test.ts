import { describe, it, expect } from 'vitest';
import { aiSafetyRules } from '../src/core/rules/ai-safety.js';

describe('AI Safety & Prompt Security Rule Engine', () => {
  it('detects prompt injection vulnerability when user input is concatenated into system prompt', () => {
    const code = `
      const response = await openai.chat.completions.create({
        messages: [
          { role: 'system', content: \`You are an assistant. User instructions: \${req.body.userInput}\` }
        ]
      });
    `;

    const rule = aiSafetyRules.find((r) => r.id === 'AIS-001')!;
    const findings = rule.match(code, 'src/chat.ts');

    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].ruleId).toBe('AIS-001');
  });

  it('detects unsafe dynamic code execution on AI generated output', () => {
    const code = `
      const aiOutput = await agent.generateCode();
      eval(aiOutput);
    `;

    const rule = aiSafetyRules.find((r) => r.id === 'AIS-002')!;
    const findings = rule.match(code, 'src/executor.ts');

    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('high');
  });

  it('detects command injection in agent tool execution', () => {
    const code = `
      import { exec } from 'child_process';
      exec(\`git checkout \${toolArgs.branch}\`);
    `;

    const rule = aiSafetyRules.find((r) => r.id === 'AIS-003')!;
    const findings = rule.match(code, 'src/tools.ts');

    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].severity).toBe('high');
  });

  it('does not flag standard non-code files', () => {
    const markdown = 'We used eval() in our description of the model.';
    for (const rule of aiSafetyRules) {
      const findings = rule.match(markdown, 'README.md');
      expect(findings.length).toBe(0);
    }
  });
});
