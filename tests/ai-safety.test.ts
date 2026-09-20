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

  it('does not flag benign metadata variables (user_id, username, textStyle) in system prompt', () => {
    const benignCode = `
      const msg1 = { role: 'system', content: \`User ID: \${user_id}, status: \${status}\` };
      const msg2 = { role: 'system', content: \`Welcome \${username} to the system\` };
    `;

    const rule = aiSafetyRules.find((r) => r.id === 'AIS-001')!;
    const findings = rule.match(benignCode, 'src/chat.ts');
    expect(findings.length).toBe(0);
  });

  it('does not flag API calls with spread configurations in AIS-004', () => {
    const code = `
      const response = await client.chat.completions.create({
        ...defaultConfig,
        messages: [{ role: 'user', content: 'hello' }]
      });
    `;

    const rule = aiSafetyRules.find((r) => r.id === 'AIS-004')!;
    const findings = rule.match(code, 'src/completion.ts');
    expect(findings.length).toBe(0);
  });

  it('detects hardcoded vector database credentials (AIS-006)', () => {
    const code = `
      const pinecone = new Pinecone({
        apiKey: "pcsk_9876543210abcdef9876543210abcdef98765432"
      });
    `;

    const rule = aiSafetyRules.find((r) => r.id === 'AIS-006')!;
    const findings = rule.match(code, 'src/vector.ts');
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('AIS-006');
    expect(findings[0].severity).toBe('high');
  });

  it('detects unshielded SSRF in agent tool execution (AIS-007)', () => {
    const code = `
      export async function executeFetchTool(toolArgs: { url: string }) {
        const res = await fetch(toolArgs.url);
        return res.text();
      }
    `;

    const rule = aiSafetyRules.find((r) => r.id === 'AIS-007')!;
    const findings = rule.match(code, 'src/tools/fetch.ts');
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('AIS-007');
  });

  it('does not flag standard non-code files', () => {
    const markdown = 'We used eval() in our description of the model.';
    for (const rule of aiSafetyRules) {
      const findings = rule.match(markdown, 'README.md');
      expect(findings.length).toBe(0);
    }
  });
});

