import { describe, it, expect } from 'vitest';
import { Scanner } from '../src/core/scanner.js';

describe('Markdown Documentation Secret Scanning', () => {
  const scanner = new Scanner();

  it('detects live high-entropy API key committed into README.md', () => {
    const docContent = `
      # Project Setup
      To get started, set your API key:
      \`\`\`bash
      export OPENAI_API_KEY=sk-proj-aB9xK1mQ8zLp7vW2rT4yU6iO0eN3sD5fG1hJ
      \`\`\`
    `;

    const findings = scanner.scanContent(docContent, 'README.md');
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('SEC-001');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].file).toBe('README.md');
  });

  it('ignores placeholder documentation keys in README.md', () => {
    const docContent = `
      # Setup
      export OPENAI_API_KEY=your_openai_api_key_placeholder
      export AWS_ACCESS_KEY_ID=your_aws_key_here
    `;

    const findings = scanner.scanContent(docContent, 'docs/setup.md');
    expect(findings.length).toBe(0);
  });
});
