import { describe, it, expect } from 'vitest';
import { OfflineReviewer } from '../src/review/offline-reviewer.js';
import { Finding } from '../src/core/types.js';

describe('Offline Reviewer (Local Static Rule Suggestions)', () => {
  const mockFinding: Finding = {
    id: 'SEC-001-1',
    ruleId: 'SEC-001',
    title: 'OpenAI API Key Leak',
    description: 'Detected a live OpenAI API key committed into source code.',
    severity: 'critical',
    category: 'secret',
    file: 'src/config.ts',
    line: 12,
    column: 5,
    suggestedFix: 'Move this key to an environment variable (.env) or GitHub Secrets.',
  };

  it('builds a structured comment body with remediation advice', () => {
    const commentBody = OfflineReviewer.buildCommentBody(mockFinding);
    expect(commentBody).toContain('### 🛡️ AgentGuard-CI: `[SEC-001]` OpenAI API Key Leak');
    expect(commentBody).toContain('**Severity:** `CRITICAL`');
    expect(commentBody).toContain('Move this key to an environment variable');
    expect(commentBody).toContain('Automated guardrail via AgentGuard-CI');
  });

  it('generates inline review comments while filtering suppressed findings', () => {
    const findings: Finding[] = [
      mockFinding,
      {
        ...mockFinding,
        id: 'SEC-001-2',
        line: 15,
        suppressed: true,
      },
    ];

    const inlineComments = OfflineReviewer.generateInlineComments(findings);
    expect(inlineComments).toHaveLength(1);
    expect(inlineComments[0].path).toBe('src/config.ts');
    expect(inlineComments[0].line).toBe(12);
    expect(inlineComments[0].side).toBe('RIGHT');
    expect(inlineComments[0].body).toContain('SEC-001');
  });
});
