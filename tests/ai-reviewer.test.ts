import { describe, it, expect } from 'vitest';
import { AIReviewer } from '../src/review/ai-reviewer.js';
import { AIReviewResult } from '../src/core/types.js';

describe('AI Reviewer (OpenAI Codex Layer)', () => {
  it('returns null gracefully when no OpenAI API key is present', async () => {
    delete process.env.OPENAI_API_KEY;
    const reviewer = new AIReviewer();
    const result = await reviewer.reviewPullRequest('diff content', []);
    expect(result).toBeNull();
  });

  it('formats structured AI review into GitHub Markdown', () => {
    const reviewer = new AIReviewer();
    const mockReview: AIReviewResult = {
      summary: 'PR has 1 high risk injection vector but secrets are secure.',
      findingsAnalysis: [
        {
          ruleId: 'AIS-001',
          line: 42,
          verdict: 'CONFIRMED_VULNERABILITY',
          confidence: 0.98,
          reasoning: 'Direct string interpolation allows arbitrary prompt override.',
          suggestedPatch: 'role: "user", content: userInput',
        },
      ],
      architecturalRecommendations: [
        'Migrate prompt construction to a centralized prompt factory.',
      ],
    };

    const markdown = reviewer.formatReviewMarkdown(mockReview);
    expect(markdown).toContain('### 🤖 OpenAI Codex Semantic Review');
    expect(markdown).toContain('CONFIRMED');
    expect(markdown).toContain('```suggestion');
    expect(markdown).toContain('role: "user", content: userInput');
    expect(markdown).toContain('Migrate prompt construction to a centralized prompt factory.');
  });
});
