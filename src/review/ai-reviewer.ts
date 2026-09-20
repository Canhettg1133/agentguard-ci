import OpenAI from 'openai';
import { Finding, AIReviewResult } from '../core/types.js';

export class AIReviewer {
  private client: OpenAI | null = null;

  constructor(apiKey?: string) {
    const key = apiKey || process.env.OPENAI_API_KEY;
    if (key) {
      this.client = new OpenAI({ apiKey: key });
    }
  }

  /**
   * Smart Diff Budgeting: Extracts prioritized context around detected findings
   * to guarantee the LLM sees the critical code blocks without arbitrary cutoffs.
   */
  private budgetDiff(diffText: string, findings: Finding[], maxChars = 8000): string {
    if (!diffText) return '';
    if (diffText.length <= maxChars) return diffText;

    // Collect targeted file paths from candidate findings
    const targetFiles = new Set(findings.map((f) => f.file.replace(/\\/g, '/')));
    const fileBlocks = diffText.split(/^diff --git /m);
    const prioritizedBlocks: string[] = [];
    const remainingBlocks: string[] = [];

    for (const block of fileBlocks) {
      if (!block.trim()) continue;
      const firstLine = block.split(/\r?\n/)[0] || '';
      const isTargeted = Array.from(targetFiles).some((tf) => firstLine.includes(tf));

      if (isTargeted) {
        prioritizedBlocks.push('diff --git ' + block);
      } else {
        remainingBlocks.push('diff --git ' + block);
      }
    }

    let budgeted = prioritizedBlocks.join('\n');
    if (budgeted.length > maxChars) {
      return budgeted.slice(0, maxChars) + '\n\n[... Diff truncated for token safety ...]';
    }

    for (const block of remainingBlocks) {
      if ((budgeted + '\n' + block).length > maxChars) {
        budgeted += '\n\n[... Additional non-critical files truncated for token budget ...]';
        break;
      }
      budgeted += '\n' + block;
    }

    return budgeted;
  }

  /**
   * Performs dual-pass semantic verification & architectural analysis
   * using OpenAI Strict Structured Outputs (JSON Schema).
   */
  public async reviewPullRequest(
    diffSummary: string,
    findings: Finding[]
  ): Promise<AIReviewResult | null> {
    if (!this.client) {
      return null;
    }

    try {
      const budgetedDiff = this.budgetDiff(diffSummary, findings);

      const hasCandidateFindings = findings.length > 0;
      const prompt = `You are AgentGuard-CI's Principal Security Auditor & OpenAI Codex Reviewer.
Analyze the provided pull request code diff ${
        hasCandidateFindings
          ? 'and verify the candidate security findings detected by static rules.'
          : 'and evaluate the security architecture of the code changes.'
      }

${
  hasCandidateFindings
    ? `Tasks:
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
    description: f.description,
  })),
  null,
  2
)}`
    : `Tasks:
1. Review the code changes for subtle application security risks, authorization issues, or insecure AI patterns.
2. Provide high-level architectural recommendations for maintainers.`
}

Code Diff:
${budgetedDiff || '(Empty diff)'}`;

      const response = await this.client.chat.completions.create({
        model: process.env.AGENTGUARD_MODEL || 'gpt-4o-mini',
        messages: [
          {
            role: 'system',
            content:
              'You are a principal application security engineer and compiler security expert. You always return rigorous, structured JSON audits strictly conforming to the requested schema.',
          },
          { role: 'user', content: prompt },
        ],
        response_format: {
          type: 'json_schema',
          json_schema: {
            name: 'security_review_report',
            strict: true,
            schema: {
              type: 'object',
              properties: {
                summary: {
                  type: 'string',
                  description: 'High-level assessment of the PR security posture.',
                },
                findingsAnalysis: {
                  type: 'array',
                  description: 'Verification analysis of each finding.',
                  items: {
                    type: 'object',
                    properties: {
                      ruleId: { type: 'string' },
                      line: { type: 'integer' },
                      verdict: {
                        type: 'string',
                        enum: [
                          'CONFIRMED_VULNERABILITY',
                          'FALSE_POSITIVE',
                          'NEEDS_INVESTIGATION',
                        ],
                      },
                      confidence: { type: 'number' },
                      reasoning: { type: 'string' },
                      suggestedPatch: {
                        type: 'string',
                        description: 'Remediation code replacement or instructions.',
                      },
                    },
                    required: [
                      'ruleId',
                      'line',
                      'verdict',
                      'confidence',
                      'reasoning',
                      'suggestedPatch',
                    ],
                    additionalProperties: false,
                  },
                },
                architecturalRecommendations: {
                  type: 'array',
                  description: 'Architectural security advice for repository maintainers.',
                  items: { type: 'string' },
                },
              },
              required: [
                'summary',
                'findingsAnalysis',
                'architecturalRecommendations',
              ],
              additionalProperties: false,
            },
          },
        },
        max_tokens: 2000,
        temperature: 0.1,
      });

      const rawJson = response.choices[0]?.message?.content;
      if (!rawJson) return null;

      const parsed = JSON.parse(rawJson) as Partial<AIReviewResult>;
      return {
        summary: parsed.summary || 'AI Semantic Review completed.',
        findingsAnalysis: Array.isArray(parsed.findingsAnalysis) ? parsed.findingsAnalysis : [],
        architecturalRecommendations: Array.isArray(parsed.architecturalRecommendations)
          ? parsed.architecturalRecommendations
          : [],
      };
    } catch (err: any) {
      return {
        summary: `AI Semantic Review could not complete: ${err.message || 'API request failed'}`,
        findingsAnalysis: [],
        architecturalRecommendations: [
          'Verify your OPENAI_API_KEY and network connectivity to enable AI review.',
        ],
      };
    }
  }

  /**
   * Helper to format structured AI review into clean GitHub Markdown.
   */
  public formatReviewMarkdown(review: AIReviewResult): string {
    const lines: string[] = [];

    lines.push('### 🤖 OpenAI Codex Semantic Review');
    lines.push('');
    lines.push(`> ${review.summary}`);
    lines.push('');

    if (review.findingsAnalysis.length > 0) {
      lines.push('#### 🔬 AI Finding Verification');
      lines.push('');
      lines.push('| Rule | Line | Verdict | Confidence | AI Assessment |');
      lines.push('| :--- | :---: | :---: | :---: | :--- |');

      for (const item of review.findingsAnalysis) {
        const badge =
          item.verdict === 'CONFIRMED_VULNERABILITY'
            ? '🔴 `CONFIRMED`'
            : item.verdict === 'FALSE_POSITIVE'
            ? '🟢 `FALSE_POSITIVE`'
            : '🟡 `INVESTIGATE`';

        const conf = `${Math.round(item.confidence * 100)}%`;
        lines.push(
          `| \`${item.ruleId}\` | \`${item.line}\` | ${badge} | ${conf} | ${item.reasoning.replace(
            /\|/g,
            '\\|'
          )} |`
        );
      }
      lines.push('');

      // Add suggested code patches
      const patches = review.findingsAnalysis.filter((f) => f.suggestedPatch);
      if (patches.length > 0) {
        lines.push('<details><summary><b>🛠️ AI Suggested Code Fixes</b></summary>');
        lines.push('');
        for (const p of patches) {
          lines.push(`**Rule \`${p.ruleId}\` (Line ${p.line}):**`);
          lines.push('```suggestion');
          lines.push(p.suggestedPatch!);
          lines.push('```');
          lines.push('');
        }
        lines.push('</details>');
        lines.push('');
      }
    }

    if (review.architecturalRecommendations.length > 0) {
      lines.push('#### 🏛️ Architectural Best Practices');
      lines.push('');
      for (const rec of review.architecturalRecommendations) {
        lines.push(`* ${rec}`);
      }
      lines.push('');
    }

    return lines.join('\n');
  }
}
