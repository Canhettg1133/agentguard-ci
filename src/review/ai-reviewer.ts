import OpenAI from 'openai';
import pc from 'picocolors';
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
   * and preserves intact hunk boundaries up to maxChars (default 32,000 chars ~ 8,000 tokens).
   */
  private budgetDiff(diffText: string, findings: Finding[], maxChars = 32000): string {
    if (!diffText) return '';
    if (diffText.length <= maxChars) return diffText;

    const targetFiles = new Set(findings.map((f) => f.file.replace(/\\/g, '/')));
    const fileBlocks = diffText.split(/^diff --git /m);
    const prioritizedBlocks: string[] = [];
    const remainingBlocks: string[] = [];

    for (const rawBlock of fileBlocks) {
      if (!rawBlock.trim()) continue;
      const block = 'diff --git ' + rawBlock;
      const firstLine = block.split(/\r?\n/)[0] || '';
      const isTargeted = Array.from(targetFiles).some((tf) => firstLine.includes(tf));

      if (isTargeted) {
        prioritizedBlocks.push(block);
      } else {
        remainingBlocks.push(block);
      }
    }

    let result = '';
    for (const block of prioritizedBlocks) {
      if ((result + '\n' + block).length > maxChars) {
        const available = maxChars - result.length;
        if (available > 500) {
          const partial = block.slice(0, available);
          const lastNewline = partial.lastIndexOf('\n');
          result += '\n' + (lastNewline > 0 ? partial.slice(0, lastNewline) : partial);
          result += '\n\n[... Remaining hunks truncated for token budget ...]';
        }
        break;
      }
      result += (result ? '\n' : '') + block;
    }

    for (const block of remainingBlocks) {
      if ((result + '\n' + block).length > maxChars) {
        result += '\n\n[... Additional non-critical files omitted for token budget ...]';
        break;
      }
      result += '\n' + block;
    }

    return result || diffText.slice(0, maxChars);
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

  /**
   * Formats structured AI review into a clear, colored terminal report.
   */
  public formatReviewTerminal(review: AIReviewResult): string {
    const lines: string[] = [];
    lines.push('');
    lines.push(
      pc.bold(
        pc.magenta('🤖 OpenAI Codex') +
          pc.white(' - Semantic Code Review & Verification')
      )
    );
    lines.push(pc.gray('═'.repeat(60)));
    lines.push(pc.bold('Assessment: ') + pc.cyan(review.summary));
    lines.push('');

    if (review.findingsAnalysis.length > 0) {
      lines.push(pc.bold('Finding Verification:'));
      for (const item of review.findingsAnalysis) {
        const badge =
          item.verdict === 'CONFIRMED_VULNERABILITY'
            ? pc.bgRed(pc.white(pc.bold(' CONFIRMED ')))
            : item.verdict === 'FALSE_POSITIVE'
            ? pc.bgGreen(pc.black(pc.bold(' FALSE POSITIVE ')))
            : pc.bgYellow(pc.black(pc.bold(' INVESTIGATE ')));

        const conf = pc.dim(`(${Math.round(item.confidence * 100)}% confidence)`);
        lines.push(`  ${badge} ${pc.bold(`Rule [${item.ruleId}]`)} Line ${item.line} ${conf}`);
        lines.push(`    ${pc.gray(item.reasoning)}`);

        if (item.suggestedPatch) {
          lines.push(`    ${pc.green('💡 Suggested Remediation (Patch):')}`);
          const patchLines = item.suggestedPatch.split(/\r?\n/);
          for (const pl of patchLines) {
            lines.push(`      ${pc.italic(pc.green(pl))}`);
          }
        }
        lines.push('');
      }
    }

    if (review.architecturalRecommendations.length > 0) {
      lines.push(pc.bold('🏛️  Architectural Recommendations:'));
      for (const rec of review.architecturalRecommendations) {
        lines.push(`  ${pc.yellow('•')} ${rec}`);
      }
      lines.push('');
    }

    lines.push(pc.gray('═'.repeat(60)));
    return lines.join('\n');
  }
}
