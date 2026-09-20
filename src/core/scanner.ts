import { Finding, Rule, ScanResult, Severity } from './types.js';
import { secretRules } from './rules/secrets.js';
import { aiSafetyRules } from './rules/ai-safety.js';
import { mcpSafetyRules } from './rules/mcp-safety.js';
import { AgentGuardConfig, DEFAULT_CONFIG } from './config.js';

export interface ScannerOptions {
  customRules?: Rule[];
  config?: AgentGuardConfig;
}

export class Scanner {
  private rules: Rule[];
  private config: Required<AgentGuardConfig>;

  constructor(optionsOrRules: Rule[] | ScannerOptions = {}) {
    let customRules: Rule[] = [];
    let cfg: Partial<AgentGuardConfig> = {};

    if (Array.isArray(optionsOrRules)) {
      customRules = optionsOrRules;
    } else {
      customRules = optionsOrRules.customRules || [];
      cfg = optionsOrRules.config || {};
    }

    this.config = {
      ...DEFAULT_CONFIG,
      ...cfg,
    };

    const allRules = [
      ...secretRules,
      ...aiSafetyRules,
      ...mcpSafetyRules,
      ...customRules,
    ];

    const disabledSet = new Set(this.config.disabledRules);
    this.rules = allRules
      .filter((r) => !disabledSet.has(r.id))
      .map((r) => {
        if (this.config.severityOverrides && this.config.severityOverrides[r.id]) {
          return {
            ...r,
            severity: this.config.severityOverrides[r.id],
          };
        }
        return r;
      });
  }

  /**
   * Determines if a given file path is excluded by project configuration or .gitignore.
   */
  public isIgnored(filePath: string): boolean {
    const normalized = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
    for (const pattern of this.config.ignorePaths) {
      let cleanPattern = pattern.replace(/\\/g, '/').replace(/^\.\//, '').trim();
      if (!cleanPattern) continue;

      // Handle wildcard extensions: e.g. *.log or *.lock
      if (cleanPattern.startsWith('*.')) {
        const ext = cleanPattern.slice(1);
        if (normalized.endsWith(ext)) {
          return true;
        }
      }

      // Strip trailing wildcards: dist/** -> dist
      cleanPattern = cleanPattern.replace(/\/\*\*$/, '').replace(/\/$/, '');

      if (
        normalized === cleanPattern ||
        normalized.startsWith(cleanPattern + '/') ||
        normalized.includes(`/${cleanPattern}/`) ||
        normalized.endsWith(`/${cleanPattern}`)
      ) {
        return true;
      }
    }
    return false;
  }

  /**
   * Parses suppression directives in file content.
   * Returns a map of line number -> Set of suppressed rule IDs (or '*' for all rules).
   */
  private parseSuppressions(content: string): Map<number, Set<string>> {
    const suppressions = new Map<number, Set<string>>();
    const lines = content.split(/\r?\n/);

    let inBlockDisable = false;
    let blockRules = new Set<string>();

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i];

      // Block disable: /* agentguard-disable [rule-id] */
      const blockDisableMatch = line.match(/\/\*\s*agentguard-disable(?:\s+([\w-]+))?\s*\*\//);
      if (blockDisableMatch) {
        inBlockDisable = true;
        blockRules = new Set(blockDisableMatch[1] ? [blockDisableMatch[1]] : ['*']);
      }

      // Block enable: /* agentguard-enable */
      if (line.includes('/* agentguard-enable */')) {
        inBlockDisable = false;
        blockRules.clear();
      }

      if (inBlockDisable) {
        suppressions.set(lineNum, new Set(blockRules));
      }

      // Inline ignore on current line: // agentguard-ignore [rule-id] or /* agentguard-ignore */
      const inlineIgnoreMatch = line.match(/(?:\/\/|\/\*)\s*agentguard-ignore(?::|\s+)?([\w-]+)?/);
      if (inlineIgnoreMatch) {
        const set = suppressions.get(lineNum) || new Set();
        set.add(inlineIgnoreMatch[1] ? inlineIgnoreMatch[1] : '*');
        suppressions.set(lineNum, set);
      }

      // Next-line disable: // agentguard-disable-next-line [rule-id]
      const nextLineMatch = line.match(/(?:\/\/|\/\*)\s*agentguard-disable-next-line(?::|\s+)?([\w-]+)?/);
      if (nextLineMatch) {
        const nextLineNum = lineNum + 1;
        const set = suppressions.get(nextLineNum) || new Set();
        set.add(nextLineMatch[1] ? nextLineMatch[1] : '*');
        suppressions.set(nextLineNum, set);
      }
    }

    return suppressions;
  }

  /**
   * Scans a single file's full content.
   */
  public scanContent(content: string, filePath: string): Finding[] {
    if (this.isIgnored(filePath)) {
      return [];
    }

    const findings: Finding[] = [];
    const suppressions = this.parseSuppressions(content);

    for (const rule of this.rules) {
      const matched = rule.match(content, filePath);
      for (const m of matched) {
        const lineSuppressions = suppressions.get(m.line);
        if (
          lineSuppressions &&
          (lineSuppressions.has('*') || lineSuppressions.has(m.ruleId))
        ) {
          findings.push({ ...m, suppressed: true });
        } else {
          findings.push(m);
        }
      }
    }
    return findings;
  }

  /**
   * Scans a git diff string (e.g. from git diff or GitHub PR).
   * Uses Hunk Context Reconstruction to accurately match multiline patterns
   * while strictly attributing findings only to newly added/modified lines.
   */
  public scanDiff(diffContent: string): Finding[] {
    const findings: Finding[] = [];
    const diffFiles = this.parseGitDiff(diffContent);
    const seenFindingKeys = new Set<string>();

    for (const file of diffFiles) {
      if (this.isIgnored(file.filename)) {
        continue;
      }

      for (const hunk of file.hunks) {
        // Reconstruct the new state lines of the hunk (context + additions)
        const newLines: Array<{
          content: string;
          newLineNumber: number;
          isAdded: boolean;
        }> = [];

        for (const line of hunk.lines) {
          if (line.type !== 'del' && line.newLineNumber !== undefined) {
            newLines.push({
              content: line.content,
              newLineNumber: line.newLineNumber,
              isAdded: line.type === 'add',
            });
          }
        }

        if (newLines.length === 0) continue;

        const hunkContent = newLines.map((l) => l.content).join('\n');
        const suppressions = this.parseSuppressions(hunkContent);

        for (const rule of this.rules) {
          const matched = rule.match(hunkContent, file.filename);

          for (const m of matched) {
            // m.line is 1-indexed line in hunkContent
            const hunkLineIdx = m.line - 1;
            if (hunkLineIdx < 0 || hunkLineIdx >= newLines.length) continue;

            // Check if any line in the match span was newly added
            const snippetLineCount = m.snippet ? m.snippet.split(/\r?\n/).length : 1;
            const endHunkLineIdx = Math.min(newLines.length - 1, hunkLineIdx + snippetLineCount - 1);

            let touchesAddedLine = false;
            for (let i = hunkLineIdx; i <= endHunkLineIdx; i++) {
              if (newLines[i].isAdded) {
                touchesAddedLine = true;
                break;
              }
            }

            // Only report finding if this PR actually introduced or modified it
            if (!touchesAddedLine) {
              continue;
            }

            const targetLineInfo = newLines[hunkLineIdx];
            const realLineNumber = targetLineInfo.newLineNumber;

            // Check suppression
            const lineSupp = suppressions.get(m.line);
            const isSuppressed = Boolean(
              lineSupp && (lineSupp.has('*') || lineSupp.has(m.ruleId))
            );

            const findingKey = `${file.filename}:${realLineNumber}:${m.ruleId}`;
            if (seenFindingKeys.has(findingKey)) {
              continue;
            }
            seenFindingKeys.add(findingKey);

            findings.push({
              ...m,
              file: file.filename,
              line: realLineNumber,
              suppressed: isSuppressed,
            });
          }
        }
      }
    }

    return findings;
  }

  /**
   * Calculates a 0-100 Risk Score based on active findings.
   */
  public calculateRiskScore(findings: Finding[]): number {
    const active = findings.filter((f) => !f.suppressed);
    if (active.length === 0) return 0;

    let score = 0;
    for (const f of active) {
      switch (f.severity) {
        case 'critical':
          score += 40;
          break;
        case 'high':
          score += 20;
          break;
        case 'medium':
          score += 10;
          break;
        case 'low':
          score += 5;
          break;
        case 'info':
          score += 1;
          break;
      }
    }

    return Math.min(100, score);
  }

  /**
   * Computes a full ScanResult summary.
   */
  public generateResult(
    findings: Finding[],
    scannedFiles: number,
    durationMs: number,
    failThreshold?: Severity
  ): ScanResult {
    const effectiveThreshold = failThreshold || this.config.failThreshold || 'high';
    const summary: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    const activeFindings = findings.filter((f) => !f.suppressed);
    const suppressedCount = findings.length - activeFindings.length;

    for (const f of activeFindings) {
      summary[f.severity]++;
    }

    const severityOrder: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
    const thresholdIdx = severityOrder.indexOf(effectiveThreshold);

    let passed = true;
    for (let i = thresholdIdx; i < severityOrder.length; i++) {
      const sev = severityOrder[i];
      if (summary[sev] > 0) {
        passed = false;
        break;
      }
    }

    return {
      totalFiles: scannedFiles,
      scannedFiles,
      findings: activeFindings,
      suppressedCount,
      riskScore: this.calculateRiskScore(activeFindings),
      summary,
      passed,
      durationMs,
    };
  }

  /**
   * Helper to parse standard unified git diff format.
   */
  private parseGitDiff(diffText: string): Array<{
    filename: string;
    hunks: Array<{
      lines: Array<{
        type: 'add' | 'del' | 'context';
        content: string;
        newLineNumber?: number;
      }>;
    }>;
  }> {
    const files: Array<{
      filename: string;
      hunks: Array<{
        lines: Array<{
          type: 'add' | 'del' | 'context';
          content: string;
          newLineNumber?: number;
        }>;
      }>;
    }> = [];

    const fileBlocks = diffText.split(/^diff --git /m);

    for (const block of fileBlocks) {
      if (!block.trim()) continue;

      const lines = block.split(/\r?\n/);
      let filename = '';

      for (const line of lines) {
        if (line.startsWith('+++ b/')) {
          filename = line.slice(6);
          break;
        } else if (line.startsWith('+++ ')) {
          filename = line.slice(4);
          break;
        }
      }

      if (!filename || filename === '/dev/null') continue;

      const hunks: Array<{
        lines: Array<{
          type: 'add' | 'del' | 'context';
          content: string;
          newLineNumber?: number;
        }>;
      }> = [];

      let currentHunk: {
        lines: Array<{
          type: 'add' | 'del' | 'context';
          content: string;
          newLineNumber?: number;
        }>;
      } | null = null;

      let currentNewLine = 0;

      for (const line of lines) {
        const hunkMatch = line.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
        if (hunkMatch) {
          currentNewLine = parseInt(hunkMatch[2], 10);
          currentHunk = { lines: [] };
          hunks.push(currentHunk);
          continue;
        }

        if (!currentHunk) continue;

        if (line.startsWith('+') && !line.startsWith('+++')) {
          currentHunk.lines.push({
            type: 'add',
            content: line.slice(1),
            newLineNumber: currentNewLine,
          });
          currentNewLine++;
        } else if (line.startsWith('-') && !line.startsWith('---')) {
          currentHunk.lines.push({
            type: 'del',
            content: line.slice(1),
          });
        } else if (line.startsWith(' ')) {
          currentHunk.lines.push({
            type: 'context',
            content: line.slice(1),
            newLineNumber: currentNewLine,
          });
          currentNewLine++;
        }
      }

      files.push({ filename, hunks });
    }

    return files;
  }
}
