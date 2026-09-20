import fs from 'node:fs';
import path from 'node:path';
import * as core from '@actions/core';
import * as github from '@actions/github';
import { Scanner } from '../core/scanner.js';
import { loadConfig } from '../core/config.js';
import { MarkdownFormatter } from '../core/formatter/markdown.js';
import { SarifFormatter } from '../core/formatter/sarif.js';
import { AIReviewer } from '../review/ai-reviewer.js';
import { Severity, Finding } from '../core/types.js';

async function run(): Promise<void> {
  const startTime = Date.now();

  try {
    const token = core.getInput('github-token') || process.env.GITHUB_TOKEN;
    const openAiKey = core.getInput('openai-api-key') || process.env.OPENAI_API_KEY;
    const failThreshold = (core.getInput('fail-on-severity') || 'high') as Severity;
    const shouldComment = core.getBooleanInput('comment-on-pr');
    const sarifOutputFile = core.getInput('sarif-file') || 'agentguard-report.sarif';

    const context = github.context;
    const config = loadConfig();
    const scanner = new Scanner({ config });

    core.info('🛡️ Starting AgentGuard-CI security and code quality scan...');

    if (context.eventName === 'pull_request' && context.payload.pull_request) {
      const pullNumber = context.payload.pull_request.number;
      const { owner, repo } = context.repo;

      if (!token) {
        core.setFailed('Missing github-token input. GITHUB_TOKEN is required to fetch PR diff.');
        return;
      }

      const octokit = github.getOctokit(token);

      core.info(`Fetching diff for PR #${pullNumber} in ${owner}/${repo}...`);

      const diffResponse = await octokit.rest.pulls.get({
        owner,
        repo,
        pull_number: pullNumber,
        mediaType: {
          format: 'diff',
        },
      });

      const diffText = diffResponse.data as unknown as string;
      const findings = scanner.scanDiff(diffText);
      const duration = Date.now() - startTime;
      const result = scanner.generateResult(findings, 1, duration, failThreshold);

      core.info(`Scan complete in ${duration}ms. Active Findings: ${result.findings.length}, Risk Score: ${result.riskScore}`);

      // 1. Emit native GitHub Annotations directly on the PR "Files changed" diff
      for (const f of result.findings) {
        const annotationProps = {
          file: f.file,
          startLine: f.line,
          startColumn: f.column || 1,
          title: `[${f.ruleId}] ${f.title}`,
        };
        const message = `${f.description}${f.suggestedFix ? ` | Suggested Fix: ${f.suggestedFix}` : ''}`;

        if (f.severity === 'critical' || f.severity === 'high') {
          core.error(message, annotationProps);
        } else {
          core.warning(message, annotationProps);
        }
      }

      // 2. Generate and write OASIS SARIF v2.1.0 file
      const sarifContent = SarifFormatter.format(result);
      const sarifPath = path.resolve(process.cwd(), sarifOutputFile);
      fs.writeFileSync(sarifPath, sarifContent, 'utf-8');
      core.info(`✔ SARIF v2.1.0 report generated at: ${sarifPath}`);
      core.setOutput('sarif-path', sarifPath);

      // 3. OpenAI Codex Semantic Review Layer (Structured Outputs)
      let aiInsightsMarkdown: string | undefined;
      if (openAiKey) {
        core.info('OpenAI key detected: Running semantic AI code review layer with Structured Outputs...');
        const aiReviewer = new AIReviewer(openAiKey);
        const review = await aiReviewer.reviewPullRequest(diffText, result.findings);
        if (review) {
          aiInsightsMarkdown = aiReviewer.formatReviewMarkdown(review);
        }
      }

      // 4. Render Step Summary (Always visible in GitHub Actions run overview)
      const reportMarkdown = MarkdownFormatter.formatPRComment(result, aiInsightsMarkdown);
      try {
        await core.summary.addRaw(reportMarkdown).write();
        core.info('✔ Published security report to GitHub Actions Step Summary.');
      } catch (summaryErr: any) {
        core.debug(`Could not write Step Summary: ${summaryErr.message}`);
      }

      // 5. In-Place PR Comment (Deduplicated via Watermark, handles fork 403 gracefully)
      if (shouldComment) {
        try {
          core.info(`Publishing security report comment to PR #${pullNumber}...`);
          const { data: comments } = await octokit.rest.issues.listComments({
            owner,
            repo,
            issue_number: pullNumber,
            per_page: 50,
          });

          const existingComment = comments.find((c) =>
            c.body?.includes('<!-- agentguard-ci-report -->')
          );

          if (existingComment) {
            core.info(`Updating existing AgentGuard report comment #${existingComment.id}...`);
            await octokit.rest.issues.updateComment({
              owner,
              repo,
              comment_id: existingComment.id,
              body: reportMarkdown,
            });
          } else {
            core.info('Creating new AgentGuard report comment...');
            await octokit.rest.issues.createComment({
              owner,
              repo,
              issue_number: pullNumber,
              body: reportMarkdown,
            });
          }
        } catch (commentErr: any) {
          if (commentErr.status === 403) {
            core.warning(
              'Notice: Unable to post PR comment because GITHUB_TOKEN has read-only permissions (standard on forked PRs). The complete security report is published to the GitHub Actions Summary tab and SARIF Code Scanning.'
            );
          } else {
            core.warning(`Failed to post or update PR comment: ${commentErr.message}`);
          }
        }
      }

      // Set Action Outputs
      core.setOutput('risk-score', result.riskScore);
      core.setOutput('findings-count', result.findings.length);
      core.setOutput('passed', result.passed);

      if (!result.passed) {
        core.setFailed(
          `AgentGuard-CI failed: Found ${result.findings.length} issue(s) exceeding severity threshold "${failThreshold}".`
        );
      } else {
        core.info('✔ AgentGuard-CI passed all security checks.');
      }
    } else {
      core.info('Push or workspace event detected. Performing full repository security scan...');
      const workspaceDir = process.cwd();
      const filesToScan: string[] = [];

      const IGNORED_DIRS = new Set([
        'node_modules',
        '.git',
        'dist',
        'build',
        'coverage',
        '.next',
        '.turbo',
        'vendor',
        '.venv',
        'venv',
        '__pycache__',
      ]);

      function collectFiles(dir: string): void {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
              collectFiles(fullPath);
            }
          } else if (entry.isFile()) {
            const relPath = path.relative(workspaceDir, fullPath);
            if (!scanner.isIgnored(relPath)) {
              filesToScan.push(fullPath);
            }
          }
        }
      }

      collectFiles(workspaceDir);

      const allFindings: Finding[] = [];
      for (const filePath of filesToScan) {
        try {
          const content = fs.readFileSync(filePath, 'utf-8');
          const relPath = path.relative(workspaceDir, filePath);
          const findings = scanner.scanContent(content, relPath);
          allFindings.push(...findings);
        } catch {
          // Skip binary or unreadable files
        }
      }

      const duration = Date.now() - startTime;
      const result = scanner.generateResult(allFindings, filesToScan.length, duration, failThreshold);

      // Emit annotations for GitHub workflow logs
      for (const f of result.findings) {
        const annotationProps = {
          file: f.file,
          startLine: f.line,
          startColumn: f.column || 1,
          title: `[${f.ruleId}] ${f.title}`,
        };
        const message = `${f.description}${f.suggestedFix ? ` | Suggested Fix: ${f.suggestedFix}` : ''}`;

        if (f.severity === 'critical' || f.severity === 'high') {
          core.error(message, annotationProps);
        } else {
          core.warning(message, annotationProps);
        }
      }

      const sarifContent = SarifFormatter.format(result);
      const sarifPath = path.resolve(process.cwd(), sarifOutputFile);
      fs.writeFileSync(sarifPath, sarifContent, 'utf-8');
      core.info(`✔ Repository SARIF v2.1.0 report generated at: ${sarifPath}`);
      core.setOutput('sarif-path', sarifPath);
      core.setOutput('risk-score', result.riskScore);
      core.setOutput('findings-count', result.findings.length);
      core.setOutput('passed', result.passed);

      // Render Step Summary for workspace scan
      const reportMarkdown = MarkdownFormatter.formatPRComment(result);
      try {
        await core.summary.addRaw(reportMarkdown).write();
        core.info('✔ Published repository security report to GitHub Actions Step Summary.');
      } catch (summaryErr: any) {
        core.debug(`Could not write Step Summary: ${summaryErr.message}`);
      }

      if (!result.passed) {
        core.setFailed(
          `AgentGuard-CI failed: Found ${result.findings.length} issue(s) exceeding severity threshold "${failThreshold}".`
        );
      } else {
        core.info(`✔ Workspace scan complete in ${duration}ms. Scanned ${filesToScan.length} files cleanly.`);
      }
    }
  } catch (error: any) {
    core.setFailed(`AgentGuard-CI action error: ${error.message}`);
  }
}

run();
