import { Command } from 'commander';
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import pc from 'picocolors';
import { Scanner } from '../core/scanner.js';
import { loadConfig } from '../core/config.js';
import { TerminalFormatter } from '../core/formatter/terminal.js';
import { MarkdownFormatter } from '../core/formatter/markdown.js';
import { SarifFormatter } from '../core/formatter/sarif.js';
import { Finding, Severity } from '../core/types.js';
import { runBenchmark, printBenchmarkReport } from '../benchmark/runner.js';

const program = new Command();

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
  'benchmark',
  'fixtures',
]);

const IGNORED_EXTS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.ico',
  '.svg',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.pdf',
  '.zip',
  '.tar',
  '.gz',
  '.lock',
  '.map',
  '.exe',
  '.bin',
  '.wasm',
  '.node',
  '.dll',
  '.dylib',
  '.so',
  '.mp4',
  '.mp3',
  '.mov',
  '.avi',
  '.webm',
  '.pyc',
]);

function walkDir(
  dir: string,
  baseDir: string = dir,
  isIgnored?: (relPath: string) => boolean,
  fileList: string[] = []
): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(baseDir, fullPath);

    if (isIgnored && isIgnored(relPath)) {
      continue;
    }

    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
        walkDir(fullPath, baseDir, isIgnored, fileList);
      }
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (!IGNORED_EXTS.has(ext)) {
        fileList.push(fullPath);
      }
    }
  }

  return fileList;
}

program
  .name('agentguard')
  .description('AI-Powered Security & Code Quality Guardrail for Pull Requests & Repositories')
  .version('0.1.0');

// COMMAND: scan
program
  .command('scan')
  .description('Scan a directory or file for secret leaks, AI vulnerabilities, and MCP risks')
  .argument('[target]', 'Target directory or file to scan', '.')
  .option(
    '-t, --threshold <level>',
    'Fail threshold severity (info, low, medium, high, critical)'
  )
  .option(
    '-f, --format <format>',
    'Output format: terminal | json | markdown | sarif',
    'terminal'
  )
  .option('-o, --output <file>', 'Save output report to specified file path')
  .action((target, options) => {
    const startTime = Date.now();
    const targetPath = path.resolve(process.cwd(), target);

    if (!fs.existsSync(targetPath)) {
      console.error(pc.red(`Error: Target path "${targetPath}" does not exist.`));
      process.exit(1);
    }

    const config = loadConfig();
    const scanner = new Scanner({ config });
    const filesToScan: string[] = [];
    const stat = fs.statSync(targetPath);

    if (stat.isFile()) {
      filesToScan.push(targetPath);
    } else if (stat.isDirectory()) {
      walkDir(targetPath, targetPath, (p) => scanner.isIgnored(p), filesToScan);
    }

    const allFindings: Finding[] = [];

    for (const filePath of filesToScan) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const relativePath = path.relative(process.cwd(), filePath);
        const findings = scanner.scanContent(content, relativePath);
        allFindings.push(...findings);
      } catch {
        // Skip binary or unreadable files
      }
    }

    const duration = Date.now() - startTime;
    const failThreshold = (options.threshold || config.failThreshold || 'high') as Severity;
    const result = scanner.generateResult(
      allFindings,
      filesToScan.length,
      duration,
      failThreshold
    );

    let outputText = '';
    if (options.format === 'json') {
      outputText = JSON.stringify(result, null, 2);
    } else if (options.format === 'markdown') {
      outputText = MarkdownFormatter.formatPRComment(result);
    } else if (options.format === 'sarif') {
      outputText = SarifFormatter.format(result);
    } else {
      outputText = TerminalFormatter.format(result);
    }

    if (options.output) {
      const outPath = path.resolve(process.cwd(), options.output);
      fs.writeFileSync(outPath, outputText, 'utf-8');
      console.log(pc.green(`✔ Output report saved to: ${pc.bold(outPath)}`));
    } else {
      console.log(outputText);
    }

    if (!result.passed) {
      process.exit(1);
    }
  });

// COMMAND: diff
program
  .command('diff')
  .description('Scan currently staged or uncommitted git changes')
  .argument('[commitOrBranch]', 'Compare with branch or commit (default: HEAD)', 'HEAD')
  .option('-s, --staged', 'Scan only staged changes (git diff --cached) for pre-commit hooks')
  .option('-t, --threshold <level>', 'Fail threshold severity')
  .option('-f, --format <format>', 'Output format: terminal | json | markdown | sarif', 'terminal')
  .option('-o, --output <file>', 'Save output report to specified file path')
  .action((targetRef, options) => {
    const startTime = Date.now();
    let diffOutput = '';
    const diffCmd = options.staged ? 'git diff --cached' : `git diff ${targetRef}`;

    try {
      diffOutput = execSync(diffCmd, {
        encoding: 'utf-8',
        maxBuffer: 10 * 1024 * 1024,
      });
    } catch {
      console.error(pc.red('Failed to run git diff. Ensure this is a git repository.'));
      process.exit(1);
    }

    if (!diffOutput.trim()) {
      console.log(pc.green('No git changes detected to scan.'));
      return;
    }

    const config = loadConfig();
    const scanner = new Scanner({ config });
    const findings = scanner.scanDiff(diffOutput);
    const duration = Date.now() - startTime;
    const failThreshold = (options.threshold || config.failThreshold || 'high') as Severity;

    const result = scanner.generateResult(
      findings,
      1,
      duration,
      failThreshold
    );

    let outputText = '';
    if (options.format === 'json') {
      outputText = JSON.stringify(result, null, 2);
    } else if (options.format === 'markdown') {
      outputText = MarkdownFormatter.formatPRComment(result);
    } else if (options.format === 'sarif') {
      outputText = SarifFormatter.format(result);
    } else {
      outputText = TerminalFormatter.format(result);
    }

    if (options.output) {
      const outPath = path.resolve(process.cwd(), options.output);
      fs.writeFileSync(outPath, outputText, 'utf-8');
      console.log(pc.green(`✔ Output report saved to: ${pc.bold(outPath)}`));
    } else {
      console.log(outputText);
    }

    if (!result.passed) {
      process.exit(1);
    }
  });

// COMMAND: hook
program
  .command('hook')
  .description('Manage local git hooks for AgentGuard-CI')
  .argument('<action>', 'Action to perform: install | uninstall')
  .action((action) => {
    const gitDir = path.resolve(process.cwd(), '.git');
    if (!fs.existsSync(gitDir)) {
      console.error(pc.red('Error: Current directory is not a git repository root.'));
      process.exit(1);
    }

    const hooksDir = path.join(gitDir, 'hooks');
    if (!fs.existsSync(hooksDir)) {
      fs.mkdirSync(hooksDir, { recursive: true });
    }

    const preCommitHook = path.join(hooksDir, 'pre-commit');

    if (action === 'install') {
      const hookScript = `#!/bin/sh
# AgentGuard-CI Pre-Commit Security Hook
# Prevents accidental commits of secret keys and AI vulnerabilities
npx agentguard-ci diff --staged --threshold high
`;
      fs.writeFileSync(preCommitHook, hookScript, { encoding: 'utf-8', mode: 0o755 });
      try {
        fs.chmodSync(preCommitHook, 0o755);
      } catch {
        // Mode flag on write handles permissions on most platforms
      }
      console.log(pc.green(`✔ Installed AgentGuard pre-commit hook at: ${pc.bold(preCommitHook)}`));
    } else if (action === 'uninstall') {
      if (fs.existsSync(preCommitHook)) {
        fs.unlinkSync(preCommitHook);
        console.log(pc.green('✔ Uninstalled AgentGuard pre-commit hook.'));
      } else {
        console.log(pc.yellow('No pre-commit hook found to uninstall.'));
      }
    } else {
      console.error(pc.red(`Unknown action: "${action}". Use "install" or "uninstall".`));
      process.exit(1);
    }
  });

// COMMAND: benchmark
program
  .command('benchmark')
  .description('Run internal detection accuracy (Precision/Recall) and latency benchmarks')
  .action(() => {
    const metrics = runBenchmark();
    printBenchmarkReport(metrics);
  });

// COMMAND: init
program
  .command('init')
  .description('Initialize GitHub Actions workflow for AgentGuard-CI in current repo')
  .action(() => {
    const workflowDir = path.resolve(process.cwd(), '.github/workflows');
    const workflowFile = path.join(workflowDir, 'agentguard.yml');

    if (!fs.existsSync(workflowDir)) {
      fs.mkdirSync(workflowDir, { recursive: true });
    }

    const workflowContent = `name: AgentGuard Security Check

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main, master]

jobs:
  agentguard:
    name: Security & PR Guardrail
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run AgentGuard-CI
        uses: agentguard-ci/agentguard-ci@v0.1.0
        with:
          github-token: \${{ secrets.GITHUB_TOKEN }}
          fail-on-severity: 'high'
          comment-on-pr: 'true'
          sarif-file: 'agentguard-report.sarif'

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'agentguard-report.sarif'
`;

    fs.writeFileSync(workflowFile, workflowContent, 'utf-8');
    console.log(pc.green(`✔ Created GitHub Actions workflow at: ${pc.bold(workflowFile)}`));
    console.log(
      pc.cyan('\nAgentGuard-CI is now configured with SARIF Code Scanning & PR Guardrails!')
    );
  });

program.parse(process.argv);
