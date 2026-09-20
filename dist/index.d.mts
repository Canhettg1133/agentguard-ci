type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
type Category = 'secret' | 'ai-safety' | 'mcp' | 'code-quality';
interface Finding {
    id: string;
    ruleId: string;
    title: string;
    description: string;
    severity: Severity;
    category: Category;
    file: string;
    line: number;
    column?: number;
    snippet: string;
    suggestedFix?: string;
    referenceUrl?: string;
    entropy?: number;
    suppressed?: boolean;
}
interface Rule {
    id: string;
    name: string;
    description: string;
    severity: Severity;
    category: Category;
    match: (content: string, filePath: string) => Finding[];
}
interface ScanResult {
    totalFiles: number;
    scannedFiles: number;
    findings: Finding[];
    suppressedCount?: number;
    riskScore: number;
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
    passed: boolean;
    durationMs: number;
}
interface ReviewComment {
    path: string;
    line: number;
    body: string;
    side?: 'RIGHT' | 'LEFT';
    suggestedChange?: string;
}
interface PRDetails {
    owner: string;
    repo: string;
    pullNumber: number;
    commitSha: string;
    title: string;
    body?: string;
}
interface DiffHunk {
    file: string;
    newStart: number;
    newLines: number;
    lines: {
        type: 'add' | 'del' | 'context';
        content: string;
        newLineNumber?: number;
    }[];
}
interface AIReviewFindingVerdict {
    ruleId: string;
    line: number;
    verdict: 'CONFIRMED_VULNERABILITY' | 'FALSE_POSITIVE' | 'NEEDS_INVESTIGATION';
    confidence: number;
    reasoning: string;
    suggestedPatch?: string;
}
interface AIReviewResult {
    summary: string;
    findingsAnalysis: AIReviewFindingVerdict[];
    architecturalRecommendations: string[];
}

interface AgentGuardConfig {
    ignorePaths?: string[];
    disabledRules?: string[];
    severityOverrides?: Record<string, Severity>;
    minEntropy?: number;
    failThreshold?: Severity;
}
declare const DEFAULT_CONFIG: Required<AgentGuardConfig>;
/**
 * Deep Module: Discovers and loads project-level configuration
 * from .agentguardrc.json or agentguard.config.json, automatically
 * honoring .gitignore entries.
 */
declare function loadConfig(cwd?: string): Required<AgentGuardConfig>;

interface ScannerOptions {
    customRules?: Rule[];
    config?: AgentGuardConfig;
}
declare class Scanner {
    private rules;
    private config;
    constructor(optionsOrRules?: Rule[] | ScannerOptions);
    /**
     * Determines if a given file path is excluded by project configuration or .gitignore.
     */
    isIgnored(filePath: string): boolean;
    /**
     * Parses suppression directives in file content.
     * Returns a map of line number -> Set of suppressed rule IDs (or '*' for all rules).
     */
    private parseSuppressions;
    /**
     * Scans a single file's full content.
     */
    scanContent(content: string, filePath: string): Finding[];
    /**
     * Scans a git diff string (e.g. from git diff or GitHub PR).
     * Uses Hunk Context Reconstruction to accurately match multiline patterns
     * while strictly attributing findings only to newly added/modified lines.
     */
    scanDiff(diffContent: string): Finding[];
    /**
     * Calculates a 0-100 Risk Score based on active findings.
     */
    calculateRiskScore(findings: Finding[]): number;
    /**
     * Computes a full ScanResult summary.
     */
    generateResult(findings: Finding[], scannedFiles: number, durationMs: number, failThreshold?: Severity): ScanResult;
    /**
     * Helper to parse standard unified git diff format.
     */
    private parseGitDiff;
}

/**
 * Shannon Entropy Calculator for cryptographic key verification.
 * Formula: H(X) = -sum(P(x) * log2(P(x)))
 *
 * Real cryptographic keys (OpenAI sk-..., AWS, private keys) exhibit
 * high information entropy (> 3.2 for base64/hex characters), whereas
 * dummy/placeholder strings (e.g., "11111111", "abcdefghabcdefgh") have very low entropy.
 */
declare function calculateShannonEntropy(str: string): number;
/**
 * Determines whether a given token has sufficient entropy to be a true secret.
 * @param token The candidate secret string
 * @param threshold Minimum entropy threshold (default: 3.2 for typical API keys)
 */
declare function isHighEntropy(token: string, threshold?: number): boolean;

declare const secretRules: Rule[];

declare const aiSafetyRules: Rule[];

declare const mcpSafetyRules: Rule[];

declare class TerminalFormatter {
    private static severityBadge;
    static format(result: ScanResult): string;
}

declare class MarkdownFormatter {
    private static severityEmoji;
    static formatPRComment(result: ScanResult, aiInsights?: string): string;
}

declare class SarifFormatter {
    private static severityToSarifLevel;
    /**
     * Generates a fully compliant OASIS SARIF v2.1.0 JSON string.
     */
    static format(result: ScanResult): string;
}

declare class OfflineReviewer {
    /**
     * Generates inline PR review comments based on scan findings.
     */
    static generateInlineComments(findings: Finding[]): ReviewComment[];
}

declare class AIReviewer {
    private client;
    constructor(apiKey?: string);
    /**
     * Smart Diff Budgeting: Extracts prioritized context around detected findings
     * and preserves intact hunk boundaries up to maxChars (default 32,000 chars ~ 8,000 tokens).
     */
    private budgetDiff;
    /**
     * Performs dual-pass semantic verification & architectural analysis
     * using OpenAI Strict Structured Outputs (JSON Schema).
     */
    reviewPullRequest(diffSummary: string, findings: Finding[]): Promise<AIReviewResult | null>;
    /**
     * Helper to format structured AI review into clean GitHub Markdown.
     */
    formatReviewMarkdown(review: AIReviewResult): string;
}

export { type AIReviewFindingVerdict, type AIReviewResult, AIReviewer, type AgentGuardConfig, type Category, DEFAULT_CONFIG, type DiffHunk, type Finding, MarkdownFormatter, OfflineReviewer, type PRDetails, type ReviewComment, type Rule, SarifFormatter, type ScanResult, Scanner, type ScannerOptions, type Severity, TerminalFormatter, aiSafetyRules, calculateShannonEntropy, isHighEntropy, loadConfig, mcpSafetyRules, secretRules };
