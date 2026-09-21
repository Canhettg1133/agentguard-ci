export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type Category = 'secret' | 'ai-safety' | 'mcp' | 'code-quality';

export interface Finding {
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
  cweId?: string;
  owaspCategory?: string;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: Category;
  cweId?: string;
  owaspCategory?: string;
  match: (content: string, filePath: string) => Finding[];
}

export interface ScanResult {
  totalFiles: number;
  scannedFiles: number;
  findings: Finding[];
  suppressedCount?: number;
  riskScore: number; // 0 - 100
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

export interface ReviewComment {
  path: string;
  line: number;
  body: string;
  side?: 'RIGHT' | 'LEFT';
  suggestedChange?: string;
}

export interface PRDetails {
  owner: string;
  repo: string;
  pullNumber: number;
  commitSha: string;
  title: string;
  body?: string;
}

export interface DiffHunk {
  file: string;
  newStart: number;
  newLines: number;
  lines: {
    type: 'add' | 'del' | 'context';
    content: string;
    newLineNumber?: number;
  }[];
}

export interface AIReviewFindingVerdict {
  ruleId: string;
  line: number;
  verdict: 'CONFIRMED_VULNERABILITY' | 'FALSE_POSITIVE' | 'NEEDS_INVESTIGATION';
  confidence: number; // 0.0 - 1.0
  reasoning: string;
  suggestedPatch?: string;
}

export interface AIReviewResult {
  summary: string;
  findingsAnalysis: AIReviewFindingVerdict[];
  architecturalRecommendations: string[];
}
