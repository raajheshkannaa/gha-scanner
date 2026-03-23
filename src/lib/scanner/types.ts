export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Category =
  | 'supply-chain'
  | 'injection'
  | 'dangerous-triggers'
  | 'permissions'
  | 'secrets-exposure'
  | 'runner-security'
  | 'ci-cd-hygiene'
  | 'best-practices';

export const CATEGORY_LABELS: Record<Category, string> = {
  'supply-chain': 'Supply Chain & Action Pinning',
  'injection': 'Workflow Injection',
  'dangerous-triggers': 'Dangerous Triggers',
  'permissions': 'Permissions',
  'secrets-exposure': 'Secrets & Data Exposure',
  'runner-security': 'Runner Security',
  'ci-cd-hygiene': 'CI/CD Hygiene',
  'best-practices': 'Best Practices',
};

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 2,
  info: 0,
};

export interface WorkflowFile {
  path: string;
  name: string;
  content: string;
  parsed: Record<string, unknown> | null;
}

export interface RepoContext {
  owner: string;
  repo: string;
  defaultBranch: string;
  headSha: string;
  workflows: WorkflowFile[];
  hasDependabot: boolean;
  dependabotConfig: Record<string, unknown> | null;
  hasCodeowners: boolean;
  codeownersContent: string | null;
}

export interface CheckDefinition {
  id: string;
  name: string;
  description: string;
  category: Category;
  severity: Severity;
  run: (context: RepoContext) => Finding[];
}

export interface Finding {
  checkId: string;
  severity: Severity;
  category: Category;
  title: string;
  description: string;
  risk: string;
  remediation: string;
  file: string;
  line?: number;
  evidence: string;
}

export interface CategorySummary {
  category: Category;
  label: string;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanResult {
  schemaVersion: number;
  repo: string;
  headSha: string;
  scannedAt: string;
  duration: number;
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  totalChecks: number;
  passingChecks: number;
  findings: Finding[];
  categories: CategorySummary[];
  workflowCount: number;
  partial: boolean;
  warnings: string[];
}

export interface VulnerableAction {
  action: string;
  affectedVersions: string;
  cveId?: string;
  disclosedDate: string;
  fixedVersion?: string;
  description: string;
}
