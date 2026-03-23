'use client';

import { Finding, Category, CategorySummary, Severity } from '@/lib/scanner/types';

interface IncidentData {
  date: string;
  name: string;
  description: string;
  pattern: string;
  link?: string;
}

const INCIDENTS: Record<string, IncidentData> = {
  'supply-chain': {
    date: 'March 2026',
    name: 'Trivy Supply Chain Compromise',
    description:
      'TeamPCP poisoned 75 of 76 version tags on aquasecurity/trivy-action after a botched credential rotation. A memory-dumping stealer targeted Runner.Worker processes, exfiltrating CI/CD secrets from thousands of repositories.',
    pattern: 'mutable tag references',
  },
  injection: {
    date: 'March 2025',
    name: 'tj-actions/changed-files (CVE-2025-30066)',
    description:
      'Attackers compromised the popular GitHub Action affecting 23,000+ repositories. Malicious code was injected to exfiltrate CI/CD secrets through workflow logs by exploiting expression injection patterns.',
    pattern: 'expression injection in workflow scripts',
  },
  'dangerous-triggers': {
    date: 'November 2025',
    name: 'Shai Hulud Worm',
    description:
      'A self-replicating worm infected 20,000+ repositories and 1,700 npm packages by abusing pull_request_target triggers to steal org-wide tokens and replicate itself across connected repositories.',
    pattern: 'pull_request_target misuse',
  },
  'secrets-exposure': {
    date: 'September 2025',
    name: 'GhostAction Campaign',
    description:
      'Attackers hijacked 327 GitHub accounts, injected malicious workflows into 817 repositories, and stole 3,325 secrets including AWS keys and PyPI/npm tokens through workflow log exfiltration.',
    pattern: 'secret exfiltration via workflow logs',
  },
  permissions: {
    date: 'September 2025',
    name: 'GhostAction Campaign',
    description:
      'Overprivileged GITHUB_TOKEN permissions allowed attackers to escalate from workflow execution to full repository control, creating releases and modifying branch protections.',
    pattern: 'overprivileged token scope',
  },
  'runner-security': {
    date: 'November 2025',
    name: 'Shai Hulud Worm',
    description:
      'Self-hosted runners became persistent backdoors when the worm established command-and-control channels through pull_request_target workflows, surviving across multiple CI runs.',
    pattern: 'self-hosted runner persistence',
  },
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const CATEGORY_PRIORITY: Category[] = [
  'supply-chain',
  'injection',
  'dangerous-triggers',
  'secrets-exposure',
  'permissions',
  'runner-security',
  'ci-cd-hygiene',
  'best-practices',
];

function getHighestSeverityForCategory(
  findings: Finding[],
  category: Category
): number {
  const categoryFindings = findings.filter((f) => f.category === category);
  if (categoryFindings.length === 0) return -1;
  return Math.max(...categoryFindings.map((f) => SEVERITY_ORDER[f.severity]));
}


interface IncidentCardsProps {
  findings: Finding[];
  categories: CategorySummary[];
  score: number;
}

export function IncidentCards({ findings, categories, score }: IncidentCardsProps) {
  // Clean scan: no findings
  if (findings.length === 0) {
    const trivy = INCIDENTS['supply-chain'];
    return (
      <section className="mt-12 pt-8 border-t border-slate-800/50">
        <p className="text-xs font-medium uppercase tracking-wider text-slate-500 mb-4">
          Real-world context
        </p>

        <div className="flex items-start gap-4 mb-6">
          <div className="w-1 self-stretch bg-emerald-500/50 rounded-full flex-shrink-0" />
          <div>
            <p className="text-sm text-slate-300 leading-relaxed">
              Your pipeline passed all checks. But could you detect and respond
              if someone poisoned your CI tomorrow?{' '}
              <span className="text-slate-100 font-medium">
                {trivy.date}:
              </span>{' '}
              {trivy.description}
            </p>
          </div>
        </div>

        <div className="mt-6 flex items-center gap-3">
          <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-emerald-500/70 rounded-full transition-all"
              style={{ width: `${score}%` }}
            />
          </div>
          <p className="text-xs text-slate-500 flex-shrink-0">
            Your score: <span className="text-slate-300">{score}/100</span>
            {' '}&middot;{' '}
            Avg: <span className="text-slate-400">72</span>
          </p>
        </div>
      </section>
    );
  }

  // Build a list of triggered categories sorted by highest severity finding
  const triggeredCategories = categories
    .filter((c) => c.totalFindings > 0)
    .map((c) => ({
      category: c.category,
      maxSeverity: getHighestSeverityForCategory(findings, c.category),
      count: c.totalFindings,
    }))
    .sort((a, b) => {
      // Sort by severity descending
      if (b.maxSeverity !== a.maxSeverity) return b.maxSeverity - a.maxSeverity;
      // Tie-break: prefer supply-chain
      const aPriority = CATEGORY_PRIORITY.indexOf(a.category);
      const bPriority = CATEGORY_PRIORITY.indexOf(b.category);
      return aPriority - bPriority;
    });

  if (triggeredCategories.length === 0) return null;

  // Primary incident: highest severity category
  const primaryCategory = triggeredCategories[0];
  const primaryIncident = INCIDENTS[primaryCategory.category];
  const primaryCount = primaryCategory.count;

  // Secondary incidents: next 1-2 categories that have a mapped incident
  const secondaryIncidents = triggeredCategories
    .slice(1)
    .filter((tc) => INCIDENTS[tc.category])
    .slice(0, 2)
    .map((tc) => INCIDENTS[tc.category]);

  // Fallback content for categories without a mapped incident
  const fallbackMessage =
    '80% of CI/CD breaches exploit misconfigurations, not zero-days.';

  return (
    <section className="mt-12 pt-8 border-t border-slate-800/50">
      <p className="text-xs font-medium uppercase tracking-wider text-slate-500 mb-4">
        Real-world context
      </p>

      {/* Primary incident */}
      <div className="flex items-start gap-4 mb-6">
        <div className="w-1 self-stretch bg-emerald-500/50 rounded-full flex-shrink-0" />
        <div>
          {primaryIncident ? (
            <p className="text-sm text-slate-300 leading-relaxed">
              <span className="text-slate-100 font-medium">
                {primaryIncident.date}:
              </span>{' '}
              {primaryIncident.description} Your scan found the same pattern (
              {primaryIncident.pattern}) in{' '}
              <span className="text-emerald-400 font-medium">
                {primaryCount} workflow{primaryCount !== 1 ? 's' : ''}
              </span>
              .
            </p>
          ) : (
            <p className="text-sm text-slate-300 leading-relaxed">
              {fallbackMessage} Your scan found{' '}
              <span className="text-emerald-400 font-medium">
                {primaryCount} finding{primaryCount !== 1 ? 's' : ''}
              </span>{' '}
              in this category.
            </p>
          )}
        </div>
      </div>

      {/* Secondary incidents */}
      {secondaryIncidents.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 ml-5">
          {secondaryIncidents.map((inc) => (
            <div key={inc.name} className="flex items-start gap-3">
              <div className="w-0.5 self-stretch bg-slate-700 rounded-full flex-shrink-0" />
              <div>
                <p className="text-xs text-slate-500">{inc.date}</p>
                <p className="text-sm text-slate-400">{inc.name}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Benchmark bar */}
      <div className="mt-6 flex items-center gap-3">
        <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
          <div
            className="h-full bg-emerald-500/70 rounded-full transition-all"
            style={{ width: `${score}%` }}
          />
        </div>
        <p className="text-xs text-slate-500 flex-shrink-0">
          Your score: <span className="text-slate-300">{score}/100</span>
          {' '}&middot;{' '}
          Avg: <span className="text-slate-400">72</span>
        </p>
      </div>
    </section>
  );
}
