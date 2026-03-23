import type { CheckDefinition, Finding, RepoContext } from '../types';

export const bestPracticesChecks: CheckDefinition[] = [
  {
    id: 'practices/no-dependabot',
    name: 'No Dependabot configuration for GitHub Actions',
    description:
      'Checks whether the repository has Dependabot configured to keep GitHub Actions up to date.',
    category: 'best-practices',
    severity: 'medium',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      // Check if dependabot config exists at all
      if (!context.hasDependabot) {
        findings.push({
          checkId: 'practices/no-dependabot',
          severity: 'medium',
          category: 'best-practices',
          title: 'No Dependabot configuration found',
          description:
            'This repository does not have a `.github/dependabot.yml` configuration file. ' +
            'Dependabot automatically creates pull requests to keep dependencies (including GitHub Actions) up to date with security patches.',
          risk:
            'Without automated dependency updates, GitHub Actions used in workflows may fall behind on security patches. ' +
            'The tj-actions/changed-files supply chain attack (CVE-2025-30066) and the Aqua Trivy compromise (March 2026) ' +
            'both demonstrated that outdated or unpinned actions are primary targets. ' +
            'Dependabot helps ensure you are notified of and can quickly adopt security fixes.',
          remediation:
            'Create `.github/dependabot.yml` with at minimum a github-actions ecosystem entry:\n\n' +
            '```yaml\n' +
            'version: 2\n' +
            'updates:\n' +
            '  - package-ecosystem: "github-actions"\n' +
            '    directory: "/"\n' +
            '    schedule:\n' +
            '      interval: "weekly"\n' +
            '```\n\n' +
            'Also consider adding entries for your other package ecosystems (npm, pip, etc.).',
          file: '.github/dependabot.yml',
          evidence: 'No .github/dependabot.yml file found',
        });
        return findings;
      }

      // Check if dependabot config includes github-actions ecosystem
      if (context.dependabotConfig) {
        const updates = context.dependabotConfig['updates'];
        if (Array.isArray(updates)) {
          const hasActionsEcosystem = updates.some(
            (entry: unknown) =>
              typeof entry === 'object' &&
              entry !== null &&
              (entry as Record<string, unknown>)['package-ecosystem'] === 'github-actions'
          );

          if (!hasActionsEcosystem) {
            findings.push({
              checkId: 'practices/no-dependabot',
              severity: 'medium',
              category: 'best-practices',
              title: 'Dependabot not configured for GitHub Actions',
              description:
                'The repository has a Dependabot configuration, but it does not include an entry for the `github-actions` package ecosystem. ' +
                'GitHub Actions dependencies will not receive automated update PRs.',
              risk:
                'While other dependencies may be kept current, GitHub Actions used in workflows will not receive automated security updates. ' +
                'Actions are a common supply chain attack vector, and keeping them updated is critical for catching compromised versions quickly.',
              remediation:
                'Add a github-actions entry to your existing `.github/dependabot.yml`:\n\n' +
                '```yaml\n' +
                'updates:\n' +
                '  # ... existing entries ...\n' +
                '  - package-ecosystem: "github-actions"\n' +
                '    directory: "/"\n' +
                '    schedule:\n' +
                '      interval: "weekly"\n' +
                '```',
              file: '.github/dependabot.yml',
              evidence: 'dependabot.yml exists but missing package-ecosystem: "github-actions"',
            });
          }
        }
      }

      return findings;
    },
  },

  {
    id: 'practices/no-codeowners',
    name: 'No CODEOWNERS for workflow files',
    description:
      'Checks whether the repository has CODEOWNERS rules protecting workflow files from unauthorized changes.',
    category: 'best-practices',
    severity: 'low',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      if (!context.hasCodeowners) {
        findings.push({
          checkId: 'practices/no-codeowners',
          severity: 'low',
          category: 'best-practices',
          title: 'No CODEOWNERS file found',
          description:
            'This repository does not have a CODEOWNERS file. ' +
            'CODEOWNERS enables mandatory code review by designated owners for changes to critical paths like workflow files.',
          risk:
            'Without CODEOWNERS, any contributor with write access can modify workflow files without mandatory review from security-aware team members. ' +
            'Workflow modifications are a high-impact change since they control CI/CD pipelines, have access to secrets, and can modify deployment processes.',
          remediation:
            'Create a CODEOWNERS file (in `.github/CODEOWNERS`, `CODEOWNERS`, or `docs/CODEOWNERS`) with workflow protection:\n\n' +
            '```\n' +
            '# Require security team review for workflow changes\n' +
            '.github/workflows/ @org/security-team\n' +
            '.github/actions/   @org/security-team\n' +
            '```\n\n' +
            'Enable the "Require review from Code Owners" branch protection rule to enforce these reviews.',
          file: 'CODEOWNERS',
          evidence: 'No CODEOWNERS file found in repository',
        });
        return findings;
      }

      // Check if CODEOWNERS covers workflow directory
      if (context.codeownersContent) {
        const lines = context.codeownersContent.split('\n');
        const hasWorkflowRule = lines.some((line) => {
          const trimmed = line.trim();
          if (trimmed.startsWith('#') || trimmed === '') return false;
          return (
            trimmed.includes('.github/workflows') ||
            trimmed.includes('.github/workflows/') ||
            trimmed.includes('.github/')
          );
        });

        if (!hasWorkflowRule) {
          findings.push({
            checkId: 'practices/no-codeowners',
            severity: 'low',
            category: 'best-practices',
            title: 'CODEOWNERS does not protect workflow files',
            description:
              'The repository has a CODEOWNERS file, but it does not include a rule for `.github/workflows/`. ' +
              'Workflow files can be modified without mandatory review from designated code owners.',
            risk:
              'Workflow files are high-value targets for supply chain attacks. Without CODEOWNERS protection, ' +
              'a compromised contributor account or a social engineering attack can modify workflow files through PRs ' +
              'that may not receive sufficient security review.',
            remediation:
              'Add a workflow protection rule to your CODEOWNERS file:\n\n' +
              '```\n' +
              '# Require security team review for CI/CD changes\n' +
              '.github/workflows/ @org/security-team\n' +
              '.github/actions/   @org/security-team\n' +
              '.github/dependabot.yml @org/security-team\n' +
              '```',
            file: 'CODEOWNERS',
            evidence: 'CODEOWNERS exists but has no rule for .github/workflows/',
          });
        }
      }

      return findings;
    },
  },
];
