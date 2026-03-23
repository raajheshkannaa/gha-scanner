import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

function getJobs(parsed: Record<string, unknown>): [string, Record<string, unknown>][] {
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return [];
  return Object.entries(jobs as Record<string, unknown>).filter(
    (entry): entry is [string, Record<string, unknown>] =>
      typeof entry[1] === 'object' && entry[1] !== null
  );
}

function countWriteScopes(permissions: Record<string, unknown>): number {
  return Object.values(permissions).filter((v) => v === 'write').length;
}

export const permissionsChecks: CheckDefinition[] = [
  {
    id: 'permissions/missing-block',
    name: 'Missing top-level permissions',
    description:
      'Checks whether workflows declare a top-level permissions block to restrict the default GITHUB_TOKEN scope.',
    category: 'permissions',
    severity: 'medium',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        if (!('permissions' in workflow.parsed)) {
          findings.push({
            checkId: 'permissions/missing-block',
            severity: 'medium',
            category: 'permissions',
            title: 'No top-level permissions block defined',
            description:
              `Workflow "${workflow.name}" does not declare a top-level \`permissions:\` block. ` +
              'Without explicit permissions, the GITHUB_TOKEN receives the default permissions configured in repository settings (often read-write for all scopes).',
            risk:
              'The default GITHUB_TOKEN permissions may grant write access to contents, packages, issues, and more. ' +
              'If a workflow is compromised (e.g., through injection or a supply chain attack), the broad token scope increases blast radius. ' +
              'GitHub recommends setting the default to read-only and explicitly granting write scopes per workflow.',
            remediation:
              'Add a top-level permissions block with the minimum required scopes:\n\n' +
              '```yaml\n' +
              'permissions:\n' +
              '  contents: read\n' +
              '  # Add only the write scopes this workflow actually needs\n' +
              '```\n\n' +
              'Also set the repository default to read-only in Settings > Actions > General > Workflow permissions.',
            file: workflow.path,
            line: 1,
            evidence: 'No permissions key found in workflow',
          });
        }
      }

      return findings;
    },
  },

  {
    id: 'permissions/overly-broad',
    name: 'Overly broad permissions',
    description:
      'Detects workflows that grant write-all or many write scopes at the top level.',
    category: 'permissions',
    severity: 'high',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const permissions = workflow.parsed['permissions'];
        if (!permissions) continue;

        let evidence = '';
        let isOverlyBroad = false;

        if (permissions === 'write-all') {
          isOverlyBroad = true;
          evidence = 'permissions: write-all';
        } else if (typeof permissions === 'object' && permissions !== null) {
          const writeCount = countWriteScopes(permissions as Record<string, unknown>);
          if (writeCount >= 3) {
            isOverlyBroad = true;
            const writeScopes = Object.entries(permissions as Record<string, unknown>)
              .filter(([, v]) => v === 'write')
              .map(([k]) => k);
            evidence = `permissions with ${writeCount} write scopes: ${writeScopes.join(', ')}`;
          }
        }

        if (isOverlyBroad) {
          findings.push({
            checkId: 'permissions/overly-broad',
            severity: 'high',
            category: 'permissions',
            title: 'Overly broad GITHUB_TOKEN permissions',
            description:
              `Workflow "${workflow.name}" grants excessive write permissions to the GITHUB_TOKEN. ${evidence}.`,
            risk:
              'Broad token permissions increase the impact of any workflow compromise. ' +
              'An attacker exploiting an injection or compromised action gains write access to multiple repository resources. ' +
              'The principle of least privilege should be applied to CI/CD tokens.',
            remediation:
              'Restrict permissions to only what the workflow needs:\n\n' +
              '```yaml\n' +
              'permissions:\n' +
              '  contents: read\n' +
              '  pull-requests: write  # only if needed\n' +
              '```\n\n' +
              'Split workflows that need different permissions into separate files, each with minimal scopes.',
            file: workflow.path,
            line: findLineNumber(workflow.content, 'permissions'),
            evidence,
          });
        }
      }

      return findings;
    },
  },

  {
    id: 'permissions/missing-job-level',
    name: 'Missing job-level permission overrides',
    description:
      'Detects workflows with broad top-level permissions where individual jobs do not narrow the scope.',
    category: 'permissions',
    severity: 'medium',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const permissions = workflow.parsed['permissions'];
        if (!permissions) continue;

        let isBroad = false;
        if (permissions === 'write-all') {
          isBroad = true;
        } else if (typeof permissions === 'object' && permissions !== null) {
          const writeCount = countWriteScopes(permissions as Record<string, unknown>);
          if (writeCount >= 2) {
            isBroad = true;
          }
        }

        if (!isBroad) continue;

        const jobs = getJobs(workflow.parsed);
        for (const [jobName, job] of jobs) {
          if (!('permissions' in job)) {
            findings.push({
              checkId: 'permissions/missing-job-level',
              severity: 'medium',
              category: 'permissions',
              title: `Job "${jobName}" does not override broad top-level permissions`,
              description:
                `Workflow "${workflow.name}" has broad top-level permissions, but job "${jobName}" does not define its own \`permissions:\` block. ` +
                'The job inherits all top-level permissions, which may be more than it needs.',
              risk:
                'Each job in a workflow may have different permission requirements. Without job-level overrides, every job gets the broadest permissions declared at the workflow level. ' +
                'A compromise in any job gains access to all granted scopes.',
              remediation:
                'Add job-level permissions to restrict each job to its minimum required scopes:\n\n' +
                '```yaml\n' +
                'jobs:\n' +
                `  ${jobName}:\n` +
                '    permissions:\n' +
                '      contents: read  # only what this specific job needs\n' +
                '    steps:\n' +
                '      - ...\n' +
                '```',
              file: workflow.path,
              line: findLineNumber(workflow.content, `${jobName}:`),
              evidence: `Job "${jobName}" inherits broad top-level permissions without override`,
            });
          }
        }
      }

      return findings;
    },
  },
];
