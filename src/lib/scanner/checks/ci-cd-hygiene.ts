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

function getSteps(job: Record<string, unknown>): Record<string, unknown>[] {
  const steps = job['steps'];
  if (!Array.isArray(steps)) return [];
  return steps.filter(
    (s): s is Record<string, unknown> => typeof s === 'object' && s !== null
  );
}

export const ciCdHygieneChecks: CheckDefinition[] = [
  {
    id: 'hygiene/no-concurrency',
    name: 'No concurrency controls',
    description:
      'Checks whether workflows define concurrency groups to prevent duplicate or conflicting runs.',
    category: 'ci-cd-hygiene',
    severity: 'info',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        // Check workflow-level concurrency
        if ('concurrency' in workflow.parsed) continue;

        // Check if any job has concurrency
        const jobs = getJobs(workflow.parsed);
        const anyJobHasConcurrency = jobs.some(([, job]) => 'concurrency' in job);
        if (anyJobHasConcurrency) continue;

        findings.push({
          checkId: 'hygiene/no-concurrency',
          severity: 'info',
          category: 'ci-cd-hygiene',
          title: 'Workflow has no concurrency controls',
          description:
            `Workflow "${workflow.name}" does not define a \`concurrency:\` group at the workflow or job level. ` +
            'Without concurrency controls, multiple instances of the same workflow can run simultaneously.',
          risk:
            'Concurrent workflow runs can cause race conditions in deployments, duplicate notifications, wasted compute costs, ' +
            'and conflicts when multiple runs modify the same resources. For deployment workflows, this can lead to inconsistent states.',
          remediation:
            'Add a concurrency group to prevent duplicate runs:\n\n' +
            '```yaml\n' +
            'concurrency:\n' +
            '  group: ${{ github.workflow }}-${{ github.ref }}\n' +
            '  cancel-in-progress: true  # cancel older runs for the same branch\n' +
            '```\n\n' +
            'For deployment workflows, omit `cancel-in-progress` to ensure deployments complete.',
          file: workflow.path,
          line: 1,
          evidence: 'No concurrency key found in workflow or jobs',
        });
      }

      return findings;
    },
  },

  {
    id: 'hygiene/no-timeout',
    name: 'No job timeout defined',
    description:
      'Checks whether jobs define timeout-minutes to prevent runaway builds.',
    category: 'ci-cd-hygiene',
    severity: 'info',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const jobs = getJobs(workflow.parsed);
        let allJobsHaveTimeout = true;

        for (const [, job] of jobs) {
          if (!('timeout-minutes' in job)) {
            allJobsHaveTimeout = false;
            break;
          }
        }

        if (!allJobsHaveTimeout && jobs.length > 0) {
          const jobsWithout = jobs
            .filter(([, job]) => !('timeout-minutes' in job))
            .map(([name]) => name);

          findings.push({
            checkId: 'hygiene/no-timeout',
            severity: 'info',
            category: 'ci-cd-hygiene',
            title: 'Jobs without timeout-minutes',
            description:
              `Workflow "${workflow.name}" has jobs without \`timeout-minutes\`: ${jobsWithout.join(', ')}. ` +
              'The default timeout is 6 hours (360 minutes), which can waste runner capacity if a job hangs.',
            risk:
              'Without explicit timeouts, a hung job (e.g., waiting on a network resource, stuck in an infinite loop, or a cryptominer injected via a compromised dependency) ' +
              'will consume runner minutes for up to 6 hours. For self-hosted runners, this can block other jobs. ' +
              'Attackers have exploited long-running CI jobs for cryptocurrency mining.',
            remediation:
              'Set appropriate timeouts on all jobs:\n\n' +
              '```yaml\n' +
              'jobs:\n' +
              '  build:\n' +
              '    timeout-minutes: 15  # adjust based on expected duration\n' +
              '    runs-on: ubuntu-latest\n' +
              '    steps:\n' +
              '      - ...\n' +
              '```',
            file: workflow.path,
            line: findLineNumber(workflow.content, jobsWithout[0] + ':'),
            evidence: `Jobs without timeout: ${jobsWithout.join(', ')}`,
          });
        }
      }

      return findings;
    },
  },

  {
    id: 'hygiene/continue-on-error',
    name: 'Steps with continue-on-error',
    description:
      'Detects steps with continue-on-error: true, which can mask failures including security check failures.',
    category: 'ci-cd-hygiene',
    severity: 'medium',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const jobs = getJobs(workflow.parsed);
        for (const [jobName, job] of jobs) {
          for (const step of getSteps(job)) {
            const continueOnError = step['continue-on-error'];
            if (continueOnError !== true && continueOnError !== 'true') continue;

            const stepName = String(step['name'] || step['uses'] || step['run'] || 'unnamed step');
            const truncatedName = stepName.substring(0, 60);
            const evidence = `continue-on-error: true (step: ${truncatedName})`;

            findings.push({
              checkId: 'hygiene/continue-on-error',
              severity: 'medium',
              category: 'ci-cd-hygiene',
              title: `Step uses continue-on-error in job "${jobName}"`,
              description:
                `Workflow "${workflow.name}" has a step with \`continue-on-error: true\` in job "${jobName}". ` +
                'This causes the job to continue even if this step fails, potentially masking important failures.',
              risk:
                'Using continue-on-error can silently swallow failures from security scanning steps, linting, tests, or validation. ' +
                'An attacker who compromises a dependency may cause a security check to fail, but the pipeline will continue to deploy regardless. ' +
                'This is especially dangerous on steps that run security tools, sign artifacts, or validate inputs.',
              remediation:
                'Remove `continue-on-error: true` or use conditional steps instead:\n\n' +
                '```yaml\n' +
                'steps:\n' +
                '  - id: security-scan\n' +
                '    run: trivy fs .\n' +
                '    # Do NOT use continue-on-error for security checks\n' +
                '\n' +
                '  # If you need optional steps, use conditionals:\n' +
                '  - run: optional-step\n' +
                '    if: always()  # runs regardless, but failure still reported\n' +
                '```',
              file: workflow.path,
              line: findLineNumber(workflow.content, 'continue-on-error'),
              evidence,
            });
          }
        }
      }

      return findings;
    },
  },
];
