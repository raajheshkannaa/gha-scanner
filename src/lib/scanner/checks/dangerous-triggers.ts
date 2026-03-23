import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

function getTriggers(parsed: Record<string, unknown>): string[] {
  const on = parsed['on'] ?? parsed['true'];
  if (!on) return [];
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.map(String);
  if (typeof on === 'object' && on !== null) return Object.keys(on);
  return [];
}

function hasOnlyWorkflowCallTrigger(parsed: Record<string, unknown>): boolean {
  const triggers = getTriggers(parsed);
  return triggers.length === 1 && triggers[0] === 'workflow_call';
}

function getJobs(parsed: Record<string, unknown>): Record<string, unknown>[] {
  const jobs = parsed['jobs'];
  if (!jobs || typeof jobs !== 'object') return [];
  return Object.values(jobs as Record<string, unknown>).filter(
    (j): j is Record<string, unknown> => typeof j === 'object' && j !== null
  );
}

function getSteps(job: Record<string, unknown>): Record<string, unknown>[] {
  const steps = job['steps'];
  if (!Array.isArray(steps)) return [];
  return steps.filter(
    (s): s is Record<string, unknown> => typeof s === 'object' && s !== null
  );
}

export const dangerousTriggersChecks: CheckDefinition[] = [
  {
    id: 'triggers/prt-checkout',
    name: 'pull_request_target with head checkout',
    description:
      'Detects pull_request_target workflows that check out the PR head ref, allowing attacker-controlled code to run with write permissions.',
    category: 'dangerous-triggers',
    severity: 'critical',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;
        if (hasOnlyWorkflowCallTrigger(workflow.parsed)) continue;

        const triggers = getTriggers(workflow.parsed);
        if (!triggers.includes('pull_request_target')) continue;

        const jobs = getJobs(workflow.parsed);
        for (const job of jobs) {
          for (const step of getSteps(job)) {
            const uses = String(step['uses'] || '');
            if (!uses.startsWith('actions/checkout')) continue;

            const withBlock = step['with'] as Record<string, unknown> | undefined;
            if (!withBlock) continue;

            const ref = String(withBlock['ref'] || '');
            if (
              ref.includes('github.event.pull_request.head.ref') ||
              ref.includes('github.event.pull_request.head.sha')
            ) {
              const evidence = `ref: ${ref}`;
              findings.push({
                checkId: 'triggers/prt-checkout',
                severity: 'critical',
                category: 'dangerous-triggers',
                title: 'pull_request_target checks out PR head code',
                description:
                  `Workflow "${workflow.name}" uses pull_request_target and checks out the PR head via \`${ref}\`. ` +
                  'This executes attacker-controlled code with the permissions of the base branch, including write access and secrets.',
                risk:
                  'An attacker can open a PR with a malicious workflow modification that runs with full repo write permissions and access to secrets. ' +
                  'This was the attack vector in the GitHub Actions pwn requests research (2021) and has been exploited against major open-source projects.',
                remediation:
                  'Avoid checking out PR head code in pull_request_target workflows. If you must, use a two-workflow pattern:\n\n' +
                  '```yaml\n' +
                  '# Workflow 1: pull_request_target (trusted code only)\n' +
                  'on: pull_request_target\n' +
                  'jobs:\n' +
                  '  build:\n' +
                  '    steps:\n' +
                  '      - uses: actions/checkout@v4  # checks out base, not PR head\n' +
                  '```\n\n' +
                  'If PR code must be analyzed, run it in an isolated job without secrets access, or use `workflow_run` with artifact passing.',
                file: workflow.path,
                line: findLineNumber(workflow.content, evidence),
                evidence,
              });
            }
          }
        }
      }

      return findings;
    },
  },

  {
    id: 'triggers/prt-secrets',
    name: 'pull_request_target with secrets access',
    description:
      'Detects pull_request_target workflows that reference secrets, which may be exposed to forked PR authors.',
    category: 'dangerous-triggers',
    severity: 'high',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;
        if (hasOnlyWorkflowCallTrigger(workflow.parsed)) continue;

        const triggers = getTriggers(workflow.parsed);
        if (!triggers.includes('pull_request_target')) continue;

        const secretsPattern = /\$\{\{\s*secrets\./g;
        let match: RegExpExecArray | null;

        while ((match = secretsPattern.exec(workflow.content)) !== null) {
          const evidence = workflow.content.substring(
            match.index,
            Math.min(match.index + 60, workflow.content.length)
          ).split('\n')[0];

          findings.push({
            checkId: 'triggers/prt-secrets',
            severity: 'high',
            category: 'dangerous-triggers',
            title: 'pull_request_target workflow references secrets',
            description:
              `Workflow "${workflow.name}" uses pull_request_target and references secrets. ` +
              'Combined with any code execution from the PR head, this can leak repository secrets to external contributors.',
            risk:
              'Secrets in pull_request_target workflows are available even for PRs from forks. ' +
              'If any step executes PR-controlled code (even indirectly through build scripts or Makefiles), secrets can be exfiltrated. ' +
              'This pattern was exploited in the 2021 attack against the GitHub Actions ecosystem.',
            remediation:
              'Remove secrets from pull_request_target workflows. Use the `pull_request` event instead (which restricts secrets from forks), or:\n\n' +
              '```yaml\n' +
              '# Pass only the minimum needed via environment\n' +
              'on: pull_request_target\n' +
              'jobs:\n' +
              '  label:\n' +
              '    runs-on: ubuntu-latest\n' +
              '    # Only use secrets in steps that do NOT run PR code\n' +
              '    steps:\n' +
              '      - uses: actions/labeler@v5  # trusted action, no PR code execution\n' +
              '```',
            file: workflow.path,
            line: findLineNumber(workflow.content, evidence),
            evidence,
          });
          break; // One finding per workflow
        }
      }

      return findings;
    },
  },

  {
    id: 'triggers/workflow-run-artifacts',
    name: 'workflow_run with artifact download',
    description:
      'Detects workflow_run triggers that download artifacts, which can be a vector for artifact poisoning attacks.',
    category: 'dangerous-triggers',
    severity: 'medium',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const triggers = getTriggers(workflow.parsed);
        if (!triggers.includes('workflow_run')) continue;

        const jobs = getJobs(workflow.parsed);
        for (const job of jobs) {
          for (const step of getSteps(job)) {
            const uses = String(step['uses'] || '');
            if (!uses.startsWith('actions/download-artifact')) continue;

            const evidence = `uses: ${uses}`;
            findings.push({
              checkId: 'triggers/workflow-run-artifacts',
              severity: 'medium',
              category: 'dangerous-triggers',
              title: 'workflow_run downloads artifacts from triggering workflow',
              description:
                `Workflow "${workflow.name}" uses workflow_run trigger and downloads artifacts. ` +
                'Artifacts from the triggering workflow (often a PR build) may contain attacker-controlled content.',
              risk:
                'Artifacts produced by pull_request workflows can contain malicious payloads. ' +
                'If the workflow_run handler extracts and executes artifact contents (e.g., running scripts, importing code, or using paths from artifact data), ' +
                'an attacker can achieve code execution in a privileged context. This is a known artifact poisoning vector.',
              remediation:
                'Treat all downloaded artifacts as untrusted input:\n\n' +
                '```yaml\n' +
                'on:\n' +
                '  workflow_run:\n' +
                '    workflows: ["Build"]\n' +
                '    types: [completed]\n' +
                'jobs:\n' +
                '  deploy:\n' +
                '    steps:\n' +
                '      - uses: actions/download-artifact@v4\n' +
                '      # Validate artifact contents before use\n' +
                '      - run: |\n' +
                '          # Verify checksums, validate file types\n' +
                '          # Never execute downloaded scripts directly\n' +
                '          sha256sum -c checksums.txt\n' +
                '```\n\n' +
                'Consider using OIDC or signed artifacts instead of relying on artifact download for sensitive deployments.',
              file: workflow.path,
              line: findLineNumber(workflow.content, evidence),
              evidence,
            });
            break; // One finding per workflow
          }
        }
      }

      return findings;
    },
  },
];
