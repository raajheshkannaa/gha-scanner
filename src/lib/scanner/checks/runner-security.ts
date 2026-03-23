import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';

function execAll(pattern: RegExp, text: string): RegExpExecArray[] {
  const results: RegExpExecArray[] = [];
  let m: RegExpExecArray | null;
  const re = new RegExp(pattern.source, pattern.flags);
  while ((m = re.exec(text)) !== null) {
    results.push(m);
    if (!re.global) break;
  }
  return results;
}

function getTriggers(parsed: Record<string, unknown>): string[] {
  const on = parsed['on'] ?? parsed['true'];
  if (!on) return [];
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.map(String);
  if (typeof on === 'object' && on !== null) return Object.keys(on);
  return [];
}

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

function runsOnSelfHosted(job: Record<string, unknown>): boolean {
  const runsOn = job['runs-on'];
  if (typeof runsOn === 'string') return runsOn.includes('self-hosted');
  if (Array.isArray(runsOn)) return runsOn.some((r) => String(r).includes('self-hosted'));
  return false;
}

export const runnerSecurityChecks: CheckDefinition[] = [
  {
    id: 'runner/self-hosted-pr',
    name: 'Self-hosted runner on pull_request',
    description:
      'Detects self-hosted runners used with pull_request triggers, allowing fork PRs to execute code on your infrastructure.',
    category: 'runner-security',
    severity: 'critical',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const triggers = getTriggers(workflow.parsed);
        if (!triggers.includes('pull_request')) continue;

        const jobs = getJobs(workflow.parsed);
        for (const [jobName, job] of jobs) {
          if (!runsOnSelfHosted(job)) continue;

          const runsOn = String(job['runs-on']);
          const evidence = `runs-on: ${runsOn} (trigger: pull_request)`;
          findings.push({
            checkId: 'runner/self-hosted-pr',
            severity: 'critical',
            category: 'runner-security',
            title: `Self-hosted runner "${jobName}" exposed to pull_request trigger`,
            description:
              `Workflow "${workflow.name}" runs job "${jobName}" on a self-hosted runner with the \`pull_request\` trigger. ` +
              'Anyone who can open a pull request (including from forks on public repos) can execute arbitrary code on your self-hosted runner.',
            risk:
              'Self-hosted runners are persistent machines, unlike GitHub-hosted ephemeral runners. ' +
              'An attacker can fork the repo, modify the workflow to run malicious code, and open a PR. ' +
              'This grants them shell access to your infrastructure, access to cached credentials, network access to internal resources, ' +
              'and the ability to compromise other jobs that run on the same runner. ' +
              'This was a primary attack vector in the SolarWinds supply chain compromise methodology.',
            remediation:
              'Use GitHub-hosted runners for pull_request workflows, or restrict self-hosted runners:\n\n' +
              '```yaml\n' +
              '# Option 1: Use GitHub-hosted runners for PRs\n' +
              'jobs:\n' +
              `  ${jobName}:\n` +
              '    runs-on: ubuntu-latest  # ephemeral, isolated\n' +
              '\n' +
              '# Option 2: Use environment protection rules\n' +
              'jobs:\n' +
              `  ${jobName}:\n` +
              '    runs-on: self-hosted\n' +
              '    environment: production  # requires approval for fork PRs\n' +
              '```\n\n' +
              'For public repos, never use self-hosted runners with pull_request triggers.',
            file: workflow.path,
            line: findLineNumber(workflow.content, 'self-hosted'),
            evidence,
          });
        }
      }

      return findings;
    },
  },

  {
    id: 'runner/self-hosted-untrusted',
    name: 'Self-hosted runner with untrusted triggers',
    description:
      'Detects self-hosted runners used with triggers that accept external input.',
    category: 'runner-security',
    severity: 'high',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];
      const untrustedTriggers = [
        'pull_request',
        'pull_request_target',
        'issue_comment',
        'discussion_comment',
      ];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const triggers = getTriggers(workflow.parsed);
        const matchingTriggers = triggers.filter((t) => untrustedTriggers.includes(t));
        // Skip if already caught by the more specific self-hosted-pr check
        if (matchingTriggers.length === 0) continue;
        if (matchingTriggers.length === 1 && matchingTriggers[0] === 'pull_request') continue;

        const jobs = getJobs(workflow.parsed);
        for (const [jobName, job] of jobs) {
          if (!runsOnSelfHosted(job)) continue;

          const evidence = `runs-on: ${String(job['runs-on'])} (triggers: ${matchingTriggers.join(', ')})`;
          findings.push({
            checkId: 'runner/self-hosted-untrusted',
            severity: 'high',
            category: 'runner-security',
            title: `Self-hosted runner "${jobName}" used with external input triggers`,
            description:
              `Workflow "${workflow.name}" runs job "${jobName}" on a self-hosted runner with triggers that accept external input: ${matchingTriggers.join(', ')}. ` +
              'These triggers can be activated by external contributors or users.',
            risk:
              'Self-hosted runners persist state between jobs. Triggers like issue_comment and discussion_comment allow any GitHub user to invoke workflows. ' +
              'Combined with a self-hosted runner, this can allow unauthorized code execution on internal infrastructure, ' +
              'access to cached secrets and credentials, and lateral movement within your network.',
            remediation:
              'Move untrusted-trigger workflows to GitHub-hosted runners:\n\n' +
              '```yaml\n' +
              'jobs:\n' +
              `  ${jobName}:\n` +
              '    runs-on: ubuntu-latest\n' +
              '```\n\n' +
              'If you must use self-hosted runners, use runner groups with repository access policies, ' +
              'and always run self-hosted runners in ephemeral (disposable) mode with `--ephemeral` flag.',
            file: workflow.path,
            line: findLineNumber(workflow.content, 'self-hosted'),
            evidence,
          });
        }
      }

      return findings;
    },
  },

  {
    id: 'runner/docker-privilege',
    name: 'Privileged Docker execution',
    description:
      'Detects run blocks that execute Docker with privileged mode or Docker socket mounting.',
    category: 'runner-security',
    severity: 'high',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];
      const privilegedPattern = /docker\s+run\s+[^;\n]*--privileged/g;
      const socketPatternAlt = /-v\s+\/var\/run\/docker\.sock/g;

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const jobs = getJobs(workflow.parsed);
        for (const [, job] of jobs) {
          for (const step of getSteps(job)) {
            const run = step['run'];
            if (typeof run !== 'string') continue;

            const privilegedMatches = execAll(privilegedPattern, run);
            for (const match of privilegedMatches) {
              const evidence = match[0].substring(0, 80);
              findings.push({
                checkId: 'runner/docker-privilege',
                severity: 'high',
                category: 'runner-security',
                title: 'Docker container run with --privileged flag',
                description:
                  `Workflow "${workflow.name}" runs a Docker container with \`--privileged\`, disabling all security isolation between the container and the host.`,
                risk:
                  'The --privileged flag gives the container full access to the host system, including all devices, capabilities, and kernel features. ' +
                  'An attacker who compromises the workflow can escape the container and access the host runner, ' +
                  'other containers, and any secrets or credentials on the machine.',
                remediation:
                  'Remove the `--privileged` flag and use specific capabilities instead:\n\n' +
                  '```yaml\n' +
                  '- run: |\n' +
                  '    docker run --cap-add SYS_PTRACE my-image  # only add needed caps\n' +
                  '```\n\n' +
                  'If privileged access is truly needed, run this on an ephemeral GitHub-hosted runner to limit blast radius.',
                file: workflow.path,
                line: findLineNumber(workflow.content, '--privileged'),
                evidence,
              });
              break;
            }

            const socketMatches = execAll(socketPatternAlt, run);
            for (const match of socketMatches) {
              const evidence = match[0].substring(0, 80);
              findings.push({
                checkId: 'runner/docker-privilege',
                severity: 'high',
                category: 'runner-security',
                title: 'Docker socket mounted into container',
                description:
                  `Workflow "${workflow.name}" mounts the Docker socket (\`/var/run/docker.sock\`) into a container, granting full control over the host's Docker daemon.`,
                risk:
                  'Mounting the Docker socket is equivalent to granting root access to the host. ' +
                  'A compromised container can spawn new privileged containers, access any volume on the host, ' +
                  'and execute arbitrary commands as root. This is a well-known container escape technique.',
                remediation:
                  'Avoid mounting the Docker socket. Use alternatives:\n\n' +
                  '```yaml\n' +
                  '- run: |\n' +
                  '    # Use buildx for building images without socket access\n' +
                  '    docker buildx build --push -t my-image .\n' +
                  '```\n\n' +
                  'If Docker-in-Docker is required, use the `dind` (Docker-in-Docker) service approach with TLS.',
                file: workflow.path,
                line: findLineNumber(workflow.content, '/var/run/docker.sock'),
                evidence,
              });
              break;
            }
          }
        }
      }

      return findings;
    },
  },
];
