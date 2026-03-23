import type { CheckDefinition, Finding, RepoContext } from '../types';
import { findLineNumber } from '../parser';
import { SENSITIVE_FILE_PATTERNS } from '../data/sensitive-file-patterns';

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

export const secretsExposureChecks: CheckDefinition[] = [
  {
    id: 'secrets/echoed-to-logs',
    name: 'Secrets echoed to logs',
    description:
      'Detects run blocks that echo or print secrets, which exposes them in workflow logs.',
    category: 'secrets-exposure',
    severity: 'critical',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];
      const echoPattern = /(?:echo|printf)\s+.*\$\{\{\s*secrets\.[^}]+\}\}/g;
      const echoPatternQuoted = /(?:echo|printf)\s+"[^"]*\$\{\{\s*secrets\.[^}]+\}\}/g;

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const jobs = getJobs(workflow.parsed);
        for (const job of jobs) {
          for (const step of getSteps(job)) {
            const run = step['run'];
            if (typeof run !== 'string') continue;

            const matches = [
              ...execAll(echoPattern, run),
              ...execAll(echoPatternQuoted, run),
            ];

            // Deduplicate by index
            const seen = new Set<number>();
            for (const match of matches) {
              if (match.index !== undefined && seen.has(match.index)) continue;
              if (match.index !== undefined) seen.add(match.index);

              const evidence = match[0].substring(0, 80);
              findings.push({
                checkId: 'secrets/echoed-to-logs',
                severity: 'critical',
                category: 'secrets-exposure',
                title: 'Secret value echoed to workflow logs',
                description:
                  `Workflow "${workflow.name}" contains a run block that prints a secret value to stdout. ` +
                  'While GitHub attempts to mask secrets in logs, this masking is not foolproof and can be bypassed through encoding, splitting, or indirect output.',
                risk:
                  'Secrets written to logs can be viewed by anyone with read access to the repository (for public repos, this means everyone). ' +
                  'GitHub\'s log masking can be bypassed using base64 encoding, character-by-character output, or writing to files that appear in logs. ' +
                  'The codecov/codecov-action breach (CVE-2021-27027) demonstrated how CI log exposure leads to credential theft at scale.',
                remediation:
                  'Never echo secrets directly. Use them only as environment variables or input parameters:\n\n' +
                  '```yaml\n' +
                  'steps:\n' +
                  '  - run: |\n' +
                  '      # WRONG: echo "${{ secrets.TOKEN }}"\n' +
                  '      # RIGHT: use as environment variable\n' +
                  '      curl -H "Authorization: Bearer $TOKEN" https://api.example.com\n' +
                  '    env:\n' +
                  '      TOKEN: ${{ secrets.TOKEN }}\n' +
                  '```',
                file: workflow.path,
                line: findLineNumber(workflow.content, evidence),
                evidence,
              });
              break; // One finding per step
            }
          }
        }
      }

      return findings;
    },
  },

  {
    id: 'secrets/cli-arguments',
    name: 'Secrets used as inline CLI arguments',
    description:
      'Detects secrets interpolated directly into run blocks instead of being passed as environment variables.',
    category: 'secrets-exposure',
    severity: 'medium',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];
      const secretsInRun = /\$\{\{\s*secrets\.[^}]+\}\}/g;

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const jobs = getJobs(workflow.parsed);
        for (const job of jobs) {
          for (const step of getSteps(job)) {
            const run = step['run'];
            if (typeof run !== 'string') continue;

            const matches = execAll(secretsInRun, run);
            if (matches.length === 0) continue;

            // If the secret expression appears in env values but also in run, it's inline use
            for (const match of matches) {
              const evidence = match[0];

              // Skip if this is just used in env block (the regex matches in `run:` content)
              // Since we're matching in the run string, these are all inline uses
              findings.push({
                checkId: 'secrets/cli-arguments',
                severity: 'medium',
                category: 'secrets-exposure',
                title: 'Secret interpolated directly in shell command',
                description:
                  `Workflow "${workflow.name}" uses a secret expression directly in a \`run:\` block. ` +
                  'This exposes the secret value in the process command line, which may appear in process listings, shell history, or error messages.',
                risk:
                  'Secrets passed as command-line arguments appear in /proc on Linux runners and can be captured by other processes. ' +
                  'If the command fails, error output may include the secret value. This also makes the workflow vulnerable to injection if the secret contains shell metacharacters.',
                remediation:
                  'Pass secrets through environment variables instead of inline interpolation:\n\n' +
                  '```yaml\n' +
                  'steps:\n' +
                  '  - run: curl -H "Authorization: Bearer $TOKEN" https://api.example.com\n' +
                  '    env:\n' +
                  '      TOKEN: ${{ secrets.API_TOKEN }}\n' +
                  '```\n\n' +
                  'Environment variables are not visible in process listings and are the recommended way to pass secrets to shell commands.',
                file: workflow.path,
                line: findLineNumber(workflow.content, evidence),
                evidence,
              });
              break; // One finding per step
            }
          }
        }
      }

      return findings;
    },
  },

  {
    id: 'secrets/credential-persistence',
    name: 'Git credential persistence in checkout',
    description:
      'Detects actions/checkout steps that leave Git credentials persisted in .git/config.',
    category: 'secrets-exposure',
    severity: 'medium',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const jobs = getJobs(workflow.parsed);
        const checkoutSteps: string[] = [];
        let stepCounter = 0;

        for (const job of jobs) {
          for (const step of getSteps(job)) {
            stepCounter++;
            const uses = String(step['uses'] || '');
            if (!uses.startsWith('actions/checkout')) continue;

            const withBlock = step['with'] as Record<string, unknown> | undefined;
            const persistCredentials = withBlock?.['persist-credentials'];

            // Default is true; flag if not explicitly set to false
            if (persistCredentials === false || persistCredentials === 'false') continue;

            const stepName = typeof step['name'] === 'string' ? step['name'] : `step ${stepCounter}`;
            checkoutSteps.push(`${stepName} (${uses})`);
          }
        }

        if (checkoutSteps.length > 0) {
          findings.push({
            checkId: 'secrets/credential-persistence',
            severity: 'medium',
            category: 'secrets-exposure',
            title: `${checkoutSteps.length} checkout step${checkoutSteps.length === 1 ? '' : 's'} persist credentials in ${workflow.name}`,
            description:
              `Workflow "${workflow.name}" has ${checkoutSteps.length} checkout step${checkoutSteps.length === 1 ? '' : 's'} without \`persist-credentials: false\`. ` +
              'By default, the checkout action stores the GITHUB_TOKEN in the local .git/config, making it available to all subsequent steps.',
            risk:
              'Any subsequent step (including third-party actions) can read the persisted token from .git/config. ' +
              'If a later action is compromised, it can use this token to push code, create releases, or access the GitHub API with the workflow\'s permissions.',
            remediation:
              'Set `persist-credentials: false` on checkout steps:\n\n' +
              '```yaml\n' +
              'steps:\n' +
              '  - uses: actions/checkout@v4\n' +
              '    with:\n' +
              '      persist-credentials: false\n' +
              '```\n\n' +
              'When you need to push changes, explicitly configure Git credentials for only the step that needs them.',
            file: workflow.path,
            line: findLineNumber(workflow.content, 'actions/checkout'),
            evidence: `${checkoutSteps.length} checkout step${checkoutSteps.length === 1 ? '' : 's'} with persisted credentials:\n${checkoutSteps.join('\n')}`,
          });
        }
      }

      return findings;
    },
  },

  {
    id: 'secrets/artifact-leakage',
    name: 'Sensitive files in uploaded artifacts',
    description:
      'Detects upload-artifact steps whose path includes potentially sensitive file patterns.',
    category: 'secrets-exposure',
    severity: 'medium',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const jobs = getJobs(workflow.parsed);
        for (const job of jobs) {
          for (const step of getSteps(job)) {
            const uses = String(step['uses'] || '');
            if (!uses.startsWith('actions/upload-artifact')) continue;

            const withBlock = step['with'] as Record<string, unknown> | undefined;
            if (!withBlock) continue;

            const artifactPath = String(withBlock['path'] || '');
            if (!artifactPath) continue;

            for (const pattern of SENSITIVE_FILE_PATTERNS) {
              // Check if the artifact path contains the sensitive pattern
              const plainPattern = pattern.replace(/\*/g, '');
              if (
                artifactPath.includes(pattern) ||
                (plainPattern && artifactPath.includes(plainPattern))
              ) {
                const evidence = `upload-artifact path: ${artifactPath} (matches sensitive pattern: ${pattern})`;
                findings.push({
                  checkId: 'secrets/artifact-leakage',
                  severity: 'medium',
                  category: 'secrets-exposure',
                  title: 'Potentially sensitive files included in uploaded artifact',
                  description:
                    `Workflow "${workflow.name}" uploads an artifact with path "${artifactPath}" which matches sensitive file pattern "${pattern}". ` +
                    'This may inadvertently include credentials, private keys, or configuration files with secrets.',
                  risk:
                    'Workflow artifacts are downloadable by anyone with read access to the repository. ' +
                    'Accidentally uploading credential files, private keys, or environment files exposes secrets to unauthorized parties. ' +
                    'Artifacts persist for the configured retention period (default 90 days).',
                  remediation:
                    'Review the artifact path and exclude sensitive files:\n\n' +
                    '```yaml\n' +
                    'steps:\n' +
                    '  - uses: actions/upload-artifact@v4\n' +
                    '    with:\n' +
                    '      name: build-output\n' +
                    '      path: |\n' +
                    '        dist/\n' +
                    '        !dist/**/*.env\n' +
                    '        !dist/**/*.key\n' +
                    '        !dist/**/*.pem\n' +
                    '```\n\n' +
                    'Use the exclusion pattern (`!`) to filter out sensitive files from artifact uploads.',
                  file: workflow.path,
                  line: findLineNumber(workflow.content, artifactPath),
                  evidence,
                });
                break; // One match per step
              }
            }
          }
        }
      }

      return findings;
    },
  },
];
