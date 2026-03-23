import type { CheckDefinition, Finding, RepoContext } from '../types';
import { DANGEROUS_CONTEXT_PATTERNS, DANGEROUS_CONTEXTS } from '../data/dangerous-contexts';
import { findLineNumber } from '../parser';

/** Expressions referencing github.event.* inside ${{ }} */
const EVENT_EXPRESSION_PATTERN = /\$\{\{[^}]*github\.event\.[^}]*\}\}/g;

interface RunStep {
  run: string;
  jobId: string;
  stepIndex: number;
  stepName: string | undefined;
  file: string;
  content: string;
}

/**
 * Walk all jobs and steps in a parsed workflow, collecting step objects that have a `run` key.
 */
function walkRunSteps(
  workflow: { path: string; content: string; parsed: Record<string, unknown> | null }
): RunStep[] {
  const results: RunStep[] = [];

  if (!workflow.parsed) return results;

  const jobs = workflow.parsed.jobs as Record<string, unknown> | undefined;
  if (!jobs || typeof jobs !== 'object') return results;

  for (const [jobId, jobDef] of Object.entries(jobs)) {
    const job = jobDef as Record<string, unknown>;
    const steps = job?.steps as Array<Record<string, unknown>> | undefined;
    if (!Array.isArray(steps)) continue;

    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      if (!step || typeof step.run !== 'string') continue;

      results.push({
        run: step.run,
        jobId,
        stepIndex: i,
        stepName: typeof step.name === 'string' ? step.name : undefined,
        file: workflow.path,
        content: workflow.content,
      });
    }
  }

  return results;
}

/**
 * Check if a workflow has workflow_dispatch trigger with inputs defined.
 */
function getWorkflowDispatchInputs(
  parsed: Record<string, unknown>
): string[] | null {
  const on = parsed.on ?? parsed.true; // YAML parses `on:` as `true:` sometimes
  if (!on || typeof on !== 'object') return null;

  const onObj = on as Record<string, unknown>;
  const dispatch = onObj.workflow_dispatch as Record<string, unknown> | undefined;
  if (!dispatch || typeof dispatch !== 'object') return null;

  const inputs = dispatch.inputs as Record<string, unknown> | undefined;
  if (!inputs || typeof inputs !== 'object') return null;

  return Object.keys(inputs);
}

export const injectionChecks: CheckDefinition[] = [
  {
    id: 'injection/expression-in-run',
    name: 'Event Expression in Run Block',
    description:
      'Detects ${{ github.event.* }} expressions used directly inside run: blocks. While not all event properties are attacker-controlled, using them inline is a risky pattern.',
    category: 'injection',
    severity: 'low',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      // Safe event properties that are NOT user-controllable
      const SAFE_EVENT_PROPS = [
        'github.event.pull_request.number',
        'github.event.pull_request.base.sha',
        'github.event.pull_request.base.ref',
        'github.event.pull_request.head.sha',
        'github.event.pull_request.merged',
        'github.event.pull_request.author_association',
        'github.event.pull_request.head.repo.full_name',
        'github.event.number',
        'github.event.action',
        'github.event.sender.login',
        'github.event.repository.full_name',
        'github.event.repository.default_branch',
        'github.event.inputs.',  // handled by dispatch-input check
      ];

      for (const workflow of context.workflows) {
        for (const step of walkRunSteps(workflow)) {
          const matches = step.run.match(EVENT_EXPRESSION_PATTERN);
          if (!matches) continue;

          for (const match of matches) {
            // Skip expressions that only reference safe properties
            const isSafe = SAFE_EVENT_PROPS.some(safe => match.includes(safe));
            if (isSafe) continue;

            // Skip if already caught by dangerous-contexts check (avoid duplicates)
            const isDangerous = DANGEROUS_CONTEXT_PATTERNS.some(p => {
              p.lastIndex = 0;
              return p.test(match);
            });
            if (isDangerous) continue;

            const stepLabel = step.stepName
              ? `step "${step.stepName}"`
              : `step ${step.stepIndex + 1}`;

            findings.push({
              checkId: 'injection/expression-in-run',
              severity: 'low',
              category: 'injection',
              title: `Event expression in run block: ${match}`,
              description: `Job \`${step.jobId}\`, ${stepLabel} uses \`${match}\` directly in a \`run:\` block. While this specific property may not be attacker-controlled, inline event expressions in shell scripts are a risky pattern.`,
              risk: 'Even if the current expression is safe, inline event data in run blocks creates a pattern that can lead to injection vulnerabilities as workflows evolve. A future change might reference a dangerous property in the same style.',
              remediation: `Best practice: assign event data to environment variables:\n\n\`\`\`yaml\n# Current:\n- run: echo "${match}"\n\n# Safer:\n- env:\n    EVENT_VALUE: ${match}\n  run: echo "$EVENT_VALUE"\n\`\`\``,
              file: step.file,
              line: findLineNumber(step.content, match),
              evidence: match,
            });
          }
        }
      }

      return findings;
    },
  },

  {
    id: 'injection/dangerous-contexts',
    name: 'Dangerous Context Variable in Run Block',
    description:
      'Detects specific GitHub context variables known to be attacker-controlled when used in run: blocks.',
    category: 'injection',
    severity: 'critical',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        for (const step of walkRunSteps(workflow)) {
          for (let patIdx = 0; patIdx < DANGEROUS_CONTEXT_PATTERNS.length; patIdx++) {
            const pattern = DANGEROUS_CONTEXT_PATTERNS[patIdx];
            const contextName = DANGEROUS_CONTEXTS[patIdx];

            // Reset regex state (patterns have /g flag)
            pattern.lastIndex = 0;
            const matches = step.run.match(pattern);
            if (!matches) continue;

            for (const match of matches) {
              const stepLabel = step.stepName
                ? `step "${step.stepName}"`
                : `step ${step.stepIndex + 1}`;

              findings.push({
                checkId: 'injection/dangerous-contexts',
                severity: 'critical',
                category: 'injection',
                title: `Dangerous context \`${contextName}\` in run block`,
                description: `Job \`${step.jobId}\`, ${stepLabel} references \`${contextName}\` in a \`run:\` block. This specific context variable is fully controlled by external users.`,
                risk: `The variable \`${contextName}\` can be set by anyone who creates a PR, issue, comment, or push. When interpolated into a \`run:\` block, it becomes executable shell code. Attackers actively scan public repos for this pattern.`,
                remediation: `Move the dangerous context into an environment variable:\n\n\`\`\`yaml\n# Vulnerable:\n- run: echo "${match}"\n\n# Safe:\n- env:\n    SAFE_VAR: \${{ ${contextName} }}\n  run: echo "$SAFE_VAR"\n\`\`\``,
                file: step.file,
                line: findLineNumber(step.content, match),
                evidence: match,
              });
            }
          }
        }
      }

      return findings;
    },
  },

  {
    id: 'injection/dispatch-input',
    name: 'Workflow Dispatch Input in Run Block',
    description:
      'Detects workflow_dispatch input values used directly in run: blocks without sanitization. Exploitation requires write access to the repository.',
    category: 'injection',
    severity: 'medium',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const inputNames = getWorkflowDispatchInputs(workflow.parsed);
        if (!inputNames) continue;

        const dispatchInputPattern = /\$\{\{\s*github\.event\.inputs\.[^}]*\}\}/g;

        for (const step of walkRunSteps(workflow)) {
          dispatchInputPattern.lastIndex = 0;
          const matches = step.run.match(dispatchInputPattern);
          if (!matches) continue;

          for (const match of matches) {
            const stepLabel = step.stepName
              ? `step "${step.stepName}"`
              : `step ${step.stepIndex + 1}`;

            findings.push({
              checkId: 'injection/dispatch-input',
              severity: 'medium',
              category: 'injection',
              title: `Dispatch input in run block: ${match}`,
              description: `Job \`${step.jobId}\`, ${stepLabel} uses workflow_dispatch input \`${match}\` directly in a \`run:\` block. While dispatch inputs are restricted to users with write access, they are still user-supplied strings that should not be interpolated into shell scripts.`,
              risk: 'A compromised or malicious collaborator with write access can trigger the workflow with crafted input values containing shell metacharacters. This is lower risk than PR/issue injection (requires write access) but still violates defense-in-depth.',
              remediation: `Pass the dispatch input through an environment variable:\n\n\`\`\`yaml\n# Vulnerable:\n- run: echo "${match}"\n\n# Safe:\n- env:\n    INPUT_VALUE: ${match}\n  run: echo "$INPUT_VALUE"\n\`\`\``,
              file: step.file,
              line: findLineNumber(step.content, match),
              evidence: match,
            });
          }
        }
      }

      return findings;
    },
  },
];
