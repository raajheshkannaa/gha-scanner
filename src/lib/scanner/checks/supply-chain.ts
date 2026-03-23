import type { CheckDefinition, Finding, RepoContext } from '../types';
import { MUTABLE_REFS } from '../data/mutable-refs';
import { KNOWN_VULNERABLE_ACTIONS } from '../data/known-vulnerable-actions';
import { findLineNumber } from '../parser';

const SHA_PATTERN = /^[0-9a-f]{40}$/;

interface StepUses {
  raw: string;       // full uses: value
  owner: string;     // e.g. "actions"
  action: string;    // e.g. "actions/checkout"
  ref: string;       // e.g. "v4" or a SHA
}

/**
 * Parse a `uses:` value into its components.
 * Returns null for local actions (./), reusable workflows (.github/workflows/), and docker:// refs.
 */
function parseMarketplaceAction(uses: string): StepUses | null {
  const trimmed = uses.trim();

  // Skip local actions
  if (trimmed.startsWith('./') || trimmed.startsWith('../')) return null;

  // Skip docker actions
  if (trimmed.startsWith('docker://')) return null;

  // Skip reusable workflows (contain .github/workflows/)
  if (trimmed.includes('.github/workflows/')) return null;

  // Must have owner/action@ref format
  const atIndex = trimmed.indexOf('@');
  if (atIndex === -1) return null;

  const actionPath = trimmed.substring(0, atIndex);
  const ref = trimmed.substring(atIndex + 1);

  // Must have at least owner/name
  if (!actionPath.includes('/')) return null;

  const owner = actionPath.split('/')[0];

  return {
    raw: trimmed,
    owner,
    action: actionPath,
    ref,
  };
}

/**
 * Extract all steps with `uses:` from all jobs in a workflow.
 */
function extractUsesSteps(
  workflow: { path: string; content: string; parsed: Record<string, unknown> | null }
): Array<{ uses: string; jobId: string; stepIndex: number; file: string; content: string }> {
  const results: Array<{ uses: string; jobId: string; stepIndex: number; file: string; content: string }> = [];

  if (!workflow.parsed) return results;

  const jobs = workflow.parsed.jobs as Record<string, unknown> | undefined;
  if (!jobs || typeof jobs !== 'object') return results;

  for (const [jobId, jobDef] of Object.entries(jobs)) {
    const job = jobDef as Record<string, unknown>;
    const steps = job?.steps as Array<Record<string, unknown>> | undefined;
    if (!Array.isArray(steps)) continue;

    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      if (step && typeof step.uses === 'string') {
        results.push({
          uses: step.uses,
          jobId,
          stepIndex: i,
          file: workflow.path,
          content: workflow.content,
        });
      }
    }
  }

  return results;
}

export const supplyChainChecks: CheckDefinition[] = [
  {
    id: 'supply-chain/unpinned-actions',
    name: 'Unpinned GitHub Actions',
    description:
      'Detects marketplace actions not pinned to a full-length commit SHA, making them vulnerable to tag mutation attacks.',
    category: 'supply-chain',
    severity: 'medium',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        const steps = extractUsesSteps(workflow);
        const unpinnedActions: string[] = [];

        for (const step of steps) {
          const parsed = parseMarketplaceAction(step.uses);
          if (!parsed) continue;

          // Skip if already pinned to SHA
          if (SHA_PATTERN.test(parsed.ref)) continue;

          // Skip if this will be caught by the mutable-refs check (those are critical)
          if (MUTABLE_REFS.includes(parsed.ref)) continue;

          const actionRef = `${parsed.action}@${parsed.ref}`;
          if (!unpinnedActions.includes(actionRef)) {
            unpinnedActions.push(actionRef);
          }
        }

        if (unpinnedActions.length > 0) {
          findings.push({
            checkId: 'supply-chain/unpinned-actions',
            severity: 'medium',
            category: 'supply-chain',
            title: `Workflow ${workflow.name} uses ${unpinnedActions.length} action${unpinnedActions.length === 1 ? '' : 's'} pinned by semver tag instead of SHA`,
            description: `Workflow "${workflow.name}" references ${unpinnedActions.length} action${unpinnedActions.length === 1 ? '' : 's'} by tag instead of commit SHA. Tags are mutable Git refs that can be force-pushed to point at different code at any time.`,
            risk: 'An attacker who compromises the action repository can move the tag to inject malicious code. This is exactly how the tj-actions/changed-files (CVE-2025-30066) and Codecov supply chain attacks worked.',
            remediation: 'Pin all actions to full commit SHAs. Use `gh api repos/OWNER/REPO/git/ref/tags/TAG --jq .object.sha` to resolve each SHA.',
            file: workflow.path,
            line: findLineNumber(workflow.content, unpinnedActions[0].split('@')[0]),
            evidence: unpinnedActions.map(a => `uses: ${a}`).join('\n'),
          });
        }
      }

      return findings;
    },
  },

  {
    id: 'supply-chain/mutable-refs',
    name: 'Actions Pinned to Mutable Branch Refs',
    description:
      'Detects actions pinned to branch names like main, master, or other refs that change with every commit.',
    category: 'supply-chain',
    severity: 'high',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        const steps = extractUsesSteps(workflow);

        for (const step of steps) {
          const parsed = parseMarketplaceAction(step.uses);
          if (!parsed) continue;

          if (!MUTABLE_REFS.includes(parsed.ref)) continue;

          const isSameOrg = parsed.owner === context.owner;
          const severity = isSameOrg ? 'medium' as const : 'high' as const;
          const sameOrgNote = isSameOrg
            ? ' This is a same-org action, so the risk is lower (you control the source), but it should still be pinned to a SHA for auditability and supply chain hygiene.'
            : '';

          findings.push({
            checkId: 'supply-chain/mutable-refs',
            severity,
            category: 'supply-chain',
            title: `Action pinned to mutable ref: ${parsed.action}@${parsed.ref}`,
            description: `The action \`${parsed.action}\` is pinned to \`${parsed.ref}\`, a branch name that changes with every commit. Any push to that branch immediately changes what code runs in your CI.${sameOrgNote}`,
            risk: 'Branch refs are the most dangerous form of action pinning. Unlike version tags (which at least require a force-push to move), branch refs change on every single commit. A compromised maintainer account or a single merged malicious PR in the upstream action repo instantly compromises every workflow that references it.',
            remediation: `Pin to the full commit SHA:\n\n\`\`\`yaml\n# Instead of:\nuses: ${parsed.action}@${parsed.ref}\n# Use:\nuses: ${parsed.action}@<full-40-char-sha> # ${parsed.ref}\n\`\`\`\n\nResolve the SHA: \`gh api repos/${parsed.action}/git/ref/heads/${parsed.ref} --jq .object.sha\``,
            file: step.file,
            line: findLineNumber(step.content, step.uses),
            evidence: `uses: ${step.uses}`,
          });
        }
      }

      return findings;
    },
  },

  {
    id: 'supply-chain/known-vulnerable',
    name: 'Known Vulnerable Actions',
    description:
      'Detects usage of GitHub Actions with known CVEs or confirmed supply chain compromises.',
    category: 'supply-chain',
    severity: 'critical',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        const steps = extractUsesSteps(workflow);

        for (const step of steps) {
          const parsed = parseMarketplaceAction(step.uses);
          if (!parsed) continue;

          const vuln = KNOWN_VULNERABLE_ACTIONS.find(
            (v) => v.action === parsed.action
          );
          if (!vuln) continue;

          const cveLabel = vuln.cveId ? ` (${vuln.cveId})` : '';

          findings.push({
            checkId: 'supply-chain/known-vulnerable',
            severity: 'critical',
            category: 'supply-chain',
            title: `Known vulnerable action: ${parsed.action}${cveLabel}`,
            description: `The action \`${parsed.action}@${parsed.ref}\` has a known vulnerability${cveLabel}. ${vuln.description}`,
            risk: `Affected versions: ${vuln.affectedVersions}. Disclosed: ${vuln.disclosedDate}. This action was involved in a confirmed security incident that could expose CI/CD secrets, source code, or enable arbitrary code execution in your workflows.`,
            remediation: vuln.fixedVersion
              ? `Update to the fixed version and pin by SHA:\n\n\`\`\`yaml\n# Upgrade to ${vuln.fixedVersion} or later, pinned by SHA:\nuses: ${parsed.action}@<sha-of-${vuln.fixedVersion}> # ${vuln.fixedVersion}\n\`\`\`\n\nVerify the fix version SHA: \`gh api repos/${parsed.action}/git/ref/tags/v${vuln.fixedVersion} --jq .object.sha\``
              : `No fixed version is available. Consider removing this action entirely and replacing it with an alternative, or forking a known-good commit:\n\n\`\`\`yaml\n# Fork or vendor the action from a commit BEFORE the compromise\n# Or replace with an alternative action\n\`\`\``,
            file: step.file,
            line: findLineNumber(step.content, step.uses),
            evidence: `uses: ${step.uses}`,
          });
        }
      }

      return findings;
    },
  },

  {
    id: 'supply-chain/docker-mutable-tags',
    name: 'Docker Actions with Mutable Tags',
    description:
      'Detects docker:// action references using mutable tags like :latest or no tag at all.',
    category: 'supply-chain',
    severity: 'high',
    run(context: RepoContext): Finding[] {
      const findings: Finding[] = [];

      for (const workflow of context.workflows) {
        if (!workflow.parsed) continue;

        const jobs = workflow.parsed.jobs as Record<string, unknown> | undefined;
        if (!jobs || typeof jobs !== 'object') continue;

        for (const [, jobDef] of Object.entries(jobs)) {
          const job = jobDef as Record<string, unknown>;
          const steps = job?.steps as Array<Record<string, unknown>> | undefined;
          if (!Array.isArray(steps)) continue;

          for (const step of steps) {
            if (!step || typeof step.uses !== 'string') continue;

            const uses = step.uses.trim();
            if (!uses.startsWith('docker://')) continue;

            const imageRef = uses.substring('docker://'.length);
            const colonIndex = imageRef.lastIndexOf(':');

            let isMutable = false;
            let tag = '';

            if (colonIndex === -1) {
              // No tag specified, defaults to :latest
              isMutable = true;
              tag = '(implicit latest)';
            } else {
              tag = imageRef.substring(colonIndex + 1);
              if (tag === 'latest') {
                isMutable = true;
              }
            }

            if (!isMutable) continue;

            findings.push({
              checkId: 'supply-chain/docker-mutable-tags',
              severity: 'high',
              category: 'supply-chain',
              title: `Docker action with mutable tag: ${uses}`,
              description: `The Docker action \`${uses}\` uses the tag \`${tag}\`, which is mutable and can be overwritten in the registry at any time.`,
              risk: 'Docker image tags (especially `:latest`) are mutable pointers. A compromised registry account or a routine image rebuild can silently change the code running in your CI pipeline. Unlike Git tags, Docker tags are routinely overwritten as part of normal publishing workflows.',
              remediation: `Pin to a specific image digest:\n\n\`\`\`yaml\n# Instead of:\nuses: ${uses}\n# Use:\nuses: docker://${colonIndex === -1 ? imageRef : imageRef.substring(0, colonIndex)}@sha256:<digest>\n\`\`\`\n\nGet the digest: \`docker inspect --format='{{index .RepoDigests 0}}' ${colonIndex === -1 ? imageRef : imageRef.substring(0, colonIndex)}:latest\``,
              file: workflow.path,
              line: findLineNumber(workflow.content, uses),
              evidence: `uses: ${uses}`,
            });
          }
        }
      }

      return findings;
    },
  },
];
