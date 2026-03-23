import { RepoContext, WorkflowFile } from '../lib/scanner/types';
import { parseWorkflowYaml } from '../lib/scanner/parser';

export function makeContext(workflows: Partial<WorkflowFile>[] = []): RepoContext {
  return {
    owner: 'test-owner',
    repo: 'test-repo',
    defaultBranch: 'main',
    headSha: 'abc1234567890abcdef1234567890abcdef123456',
    workflows: workflows.map((w, i) => ({
      path: w.path ?? `.github/workflows/test-${i}.yml`,
      name: w.name ?? `test-${i}.yml`,
      content: w.content ?? '',
      parsed: w.parsed ?? null,
    })),
    parseWarnings: [],
    hasDependabot: false,
    dependabotConfig: null,
    hasCodeowners: false,
    codeownersContent: null,
  };
}

export function makeWorkflow(yamlContent: string): Partial<WorkflowFile> {
  const { parsed } = parseWorkflowYaml(yamlContent, 'test.yml');
  return {
    content: yamlContent,
    parsed,
  };
}
