export const DANGEROUS_CONTEXTS: string[] = [
  'github.event.issue.title',
  'github.event.issue.body',
  'github.event.pull_request.title',
  'github.event.pull_request.body',
  'github.event.comment.body',
  'github.event.review.body',
  'github.event.review_comment.body',
  'github.event.pages.*.page_name',
  'github.event.commits.*.message',
  'github.event.commits.*.author.email',
  'github.event.commits.*.author.name',
  'github.event.head_commit.message',
  'github.event.head_commit.author.email',
  'github.event.head_commit.author.name',
  'github.event.workflow_run.head_branch',
  'github.event.workflow_run.head_commit.message',
  'github.event.workflow_run.head_commit.author.email',
  'github.event.discussion.title',
  'github.event.discussion.body',
  'github.head_ref',
  'github.event.workflow_dispatch.inputs.*',
];

// Regex patterns to match these in expressions
// Matches ${{ github.event.issue.title }}, ${{ github.event.pull_request.body }}, etc.
export const DANGEROUS_CONTEXT_PATTERNS: RegExp[] = DANGEROUS_CONTEXTS.map(
  (ctx) => {
    const escaped = ctx.replace(/\./g, '\\.').replace(/\*/g, '[^}]+');
    return new RegExp(`\\$\\{\\{[^}]*${escaped}[^}]*\\}\\}`, 'g');
  }
);
