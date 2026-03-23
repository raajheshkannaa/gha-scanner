# Contributing to GHA Scanner

Thanks for your interest in improving GHA Scanner. This guide covers how to add new security checks, update the vulnerability database, run the project locally, and submit changes.

## How to Add a New Security Check

Each check implements the `CheckDefinition` interface defined in `src/lib/scanner/types.ts`:

```typescript
interface CheckDefinition {
  id: string;              // Format: "category/check-name"
  name: string;            // Human-readable name
  description: string;     // What the check detects
  category: Category;      // One of 8 categories (see below)
  severity: Severity;      // 'critical' | 'high' | 'medium' | 'low' | 'info'
  run: (context: RepoContext) => Finding[];
}
```

Categories: `supply-chain`, `injection`, `dangerous-triggers`, `permissions`, `secrets-exposure`, `runner-security`, `ci-cd-hygiene`, `best-practices`.

### Step by Step

1. **Identify the right category file.** Checks live in `src/lib/scanner/checks/<category>.ts`. Pick the file that matches your check's category.

2. **Add your check to the category's exported array.** The check is automatically registered because `src/lib/scanner/checks/index.ts` spreads all category arrays into `allChecks`. No manual registration needed.

3. **Implement the `run` function.** It receives a `RepoContext` and returns `Finding[]`. Return an empty array if nothing is wrong.

4. **Test against real repositories.** Run the scanner against repos that should trigger your check and repos that should not.

### Minimal Example

```typescript
// In src/lib/scanner/checks/permissions.ts

{
  id: 'permissions/id-token-write',
  name: 'Unnecessary id-token write permission',
  description:
    'Detects workflows that grant id-token: write without using OIDC.',
  category: 'permissions',
  severity: 'medium',
  run(context: RepoContext): Finding[] {
    const findings: Finding[] = [];

    for (const workflow of context.workflows) {
      if (!workflow.parsed) continue;

      const permissions = workflow.parsed['permissions'] as
        | Record<string, unknown>
        | undefined;
      if (!permissions || permissions['id-token'] !== 'write') continue;

      // Check if any step actually uses OIDC
      const content = workflow.content;
      if (content.includes('aws-actions/configure-aws-credentials')) continue;
      if (content.includes('google-github-actions/auth')) continue;

      findings.push({
        checkId: 'permissions/id-token-write',
        severity: 'medium',
        category: 'permissions',
        title: 'id-token: write granted but no OIDC action found',
        description:
          `Workflow "${workflow.name}" grants id-token: write permission but does not appear to use OIDC authentication.`,
        risk:
          'Granting id-token: write allows the workflow to request OIDC tokens. If unused, this is an unnecessary permission expansion that increases blast radius.',
        remediation:
          'Remove `id-token: write` from the permissions block if OIDC is not needed.',
        file: workflow.path,
        line: 1,
        evidence: 'permissions: id-token: write',
      });
    }

    return findings;
  },
},
```

### RepoContext Reference

The `run` function receives a `RepoContext` with:

- `context.workflows[]` : Array of workflow files, each with `path`, `name`, `content` (raw YAML), and `parsed` (parsed object or `null`).
- `context.owner` / `context.repo` : Repository identifiers.
- `context.hasDependabot` / `context.dependabotConfig` : Dependabot status and parsed config.
- `context.defaultBranch` : The repository's default branch name.
- `context.headSha` : The HEAD commit SHA that was scanned.
- `context.hasCodeowners` / `context.codeownersContent` : CODEOWNERS status and content.

### Tips for Writing Good Checks

- Always handle `workflow.parsed === null` gracefully.
- Use `findLineNumber(content, searchString)` from `../parser` to locate the relevant line.
- Write clear `risk` and `remediation` text. Include YAML code blocks in remediation.
- Use semantic IDs: `category/descriptive-name`.
- Return one `Finding` per distinct instance. Consolidate where appropriate (e.g., one finding per workflow for credential persistence, not one per step).

### Severity Guidelines

| Severity | Criteria | Score Weight |
|----------|----------|--------------|
| critical | Directly exploitable by external attackers. Enables secret theft, code execution, or pipeline compromise. | 10 |
| high | Exploitable with some preconditions (write access, specific trigger). Significant blast radius. | 7 |
| medium | Concrete security implications but not directly exploitable. Increases attack surface. | 4 |
| low | Hardening recommendation. Improves posture but absence is not directly exploitable. | 2 |
| info | Informational. Does not affect score. Useful context for security-conscious teams. | 0 |

## How to Update the Known-Vulnerable-Actions Database

The CVE database lives in `src/lib/scanner/data/known-vulnerable-actions.ts`.

To add a new entry:

```typescript
{
  action: 'owner/action-name',
  affectedVersions: '< 2.0.0',       // Human-readable version range
  cveId: 'CVE-2026-XXXXX',           // Optional, omit if no CVE assigned
  disclosedDate: '2026-01-15',       // ISO date string
  fixedVersion: '2.0.0',             // Optional, omit if no fix available
  description:
    'Brief description of the vulnerability and its impact.',
},
```

Guidelines:

- Verify the CVE or advisory is confirmed before adding.
- Include the disclosure date for timeline context.
- If no fix exists, omit `fixedVersion`. The scanner will suggest removing or forking the action.
- Do not add entries based on unconfirmed reports.

## Running Locally

```bash
git clone https://github.com/raajheshkannaa/gha-scanner.git
cd gha-scanner
npm install
npm run dev
```

The app runs at `http://localhost:3000`.

### GitHub Token (Optional but Recommended)

Set a `GITHUB_TOKEN` for higher API rate limits:

```bash
export GITHUB_TOKEN=ghp_your_token_here
npm run dev
```

Without a token, the GitHub API allows 60 requests per hour. With a token, 5,000.

### Build and Lint

```bash
npm run build    # TypeScript compilation and Next.js build
npm run build:cli    # Build standalone CLI (dist/cli.js)
node dist/cli.js facebook/react   # Test CLI locally
npm run lint     # ESLint
```

## PR Process

1. **Fork the repository** and create a branch from `main`.
2. **Make your changes.** One check or one concern per PR.
3. **Test locally.** Scan at least 2 repositories to confirm detection works and no false positives are introduced.
4. **Run lint and build.** Both `npm run lint` and `npm run build` must pass.
5. **Open a pull request** with a clear title and description.
6. **Link related issues** if applicable (e.g., "Closes #42").

### What Makes a Good PR

- Focused scope. Do not bundle unrelated changes.
- Include example scan output when adding or modifying a check.
- If fixing a false positive, include the workflow YAML that triggered it.

## Code Conventions

- **TypeScript strict mode.** All scanner code is TypeScript.
- **No em dashes in user-facing text.** Use commas, periods, or rewrite sentences instead.
- **Semantic check IDs.** Format: `category/descriptive-name` (e.g., `supply-chain/unpinned-actions`).
- **Use `import type` for type-only imports.**
- **Named exports only.** No default exports for check arrays.
- **Self-contained checks.** Each check lives in its category file. Shared utilities go in `src/lib/scanner/parser.ts` or `src/lib/scanner/data/`.
- **Copy-pasteable remediation.** Include YAML code blocks showing the corrected pattern.
- **Reference real incidents.** When a check relates to a known attack, mention it in the risk description.

## Reporting Issues

- **False positives:** Use the [false positive issue template](https://github.com/raajheshkannaa/gha-scanner/issues/new?template=false-positive.md).
- **New check proposals:** Use the [new check issue template](https://github.com/raajheshkannaa/gha-scanner/issues/new?template=new-check.md).
- **Security vulnerabilities in the scanner itself:** Please report privately rather than opening a public issue.
