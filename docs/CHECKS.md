# Security Checks

25 checks across 8 categories.

## Supply Chain and Action Pinning

| Check | Severity | Description |
|-------|----------|-------------|
| Unpinned GitHub Actions | Medium | Actions pinned by semver tag instead of commit SHA |
| Actions Pinned to Mutable Branch Refs | High | Actions pinned to `main`, `master`, or other branch names |
| Known Vulnerable Actions | Critical | Actions with known CVEs or confirmed supply chain compromises |
| Docker Actions with Mutable Tags | High | Docker actions using `:latest` or no tag |

## Workflow Injection

| Check | Severity | Description |
|-------|----------|-------------|
| Event Expression in Run Block | Low | `${{ github.event.* }}` expressions used directly in shell scripts |
| Dangerous Context Variable in Run Block | Critical | Attacker-controlled context variables (`head.ref`, `title`, `body`) in run blocks |
| Workflow Dispatch Input in Run Block | Medium | `workflow_dispatch` inputs interpolated into shell commands |

## Dangerous Triggers

| Check | Severity | Description |
|-------|----------|-------------|
| pull_request_target with Head Checkout | Critical | Checks out PR head code with base branch permissions and secrets |
| pull_request_target with Secrets Access | High | Secrets accessible in workflows triggered by fork PRs |
| workflow_run with Artifact Download | Medium | Artifact poisoning vector via workflow_run trigger |

## Permissions

| Check | Severity | Description |
|-------|----------|-------------|
| Missing Top-Level Permissions | Medium | No explicit `permissions:` block, inherits potentially broad repo defaults |
| Overly Broad Permissions | High | `write-all` or 3+ write scopes granted to GITHUB_TOKEN |
| Missing Job-Level Permission Overrides | Medium | Broad top-level permissions not narrowed at job level |

## Secrets and Data Exposure

| Check | Severity | Description |
|-------|----------|-------------|
| Secrets Echoed to Logs | Critical | Secrets printed via `echo` or `printf` in run blocks |
| Secrets as Inline CLI Arguments | Medium | Secrets interpolated directly into shell commands instead of env vars |
| Git Credential Persistence in Checkout | Medium | `actions/checkout` without `persist-credentials: false` |
| Sensitive Files in Uploaded Artifacts | Medium | Artifact uploads matching sensitive file patterns (.env, .pem, .key) |

## Runner Security

| Check | Severity | Description |
|-------|----------|-------------|
| Self-Hosted Runner on pull_request | Critical | Fork PRs can execute arbitrary code on self-hosted infrastructure |
| Self-Hosted Runner with Untrusted Triggers | High | Self-hosted runners used with external input triggers |
| Privileged Docker Execution | High | `--privileged` flag or Docker socket mounting in run blocks |

## CI/CD Hygiene

| Check | Severity | Description |
|-------|----------|-------------|
| No Concurrency Controls | Info | Missing `concurrency:` group allows duplicate workflow runs |
| No Job Timeout Defined | Info | Missing `timeout-minutes` defaults to 6-hour timeout |
| Steps with continue-on-error | Medium | `continue-on-error: true` can silently mask security check failures |

## Best Practices

| Check | Severity | Description |
|-------|----------|-------------|
| No Dependabot for GitHub Actions | Medium | Missing or incomplete Dependabot configuration for actions ecosystem |
| No CODEOWNERS for Workflow Files | Low | No mandatory code review for workflow file changes |

## Scoring

Each finding contributes its severity weight, capped at 3 findings per check:

| Severity | Weight |
|----------|--------|
| Critical | 10 |
| High | 7 |
| Medium | 4 |
| Low | 2 |
| Info | 0 |

Score = `100 * (1 - failedWeight / maxPossibleWeight)`

| Grade | Score |
|-------|-------|
| A | 90-100 |
| B | 80-89 |
| C | 70-79 |
| D | 60-69 |
| F | 0-59 |
