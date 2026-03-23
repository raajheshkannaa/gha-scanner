import { parseRepoInput } from './lib/utils/parse-repo';
import { fetchRepoContext, GitHubNotFoundError, GitHubRateLimitError } from './lib/github/fetch-workflows';
import { runScan } from './lib/scanner/engine';
import type { ScanResult, Finding, Severity } from './lib/scanner/types';

// ---------------------------------------------------------------------------
// Input sanitization
// ---------------------------------------------------------------------------

function sanitize(s: string): string {
  return s.replace(/[\x00-\x1f\x7f]/g, '');
}

// ---------------------------------------------------------------------------
// ANSI color helpers (no dependencies)
// ---------------------------------------------------------------------------

const isColorSupported = process.stdout.isTTY && !process.env.NO_COLOR;

const c = {
  reset: isColorSupported ? '\x1b[0m' : '',
  bold: isColorSupported ? '\x1b[1m' : '',
  dim: isColorSupported ? '\x1b[2m' : '',
  red: isColorSupported ? '\x1b[31m' : '',
  green: isColorSupported ? '\x1b[32m' : '',
  yellow: isColorSupported ? '\x1b[33m' : '',
  blue: isColorSupported ? '\x1b[34m' : '',
  cyan: isColorSupported ? '\x1b[36m' : '',
  gray: isColorSupported ? '\x1b[90m' : '',
};

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

interface CliArgs {
  repo: string | null;
  token: string | null;
  json: boolean;
  markdown: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    repo: null,
    token: null,
    json: false,
    markdown: false,
    help: false,
  };

  const positional: string[] = [];

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      args.help = true;
    } else if (arg === '--json') {
      args.json = true;
    } else if (arg === '--markdown' || arg === '--md') {
      args.markdown = true;
    } else if (arg === '--token') {
      if (i + 1 >= argv.length) {
        console.error('Error: --token requires a value.');
        process.exit(2);
      }
      args.token = argv[++i];
    } else if (arg.startsWith('--token=')) {
      const val = arg.slice('--token='.length).trim();
      if (!val) {
        console.error('Error: --token requires a non-empty value.');
        process.exit(2);
      }
      args.token = val;
    } else if (!arg.startsWith('-')) {
      positional.push(arg);
    }
  }

  args.repo = positional[0] ?? null;
  return args;
}

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------

function printHelp(): void {
  console.log(`
${c.bold}GHA Scanner${c.reset} - GitHub Actions Security Scanner

${c.bold}USAGE${c.reset}
  gha-scanner <owner/repo>                Scan a repository
  gha-scanner <github-url>                Scan from a GitHub URL
  gha-scanner owner/repo --json           Output results as JSON
  gha-scanner owner/repo --markdown       Output results as Markdown

${c.bold}OPTIONS${c.reset}
  --token <token>    GitHub personal access token (or set GITHUB_TOKEN env var)
  --json             Output raw JSON results
  --markdown, --md   Output Markdown report
  -h, --help         Show this help message

${c.bold}EXAMPLES${c.reset}
  gha-scanner facebook/react
  gha-scanner https://github.com/actions/checkout
  GITHUB_TOKEN=ghp_xxx gha-scanner owner/repo --json

${c.bold}EXIT CODES${c.reset}
  0    Clean scan (no critical or high findings)
  1    Findings with critical or high severity
  2    Error (invalid input, network failure, etc.)
`);
}

// ---------------------------------------------------------------------------
// Severity styling
// ---------------------------------------------------------------------------

function severityColor(severity: Severity): string {
  switch (severity) {
    case 'critical': return c.red;
    case 'high': return c.yellow;
    case 'medium': return c.yellow;
    case 'low': return c.blue;
    case 'info': return c.gray;
  }
}

function gradeColor(grade: string): string {
  if (grade === 'A' || grade === 'B') return c.green;
  if (grade === 'C') return c.yellow;
  return c.red;
}

// ---------------------------------------------------------------------------
// Terminal output formatter
// ---------------------------------------------------------------------------

function formatTerminal(result: ScanResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`${c.bold}GHA Scanner${c.reset} - GitHub Actions Security Scanner`);
  lines.push('');

  const gc = gradeColor(result.grade);
  lines.push(
    `${c.bold}Grade: ${gc}${result.grade}${c.reset} ${c.dim}(${result.score}/100)${c.reset} | ` +
    `${result.workflowCount} workflows | ` +
    `${result.findings.length} findings | ` +
    `${result.duration}ms`
  );

  if (result.warnings.length > 0) {
    lines.push('');
    for (const w of result.warnings) {
      lines.push(`  ${c.yellow}warning:${c.reset} ${w}`);
    }
  }

  // Group findings by severity
  const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const grouped = new Map<Severity, Finding[]>();

  for (const sev of severityOrder) {
    grouped.set(sev, []);
  }
  for (const f of result.findings) {
    grouped.get(f.severity)!.push(f);
  }

  for (const sev of severityOrder) {
    const findings = grouped.get(sev)!;
    if (findings.length === 0) continue;

    const sc = severityColor(sev);
    lines.push('');
    lines.push(`  ${c.bold}${sc}${sev.toUpperCase()} (${findings.length})${c.reset}`);

    for (const f of findings) {
      const location = f.line ? `${f.file}:${f.line}` : f.file;
      lines.push(`    ${sc}[${sev}]${c.reset} ${f.title}`);
      lines.push(`           ${c.dim}${location}${c.reset}`);
    }
  }

  lines.push('');
  lines.push(`${c.dim}---${c.reset}`);
  lines.push(
    `${c.dim}Scanned commit ${(result.headSha || 'unknown').slice(0, 7)} on ${result.scannedAt.split('T')[0]}${c.reset}`
  );
  lines.push('');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Markdown output formatter
// ---------------------------------------------------------------------------

function formatMarkdown(result: ScanResult): string {
  const lines: string[] = [];

  lines.push(`# GHA Scanner Report: ${result.repo}`);
  lines.push('');
  lines.push(`**Grade:** ${result.grade} (${result.score}/100)`);
  lines.push(`**Workflows:** ${result.workflowCount}`);
  lines.push(`**Findings:** ${result.findings.length}`);
  lines.push(`**Scan duration:** ${result.duration}ms`);
  lines.push(`**Commit:** \`${(result.headSha || 'unknown').slice(0, 7)}\``);
  lines.push(`**Scanned at:** ${result.scannedAt}`);
  lines.push('');

  if (result.warnings.length > 0) {
    lines.push('## Warnings');
    lines.push('');
    for (const w of result.warnings) {
      lines.push(`- ${w}`);
    }
    lines.push('');
  }

  const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

  for (const sev of severityOrder) {
    const findings = result.findings.filter((f) => f.severity === sev);
    if (findings.length === 0) continue;

    lines.push(`## ${sev.charAt(0).toUpperCase() + sev.slice(1)} (${findings.length})`);
    lines.push('');

    for (const f of findings) {
      const location = f.line ? `${f.file}:${f.line}` : f.file;
      lines.push(`- **${f.title}**`);
      lines.push(`  - File: \`${location}\``);
      lines.push(`  - ${f.description}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = parseArgs(process.argv);

  if (args.help) {
    printHelp();
    process.exit(0);
  }

  if (!args.repo) {
    console.error(`${c.red}Error:${c.reset} Missing repository argument.`);
    console.error(`Usage: gha-scanner <owner/repo>`);
    console.error(`Run gha-scanner --help for more information.`);
    process.exit(2);
  }

  // Set token if provided via flag
  if (args.token) {
    process.env.GITHUB_TOKEN = args.token;
  }

  const parsed = parseRepoInput(args.repo);
  if (!parsed) {
    console.error(`${c.red}Error:${c.reset} Invalid repository format: ${sanitize(args.repo)}`);
    console.error(`Expected: owner/repo or https://github.com/owner/repo`);
    process.exit(2);
  }

  const { owner, repo } = parsed;

  if (!args.json) {
    process.stderr.write(`\nScanning ${owner}/${repo}...\n`);
  }

  try {
    const context = await fetchRepoContext(owner, repo);
    const result = runScan(context);

    if (args.json) {
      console.log(JSON.stringify(result, null, 2));
    } else if (args.markdown) {
      console.log(formatMarkdown(result));
    } else {
      console.log(formatTerminal(result));
    }

    // Exit code based on findings
    const hasCriticalOrHigh = result.findings.some(
      (f) => f.severity === 'critical' || f.severity === 'high'
    );
    process.exit(hasCriticalOrHigh ? 1 : 0);
  } catch (err) {
    if (err instanceof GitHubNotFoundError) {
      console.error(`${c.red}Error:${c.reset} ${err.message}`);
      process.exit(2);
    }
    if (err instanceof GitHubRateLimitError) {
      console.error(`${c.red}Error:${c.reset} ${err.message}`);
      console.error(`Tip: Set GITHUB_TOKEN to increase your rate limit.`);
      process.exit(2);
    }
    if (err instanceof Error) {
      console.error(`${c.red}Error:${c.reset} ${err.message}`);
    } else {
      console.error(`${c.red}Error:${c.reset} An unexpected error occurred.`);
    }
    process.exit(2);
  }
}

main();
