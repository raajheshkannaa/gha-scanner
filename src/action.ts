import { parseRepoInput } from './lib/utils/parse-repo';
import { fetchRepoContext } from './lib/github/fetch-workflows';
import { runScan } from './lib/scanner/engine';
import type { Severity, ScanResult } from './lib/scanner/types';
import * as fs from 'fs';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0, none: -1
};

function getInput(name: string): string {
  return process.env[`INPUT_${name.toUpperCase().replace(/-/g, '_')}`] || '';
}

function setOutput(name: string, value: string) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    fs.appendFileSync(outputFile, `${name}=${value}\n`);
  }
}

function writeSummary(md: string) {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) {
    fs.appendFileSync(summaryFile, md);
  }
}

async function run() {
  const repo = process.env.GITHUB_REPOSITORY;
  if (!repo) {
    console.error('Error: GITHUB_REPOSITORY not set');
    process.exit(1);
  }

  const token = getInput('token') || process.env.GITHUB_TOKEN;
  if (token) process.env.GITHUB_TOKEN = token;

  const failOn = getInput('fail-on') || 'high';

  const parsed = parseRepoInput(repo);
  if (!parsed) {
    console.error(`Error: Invalid repository: ${repo}`);
    process.exit(1);
  }

  console.log(`Scanning ${parsed.owner}/${parsed.repo}...`);

  try {
    const context = await fetchRepoContext(parsed.owner, parsed.repo);
    const result = runScan(context);

    // Set outputs
    setOutput('score', String(result.score));
    setOutput('grade', result.grade);
    setOutput('findings', String(result.findings.length));
    setOutput('result', JSON.stringify(result));

    // Write step summary
    writeSummary(formatSummary(result));

    // Check fail threshold
    const failSeverity = SEVERITY_ORDER[failOn] ?? SEVERITY_ORDER.high;
    const maxFindingSeverity = Math.max(
      ...result.findings.map(f => SEVERITY_ORDER[f.severity] ?? 0),
      -1
    );

    if (maxFindingSeverity >= failSeverity) {
      const count = result.findings.filter(
        f => (SEVERITY_ORDER[f.severity] ?? 0) >= failSeverity
      ).length;
      console.error(
        `\nFailed: ${count} finding(s) at ${failOn} severity or above.`
      );
      process.exit(1);
    }

    console.log(`\nPassed: Grade ${result.grade} (${result.score}/100)`);
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : 'Unknown error'}`);
    process.exit(1);
  }
}

function formatSummary(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(`## GHA Scanner: ${result.repo}`);
  lines.push('');
  lines.push(`**Grade: ${result.grade} (${result.score}/100)** | ${result.workflowCount} workflows | ${result.findings.length} findings`);
  lines.push('');

  if (result.findings.length === 0) {
    lines.push('No security findings.');
  } else {
    lines.push('| Severity | Finding | File |');
    lines.push('|----------|---------|------|');
    for (const f of result.findings.slice(0, 30)) {
      lines.push(`| ${f.severity} | ${f.title} | \`${f.file}\` |`);
    }
    if (result.findings.length > 30) {
      lines.push(`| | ... and ${result.findings.length - 30} more | |`);
    }
  }
  lines.push('');
  lines.push(`*Scanned with [GHA Scanner](https://github.com/raajheshkannaa/gha-scanner)*`);
  return lines.join('\n');
}

run();
