'use client';

import { useEffect, useState } from 'react';
import { ScanResult } from '@/lib/scanner/types';
import { ResultsSummary } from '@/components/scanner/ResultsSummary';
import { ResultsCategory } from '@/components/scanner/ResultsCategory';
import { CTABanner } from '@/components/scanner/CTABanner';
import { IncidentCards } from '@/components/scanner/IncidentCards';
import { ArrowLeft, Share2, Check, ClipboardCopy, ChevronRight } from 'lucide-react';
import Link from 'next/link';

export default function ScanPage() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [copiedMd, setCopiedMd] = useState(false);

  useEffect(() => {
    try {
      const hash = window.location.hash;
      if (!hash.startsWith('#r=')) {
        setError('No scan results found. Go back and scan a repository.');
        return;
      }
      const encoded = decodeURIComponent(hash.slice(3));
      const decoded = JSON.parse(decodeURIComponent(escape(atob(encoded))));
      // Basic validation
      if (!decoded.schemaVersion || !decoded.repo || !decoded.findings || !decoded.headSha) {
        setError('Invalid scan results.');
        return;
      }
      setResult(decoded as ScanResult);
    } catch {
      setError('Failed to decode scan results.');
    }
  }, []);

  if (error) {
    return (
      <div className="max-w-5xl mx-auto px-4 py-16 text-center">
        <p className="text-slate-400 mb-4">{error}</p>
        <Link href="/" className="text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1">
          <ArrowLeft className="w-4 h-4" /> Back to scanner
        </Link>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="max-w-5xl mx-auto px-4 py-16 text-center">
        <div className="animate-pulse text-slate-400">Loading results...</div>
      </div>
    );
  }

  function generateMarkdown(r: ScanResult): string {
    const lines: string[] = [];
    lines.push(`# GitHub Actions Security Scan: ${r.repo}`);
    lines.push('');
    lines.push(`**Grade: ${r.grade} (${r.score}/100)** | ${r.workflowCount} workflows scanned | ${r.findings.length} findings`);
    lines.push(`*Scanned commit ${r.headSha.slice(0, 7)} on ${new Date(r.scannedAt).toLocaleDateString()}*`);
    lines.push('');

    if (r.findings.length === 0) {
      lines.push('No security findings. Clean bill of health!');
    } else {
      const bySeverity = ['critical', 'high', 'medium', 'low', 'info'] as const;
      for (const sev of bySeverity) {
        const sevFindings = r.findings.filter(f => f.severity === sev);
        if (sevFindings.length === 0) continue;
        lines.push(`## ${sev.charAt(0).toUpperCase() + sev.slice(1)} (${sevFindings.length})`);
        lines.push('');
        for (const f of sevFindings) {
          lines.push(`- **${f.title}** — \`${f.file}${f.line ? `:${f.line}` : ''}\``);
        }
        lines.push('');
      }
    }

    lines.push('---');
    lines.push('*Scanned with [DefensiveWorks](https://defensive.works) GitHub Actions Security Scanner*');
    return lines.join('\n');
  }

  return (
    <div className="max-w-5xl mx-auto px-4 py-8">
      {/* Navigation */}
      <div className="flex items-center justify-between mb-6">
        <Link href="/" className="text-sm text-slate-400 hover:text-slate-300 inline-flex items-center gap-1 py-2">
          <ArrowLeft className="w-4 h-4" /> Scan another repo
        </Link>
        <div className="flex items-center gap-4">
          <button
            onClick={() => { navigator.clipboard.writeText(window.location.href); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
            className="text-sm text-slate-400 hover:text-slate-300 inline-flex items-center gap-1 py-2"
          >
            {copied ? <><Check className="w-4 h-4" /> Copied!</> : <><Share2 className="w-4 h-4" /> Share results</>}
          </button>
          <button
            onClick={() => { navigator.clipboard.writeText(generateMarkdown(result)); setCopiedMd(true); setTimeout(() => setCopiedMd(false), 2000); }}
            className="text-sm text-slate-400 hover:text-slate-300 inline-flex items-center gap-1 py-2"
          >
            {copiedMd ? <><Check className="w-4 h-4" /> Copied!</> : <><ClipboardCopy className="w-4 h-4" /> Copy as Markdown</>}
          </button>
        </div>
      </div>

      {/* Repo name */}
      <h1 className="text-2xl font-bold mb-1">{result.repo}</h1>
      <p className="text-sm text-slate-500 mb-6">
        Scanned commit {result.headSha.slice(0, 7)} on {new Date(result.scannedAt).toLocaleDateString()}
        {' '}({result.workflowCount} workflow{result.workflowCount !== 1 ? 's' : ''}, {result.duration}ms)
      </p>

      {/* Warnings */}
      {result.warnings.length > 0 && (
        <div className="bg-yellow-900/20 border border-yellow-800 rounded-lg p-3 mb-6">
          {result.warnings.map((w, i) => (
            <p key={i} className="text-sm text-yellow-400">{w}</p>
          ))}
        </div>
      )}

      {/* Summary */}
      <ResultsSummary result={result} />

      {/* Findings by category */}
      <div className="mt-8 space-y-4">
        {result.categories
          .filter(c => c.totalFindings > 0)
          .map(cat => (
            <ResultsCategory
              key={cat.category}
              category={cat}
              findings={result.findings.filter(f => f.category === cat.category)}
            />
          ))}
      </div>

      {/* Categories with no findings */}
      {result.categories.filter(c => c.totalFindings === 0).length > 0 && (
        <details className="mt-6 group">
          <summary className="text-sm text-slate-500 cursor-pointer hover:text-slate-400 list-none flex items-center gap-1">
            <ChevronRight className="w-3.5 h-3.5 group-open:rotate-90 transition-transform" />
            {result.categories.filter(c => c.totalFindings === 0).length} categories passed
          </summary>
          <div className="mt-2 flex flex-wrap gap-2">
            {result.categories
              .filter(c => c.totalFindings === 0)
              .map(c => (
                <span key={c.category} className="text-xs bg-emerald-900/30 text-emerald-400 px-2 py-1 rounded">
                  {c.label}
                </span>
              ))}
          </div>
        </details>
      )}

      {/* Incident Context */}
      <IncidentCards
        findings={result.findings}
        categories={result.categories}
        score={result.score}
      />

      {/* CTA */}
      <CTABanner result={result} />
    </div>
  );
}
