'use client';

import { useState } from 'react';
import { Finding } from '@/lib/scanner/types';
import { ChevronDown, ChevronRight } from 'lucide-react';

const severityStyles: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400',
  high: 'bg-orange-500/15 text-orange-400',
  medium: 'bg-yellow-500/15 text-yellow-400',
  low: 'bg-blue-500/15 text-blue-400',
  info: 'bg-slate-500/10 text-slate-400',
};

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      className="absolute top-2 right-2 text-xs text-slate-500 hover:text-slate-300 bg-slate-900 px-1.5 py-0.5 rounded"
      aria-label="Copy to clipboard"
    >
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

export function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="px-4 py-3">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left flex items-start gap-3 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 rounded"
        aria-expanded={expanded}
        aria-label={`${finding.severity} finding: ${finding.title}`}
      >
        <span className={`text-xs px-2 py-0.5 rounded mt-0.5 flex-shrink-0 uppercase tracking-wide min-w-[4.5rem] text-center ${severityStyles[finding.severity]}`}>
          {finding.severity}
        </span>
        <div className="flex-1 min-w-0">
          <div className="font-medium text-sm">{finding.title}</div>
          <div className="text-xs text-slate-500 mt-0.5">
            {finding.file}{finding.line ? `:${finding.line}` : ''}
          </div>
        </div>
        {expanded ? <ChevronDown className="w-4 h-4 text-slate-500 mt-1" /> : <ChevronRight className="w-4 h-4 text-slate-500 mt-1" />}
      </button>

      {expanded && (
        <div className="mt-3 ml-0 sm:ml-[4.5rem] space-y-3 text-sm">
          {/* Evidence */}
          <div>
            <div className="text-xs text-slate-500 mb-1">Evidence</div>
            <pre className="bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap break-words">
              <code>{finding.evidence}</code>
            </pre>
          </div>

          {/* Risk */}
          <div>
            <div className="text-xs text-slate-500 mb-1">Risk</div>
            <p className="text-slate-300">{finding.risk}</p>
          </div>

          {/* Remediation */}
          <div>
            <div className="text-xs text-emerald-500 mb-1">Remediation</div>
            <div className="relative">
              <CopyButton text={finding.remediation} />
              <pre className="bg-slate-950 border border-emerald-900/50 rounded p-2 pr-16 text-xs text-emerald-300 overflow-x-auto whitespace-pre-wrap break-words">
                <code>{finding.remediation}</code>
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
