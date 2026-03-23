'use client';

import { useState } from 'react';
import { CategorySummary, Finding } from '@/lib/scanner/types';
import { FindingCard } from './FindingCard';
import { ChevronDown, ChevronRight } from 'lucide-react';

export function ResultsCategory({ category, findings }: { category: CategorySummary; findings: Finding[] }) {
  const [open, setOpen] = useState(category.critical > 0 || category.high > 0);

  return (
    <div className="bg-card border border-slate-700/20 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-slate-800/50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900"
        aria-expanded={open}
        aria-label={`${category.label} category, ${category.totalFindings} findings`}
      >
        <div className="flex items-center gap-3">
          {open ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
          <span className="font-medium">{category.label}</span>
        </div>
        <div className="flex gap-2 text-xs">
          {category.critical > 0 && <span className="bg-red-900/50 text-red-400 px-2 py-0.5 rounded">{category.critical} critical</span>}
          {category.high > 0 && <span className="bg-orange-900/50 text-orange-400 px-2 py-0.5 rounded">{category.high} high</span>}
          {category.medium > 0 && <span className="bg-yellow-900/50 text-yellow-400 px-2 py-0.5 rounded">{category.medium} medium</span>}
          {category.low > 0 && <span className="bg-blue-900/50 text-blue-400 px-2 py-0.5 rounded">{category.low} low</span>}
        </div>
      </button>
      {open && (
        <div className="border-t border-slate-700/20 divide-y divide-slate-700/20">
          {findings.map((finding, i) => (
            <FindingCard key={`${finding.checkId}-${i}`} finding={finding} />
          ))}
        </div>
      )}
    </div>
  );
}
