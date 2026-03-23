'use client';

import { ScanResult } from '@/lib/scanner/types';

const gradeColors: Record<string, string> = {
  A: 'text-emerald-400 border-emerald-400',
  B: 'text-green-400 border-green-400',
  C: 'text-yellow-400 border-yellow-400',
  D: 'text-orange-400 border-orange-400',
  F: 'text-red-400 border-red-400',
};

export function ResultsSummary({ result }: { result: ScanResult }) {
  const color = gradeColors[result.grade] || gradeColors.F;
  const criticalCount = result.findings.filter(f => f.severity === 'critical').length;
  const highCount = result.findings.filter(f => f.severity === 'high').length;
  const mediumCount = result.findings.filter(f => f.severity === 'medium').length;
  const lowCount = result.findings.filter(f => f.severity === 'low').length;

  return (
    <div className="bg-card border border-slate-700/20 rounded-xl p-6">
      <div className="flex flex-col sm:flex-row items-center gap-6 sm:gap-8">
        {/* Grade circle */}
        <div className={`w-24 h-24 rounded-full border-4 ${color} flex items-center justify-center flex-shrink-0`}>
          <div className="text-center">
            <div className={`text-3xl font-bold ${color.split(' ')[0]}`}>{result.grade}</div>
            <div className="text-xs text-slate-400">{result.score}/100</div>
          </div>
        </div>

        {/* Stats */}
        <div className="flex-1 text-center sm:text-left">
          <div className="flex items-baseline justify-center sm:justify-start gap-2 mb-2">
            <span className="text-lg font-semibold">{result.passingChecks}</span>
            <span className="text-slate-400">of {result.totalChecks} checks passed</span>
          </div>
          <div className="flex flex-wrap justify-center sm:justify-start gap-3 text-sm">
            {criticalCount > 0 && (
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-red-500" aria-hidden="true" />
                <span className="text-red-400">{criticalCount} critical</span>
              </span>
            )}
            {highCount > 0 && (
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-orange-500" aria-hidden="true" />
                <span className="text-orange-400">{highCount} high</span>
              </span>
            )}
            {mediumCount > 0 && (
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-yellow-500" aria-hidden="true" />
                <span className="text-yellow-400">{mediumCount} medium</span>
              </span>
            )}
            {lowCount > 0 && (
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-blue-400" aria-hidden="true" />
                <span className="text-blue-400">{lowCount} low</span>
              </span>
            )}
            {result.findings.length === 0 && (
              <span className="text-emerald-400">No findings. Clean bill of health!</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
