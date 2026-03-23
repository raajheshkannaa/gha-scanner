'use client';

import { ScanResult } from '@/lib/scanner/types';

export function CTABanner({ result }: { result: ScanResult }) {
  const critHighCount = result.findings.filter(
    f => f.severity === 'critical' || f.severity === 'high'
  ).length;

  return (
    <section className="mt-12">
      <div className="bg-card border border-slate-700/20 rounded-xl p-6 sm:p-8">
        <div className="flex flex-col sm:flex-row sm:items-center gap-6">
          {/* Primary CTA */}
          <div className="flex-1">
            <p className="text-xs font-medium uppercase tracking-wider text-emerald-500 mb-2">
              Coming soon
            </p>
            <h3 className="text-lg font-semibold mb-1">
              Module 1: Supply Chain Attacks
            </h3>
            <p className="text-sm text-slate-400">
              {critHighCount > 0
                ? `Explore how attackers exploit the ${critHighCount} critical/high severity pattern${critHighCount !== 1 ? 's' : ''} found in your pipeline. Hands-on drill, not a lecture.`
                : 'Your pipeline looks solid. Test if your team could detect and respond to a supply chain attack in real time.'}
            </p>
          </div>

          {/* Secondary: Challenge teaser */}
          <div className="border-t sm:border-t-0 sm:border-l border-slate-700/20 pt-4 sm:pt-0 sm:pl-6 flex-shrink-0">
            <p className="text-xs text-slate-500 mb-2">While you wait</p>
            <p className="text-sm text-emerald-400/70">
              Can you spot the backdoor?
              <span className="block text-xs text-slate-500 mt-0.5">
                5-min challenge (coming soon)
              </span>
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
