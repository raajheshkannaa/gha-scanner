'use client';

import { useState } from 'react';
import { Loader2, Check } from 'lucide-react';
import { ScanResult } from '@/lib/scanner/types';

type Status = 'idle' | 'loading' | 'done' | 'error';

export function CTABanner({ result }: { result: ScanResult }) {
  const critHighCount = result.findings.filter(
    f => f.severity === 'critical' || f.severity === 'high'
  ).length;

  const [email, setEmail] = useState('');
  const [botCheck, setBotCheck] = useState('');
  const [status, setStatus] = useState<Status>('idle');
  const [message, setMessage] = useState('');

  const headline =
    critHighCount > 0
      ? `You just found ${critHighCount} critical/high pattern${critHighCount !== 1 ? 's' : ''}. Get the next one before it ships.`
      : 'This pipeline looks solid. Stay ahead of the next supply-chain attack.';

  async function handleSubscribe(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = email.trim();
    if (!trimmed || status === 'loading') return;

    setStatus('loading');
    setMessage('');

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10_000);

    try {
      const res = await fetch('/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: trimmed,
          bot_check: botCheck,
          utm_source: 'scan.defensive.works',
          utm_medium: 'results-page',
          utm_campaign: 'scanner-funnel',
          referring_site: 'scan.defensive.works',
        }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      const data = await res.json();

      if (!res.ok) {
        setStatus('error');
        setMessage(data.error || 'Something went wrong. Try again.');
        return;
      }

      setStatus('done');
      setMessage(
        data.message ||
          "You're in. Check your inbox to confirm, then look for Weekly Recon every Tuesday."
      );
    } catch (err) {
      clearTimeout(timeoutId);
      setStatus('error');
      setMessage(
        err instanceof DOMException && err.name === 'AbortError'
          ? 'That took too long. Try again in a moment.'
          : 'Failed to connect. Please try again.'
      );
    }
  }

  return (
    <section className="mt-12">
      <div className="bg-card border border-slate-700/20 rounded-xl p-6 sm:p-8">
        <p className="text-xs font-medium uppercase tracking-wider text-emerald-500 mb-2">
          Weekly Recon
        </p>
        <h3 className="text-lg font-semibold mb-1">{headline}</h3>
        <p className="text-sm text-slate-400 mb-5">
          One attack walked through, one detection to ship, one defender move.
          Cloud, agents, CI/CD, and supply chain, every Tuesday. From the same
          eye behind this scanner.
        </p>

        {status === 'done' ? (
          <div
            className="flex items-start gap-2 text-sm text-[#22c55e]"
            role="status"
          >
            <Check className="w-4 h-4 mt-0.5 flex-shrink-0" />
            <span>{message}</span>
          </div>
        ) : (
          <form onSubmit={handleSubscribe} className="space-y-3">
            <div className="flex flex-col sm:flex-row gap-2">
              <div className="flex-1 flex items-center bg-[#111] border border-[#333] rounded-lg px-3 focus-within:ring-2 focus-within:ring-[#22c55e] focus-within:border-transparent transition-colors">
                <span className="text-[#22c55e] mr-1.5 text-sm select-none">$</span>
                <span className="text-[#94a3b8] mr-1 text-sm select-none whitespace-nowrap">
                  subscribe
                </span>
                <span className="text-[#fbbf24] mr-2 text-sm select-none whitespace-nowrap">
                  --email
                </span>
                <input
                  type="email"
                  aria-label="Email address"
                  aria-describedby={status === 'error' ? 'subscribe-error' : undefined}
                  aria-invalid={status === 'error'}
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  className="flex-1 bg-transparent py-3 text-[#e2e8f0] placeholder-[#71717a] focus:outline-none font-mono text-sm"
                  disabled={status === 'loading'}
                  required
                />
              </div>
              <button
                type="submit"
                disabled={status === 'loading' || !email.trim()}
                className="bg-[#052e16] text-[#22c55e] border border-[#166534] hover:bg-[#14532d] disabled:bg-[#111] disabled:text-[#71717a] disabled:border-[#1e1e1e] font-medium px-6 py-3 rounded-lg transition-colors flex items-center justify-center gap-2 w-full sm:w-auto text-sm"
              >
                {status === 'loading' ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    subscribing...
                  </>
                ) : (
                  'subscribe'
                )}
              </button>
            </div>

            {/* Honeypot: hidden from humans, bots fill it. Name matches the
                API route's bot_check field. */}
            <div
              aria-hidden="true"
              style={{
                position: 'absolute',
                left: '-99999px',
                width: '1px',
                height: '1px',
                overflow: 'hidden',
              }}
            >
              <label htmlFor="bot_check">Leave this field empty</label>
              <input
                id="bot_check"
                name="bot_check"
                type="text"
                tabIndex={-1}
                autoComplete="off"
                value={botCheck}
                onChange={(e) => setBotCheck(e.target.value)}
              />
            </div>

            {status === 'error' && (
              <p id="subscribe-error" className="text-[#ef4444] text-sm" role="alert">
                {message}
              </p>
            )}
            <p className="text-xs text-[#71717a]">
              No spam. One issue a week. Unsubscribe anytime.
            </p>
          </form>
        )}
      </div>
    </section>
  );
}
