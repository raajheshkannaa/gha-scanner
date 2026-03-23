'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Search, Loader2 } from 'lucide-react';

export function ScanForm() {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = input.trim();
    if (!trimmed || loading) return;

    // Quick client-side validation
    const repoPattern = /^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+$/;
    const urlPattern = /^https?:\/\/github\.com\/[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+/;
    if (!repoPattern.test(trimmed) && !urlPattern.test(trimmed)) {
      setError('Please enter a valid repository (owner/repo) or GitHub URL.');
      return;
    }

    setLoading(true);
    setError(null);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30_000);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo: trimmed }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || 'Something went wrong');
        return;
      }

      // Encode results in URL hash (Unicode-safe) and navigate
      const encoded = btoa(unescape(encodeURIComponent(JSON.stringify(data))));
      router.push(`/scan#r=${encodeURIComponent(encoded)}`);
    } catch (err) {
      clearTimeout(timeoutId);
      if (err instanceof DOMException && err.name === 'AbortError') {
        setError('Scan timed out. The repository may be too large. Please try again.');
      } else {
        setError('Failed to connect. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleScan} className="space-y-3">
      <div className="flex flex-col sm:flex-row gap-2">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
          <input
            type="text"
            aria-label="GitHub repository (owner/repo or URL)"
            aria-describedby={error ? 'scan-error' : undefined}
            aria-invalid={!!error}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="owner/repo or GitHub URL"
            className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-10 pr-4 py-3 text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent"
            disabled={loading}
          />
        </div>
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-700 disabled:text-slate-500 text-white font-medium px-6 py-3 rounded-lg transition-colors flex items-center justify-center gap-2 w-full sm:w-auto"
        >
          {loading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Scanning...
            </>
          ) : (
            'Scan'
          )}
        </button>
      </div>
      {error && (
        <p id="scan-error" className="text-red-400 text-sm" role="alert">{error}</p>
      )}
      <p className="text-xs text-slate-500 text-center">
        Works with any public GitHub repository. Try: kubernetes/kubernetes, facebook/react
      </p>
    </form>
  );
}
