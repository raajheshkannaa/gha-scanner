import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import Link from 'next/link';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'DefensiveWorks - GitHub Actions Security Scanner',
  description: 'Scan your GitHub Actions workflows for security vulnerabilities. Free, instant, and comprehensive.',
  openGraph: {
    title: 'DefensiveWorks - GitHub Actions Security Scanner',
    description: 'Is your GitHub Actions pipeline secure? Scan now.',
    type: 'website',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-slate-950 text-slate-100 min-h-screen flex flex-col`}>
        <header className="border-b border-slate-800">
          <div className="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
            <Link href="/" className="flex items-center gap-2">
              <div className="w-8 h-8 bg-emerald-500 rounded-lg flex items-center justify-center text-white font-bold text-sm">DW</div>
              <span className="font-semibold text-lg">DefensiveWorks</span>
            </Link>
            <nav className="text-sm text-slate-400">
              <span>GitHub Actions Security Scanner</span>
            </nav>
          </div>
        </header>
        <main className="flex-1">{children}</main>
        <footer className="border-t border-slate-800 mt-auto">
          <div className="max-w-5xl mx-auto px-4 py-6 text-center text-sm text-slate-500">
            Built by practitioners, for practitioners. Part of the DefensiveWorks platform.
          </div>
        </footer>
      </body>
    </html>
  );
}
