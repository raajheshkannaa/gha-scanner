import { ScanForm } from '@/components/scanner/ScanForm';
import { Shield, AlertTriangle, Lock, Eye, Server, Settings, CheckCircle, GitBranch } from 'lucide-react';

const categories = [
  { icon: GitBranch, name: 'Supply Chain', desc: 'Unpinned actions, mutable tags, known CVEs', color: 'text-red-400' },
  { icon: AlertTriangle, name: 'Injection', desc: 'Expression injection in run blocks', color: 'text-orange-400' },
  { icon: Shield, name: 'Dangerous Triggers', desc: 'pull_request_target misuse', color: 'text-yellow-400' },
  { icon: Lock, name: 'Permissions', desc: 'Overly broad GITHUB_TOKEN scope', color: 'text-blue-400' },
  { icon: Eye, name: 'Secrets Exposure', desc: 'Leaked secrets in logs and artifacts', color: 'text-purple-400' },
  { icon: Server, name: 'Runner Security', desc: 'Self-hosted runner risks', color: 'text-pink-400' },
  { icon: Settings, name: 'CI/CD Hygiene', desc: 'Timeouts, concurrency, error handling', color: 'text-cyan-400' },
  { icon: CheckCircle, name: 'Best Practices', desc: 'Dependabot, CODEOWNERS', color: 'text-emerald-400' },
];

export default function Home() {
  return (
    <div className="max-w-5xl mx-auto px-4 py-16">
      {/* Hero */}
      <div className="text-center mb-12">
        <h1 className="text-4xl md:text-5xl font-bold mb-4">
          Is your GitHub Actions pipeline{' '}
          <span className="text-emerald-400">secure</span>?
        </h1>
        <p className="text-lg text-slate-400 max-w-2xl mx-auto mb-8">
          Scan any public repository for 28 security checks across 8 categories.
          Get a detailed report with specific remediation steps. Free, instant, no sign-up required.
        </p>
      </div>

      {/* Scan Form */}
      <div className="max-w-2xl mx-auto mb-16">
        <ScanForm />
      </div>

      {/* What We Check */}
      <div className="mb-16">
        <h2 className="text-2xl font-semibold text-center mb-8">What we check</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {categories.map((cat) => (
            <div
              key={cat.name}
              className="bg-slate-900 border border-slate-800 rounded-lg p-4 hover:border-slate-700 transition-colors"
            >
              <cat.icon className={`w-5 h-5 ${cat.color} mb-2`} />
              <h3 className="font-medium mb-1">{cat.name}</h3>
              <p className="text-sm text-slate-400">{cat.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Trust indicators */}
      <div className="text-center text-sm text-slate-500">
        <p>28 checks inspired by real attacks: tj-actions (2025), Trivy (2026), Shai Hulud, GhostAction</p>
        <p className="mt-1">No data stored. No sign-up. Open source scanner engine.</p>
      </div>
    </div>
  );
}
