import type { VulnerableAction } from '../types';

export const KNOWN_VULNERABLE_ACTIONS: VulnerableAction[] = [
  {
    action: 'tj-actions/changed-files',
    affectedVersions: '< 46.0.1',
    cveId: 'CVE-2025-30066',
    disclosedDate: '2025-03-14',
    fixedVersion: '46.0.1',
    description:
      'Supply chain compromise exposing CI/CD secrets in workflow logs for 23,000+ repos',
  },
  {
    action: 'reviewdog/action-setup',
    affectedVersions: 'v1 tag (compromised)',
    cveId: 'CVE-2025-30154',
    disclosedDate: '2025-03-20',
    description: 'Compromised v1 tag injecting malicious code to steal secrets',
  },
  {
    action: 'aquasecurity/trivy-action',
    affectedVersions: 'all tags (compromised Mar 2026)',
    disclosedDate: '2026-03-12',
    description:
      'TeamPCP poisoned 75 of 76 version tags after botched credential rotation. Memory dumping stealer targeting Runner.Worker process.',
  },
  {
    action: 'aquasecurity/setup-trivy',
    affectedVersions: 'all tags (compromised Mar 2026)',
    disclosedDate: '2026-03-12',
    description:
      'Compromised alongside trivy-action in the same supply chain attack',
  },
  {
    action: 'codecov/codecov-action',
    affectedVersions: '< 1.0.2',
    cveId: 'CVE-2021-27027',
    disclosedDate: '2021-04-15',
    fixedVersion: '1.0.2',
    description:
      'Bash uploader modified to export environment variables and secrets',
  },
];
