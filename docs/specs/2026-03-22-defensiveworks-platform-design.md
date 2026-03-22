# DefensiveWorks Platform Design Spec

**Version:** 1.0
**Date:** 2026-03-22
**Author:** Raajhesh Kannaa Chidambaram
**Status:** Draft

---

## 1. Vision

DefensiveWorks is an adversary simulation platform for cloud security. An automated adversary (VEGA) attacks simulated cloud environments using real-world TTPs, including AI-augmented techniques. Users build defenses using real tools and AI assistance. If VEGA reaches its objective, you see what happened, learn why, and try again. When you win, you level up.

**Tagline:** "Engineer your defense. Prove it works."

**What this is:** A flight simulator for cloud security engineers. Practice against realistic, AI-augmented attack campaigns in a safe environment. Build defenses that actually work. Prove it with a practical certification.

**What this is not:** A gamified training platform. A CTF. A slide deck with labs. A multiple-choice certification.

### 1.1 Core Educational Philosophy: Teach the Arithmetic, Not the Calculator

AI makes both attackers and defenders 100x more powerful. But a defender who only knows how to prompt an AI is like a student who can use a calculator but doesn't understand arithmetic. When the calculator gives the wrong answer, they can't tell. When a new problem appears that the calculator wasn't trained on, they're helpless.

**DefensiveWorks teaches understanding, not tool usage.**

- We don't teach "use AI to write an SCP." We teach WHY the SCP needs to exist, what threat model it addresses, and how IAM evaluation actually processes it.
- We don't teach "use AI to analyze CloudTrail." We teach what the events MEAN in the context of an attack chain, how to trace lateral movement through AssumeRole chains, and how to distinguish legitimate activity from compromise.
- We don't teach "let AI build your detection." We teach how to reason about false positives, false negatives, detection coverage gaps, and evasion techniques.

**The test:** Can the user reason from first principles when AI is unavailable, wrong, or facing a novel situation? Can they evaluate whether AI-generated security advice is correct? Can they adapt when the playbook doesn't exist?

**Design implications:**
- AI tutor asks questions, never gives answers. Socratic method.
- Certain stages (and the certification exam) disable the AI tutor entirely. The user must reason independently.
- Challenges require the user to EXPLAIN their reasoning, not just deploy the right config.
- VEGA uses novel techniques in later stages that no AI has been trained on, forcing original thinking.
- Scoring rewards understanding (can you explain why this works?) over implementation speed.

This is the most important principle in the platform. Everything else is execution detail.

---

## 2. Target Audience

**Primary:** Mid-career cloud engineers (3-8 years experience) adding security to their skillset. They know AWS, Terraform, and CI/CD. They lack the security lens: how attackers think, how to detect and respond, how to engineer preventive controls.

**Why this segment:**
- 4.8M unfilled cybersecurity roles globally, cloud security is the #2 skills shortage (30%)
- 52% of leaders say the gap is skills misalignment, not headcount
- $136K-$167K average salary (purchasing power for premium training)
- 29% projected job growth through 2034
- Underserved: existing training is either too theoretical (CCSP, AWS certs), too narrow (OSCP = no cloud), or too expensive (SANS = $8,780+)

**Secondary:** Junior security engineers deepening cloud-specific skills.

**Not primary (yet):** Complete beginners. The platform assumes cloud familiarity.

---

## 3. Product Structure

Three layers, progressive depth.

### 3.1 Scenarios (Free, public)

Written attack breakdowns based on real incidents. Each scenario covers: what happened, the attack chain, what defenders missed, CloudTrail evidence, MITRE ATT&CK mapping, and defensive recommendations.

**Purpose:** Build audience, establish credibility, SEO, newsletter funnel.

**Examples:**
- "How Change Healthcare lost $22B from one stolen credential"
- "SolarWinds: When your build system is the backdoor"
- "The Codecov bash uploader: CI/CD as an attack surface"

**Format:** MDX on defensive.works. 10-15 minute reads. Technically deep.

### 3.2 Challenges (Learn the skills)

Individual skill-building exercises in simulated cloud environments. Each challenge teaches one offensive technique and its defensive counterpart.

**Structure per challenge:**
1. Context: real-world scenario framing (why this matters)
2. Attack: execute the technique in the simulated environment
3. Detect: write the query/rule that catches it
4. Prevent: implement the control that blocks it
5. Validate: confirm your detection catches the attack and your prevention blocks it

**Duration:** 10-20 minutes per challenge (microlearning, includes terminal interaction time). Grouped into skill tracks. Validate with beta testers and adjust.

**AI tutor available:** Claude Code skill provides Socratic guidance.

### 3.3 Missions (The core experience)

Persistent simulated environments where VEGA actively attacks and the user engineers defenses in real-time.

**Three phases per mission:**

**Phase 1: Fortify (build time, untimed)**
- Read the threat briefing (what kind of attack to expect)
- Build defenses: SCPs, detection rules, automation, deception
- Traffic light dashboard shows coverage: green/yellow/red per attack vector
- AI tutor reviews your work proactively
- Static validation checks before going live
- Pre-built component library available (SCP templates, detection templates)

**Phase 2: Defend (real-time, 10-15 minutes compressed)**
- VEGA's attack unfolds. CloudTrail events stream in.
- Your detections fire (or don't). Alerts appear (or don't).
- Make real-time decisions: triage, adjust, invoke automation, isolate resources
- VEGA sends probes before full assault (partial feedback)
- This is where the tension and learning live

**Phase 3: Debrief**
- Full attack chain replay: what VEGA did, timestamped
- Side-by-side timeline: VEGA's actions vs your defenses
- Score breakdown: MTTD (mean time to detect), MTTC (mean time to contain)
- Partial credit: "VEGA reached objective in 4 steps. You blocked 3 of 4."
- Intel revealed: one piece of VEGA's strategy permanently unlocked
- VEGA commentary: adversary acknowledges what worked and what didn't
- "Translate to your org" prompt: optional exercise to apply learnings to real work

**If VEGA wins:** Checkpoint reset (not full stage reset). Accumulated defenses from earlier checkpoints persist. Intel from failure helps next attempt.

**If user wins:** Next stage unlocked. Defense portfolio updated. Threat intel brief unlocked.

---

## 4. The VEGA Adversary Engine

VEGA is the automated adversary. Named after the recurring antagonist from the Cloud Security Cinematic Universe (CSCU) books.

### 4.1 Design Principles

- **Realistic:** Every technique maps to MITRE ATT&CK and has real-world precedent
- **AI-augmented:** VEGA uses AI the way real threat actors do: automated enumeration, LLM-powered social engineering, automated exploit chaining, adaptive persistence
- **Adaptive:** If the user blocks path A, VEGA tries path B. Not fully deterministic.
- **Fair:** Every attack is defensible. Every failure is explainable. If a user says "that's unfair," that's a platform bug.
- **Evolving:** Quarterly updates with new TTPs from real-world threat intelligence

### 4.2 Behavior Model

**Stages 1-3:** Deterministic attack chains. User knows what's coming from the threat briefing. Learning objective: implement the right defense.

**Stages 4+:** Attack families with randomized execution paths. User knows the category of attack but not the specific path. Learning objective: build robust defenses, not point solutions.

**VEGA personality:** Evolves across stages.
- Stage 1: Dismissive. "That was barely worth my time."
- Stage 3: Noticing. "Your CloudTrail coverage is improving."
- Stage 5: Respectful. "Interesting deception. I almost fell for it."
- Stage 6: Peer. "Your architecture forced me to burn three zero-days. Impressive."

### 4.3 AI-Augmented Attack Techniques

**Narrative (what the user experiences):** VEGA represents how real adversaries use AI to hack organizations today:
- AI agents that autonomously enumerate cloud environments
- Automated exploit chaining: discover misconfig, chain to escalation, establish persistence
- AI that reads AWS documentation to find novel attack paths
- Automated persistence mechanisms that adapt when one is blocked
- LLM-generated artifacts (realistic-looking configs, policies, commit messages)

**Implementation (what gets built):**
- **Phases 1-2 (MVP):** VEGA is scripted YAML playbooks with deterministic attack chains. The speed and breadth of attacks *simulates* AI-augmented behavior. Framing materials explain "this is how AI-powered attackers operate."
- **Phase 3+:** VEGA gains actual adaptive behavior: branching attack trees, randomized path selection, dynamic response to user's defenses.
- **Phase 4+:** Potential integration of actual LLM-driven attack planning (research item, not committed).

This teaches defenders: "Attackers have AI too. Your defenses need to handle AI-speed, AI-breadth attacks."

---

## 5. Stage Structure

6 stages + Stage 0 onboarding. Designed for 30 sessions (not 30 calendar days). Each session: 45-60 minutes. Users progress at their own pace. Stage 0 is a 15-minute onboarding experience, not counted as a session. 30 sessions span Stages 1-6.

### Stage 0: The Breach (Onboarding, 15 minutes)

Non-interactive cinematic. VEGA attacks an undefended environment. User watches CloudTrail events stream, lateral movement unfold, data exfiltrate. Environment destroyed in 90 seconds.

Then: environment resets with one basic control pre-deployed. VEGA attacks again. The control catches the initial access. Attack blocked.

User now understands the game. First real action: Stage 1.

**Tool introduction:** None. Observation only.

### Stage 1: Detection Fundamentals (Sessions 1-4)

**VEGA attacks:** Stolen credentials, basic enumeration (sts:GetCallerIdentity, iam:ListUsers, s3:ListBuckets from unknown IP).

**User learns:**
- Read and interpret CloudTrail events
- Write basic detection queries
- Set up CloudTrail alerts
- Basic IAM hardening (disable unused keys, enforce MFA)

**First win condition:** Detect VEGA's enumeration within 60 seconds.

**Tools:** AWS CLI only. No Terraform yet. Minimal cognitive load.

**Difficulty:** Trivially simple first win. Build confidence and hook.

### Stage 2: Preventive Controls (Sessions 5-9)

**VEGA attacks:** Privilege escalation, resource creation in unauthorized regions, S3 data access.

**User learns:**
- Write and deploy SCPs
- Permission boundaries
- S3 bucket policies
- VPC and security group hardening

**Introduce:** Terraform (single resource at first, then multiple).

**VEGA behavior:** Tests your controls. If SCP blocks region, tries another vector. Adapts.

**Win condition:** Block all of VEGA's escalation paths.

### Stage 3: Response Automation (Sessions 10-14)

**VEGA attacks:** Faster, multi-vector. Creates resources, modifies configs, attempts lateral movement.

**User learns:**
- EventBridge rules for automated detection
- Lambda functions for auto-remediation
- Step Functions for incident response workflows
- GuardDuty tuning and custom threat lists

**AI tutor:** Claude Code tutor deepens from basic hints (Stage 1) to proactive review (Stage 3). Available from Stage 1, capabilities expand per stage.

**Win condition:** Automated detection AND containment. MTTC under 2 minutes.

**Branching unlocked:** After Stage 3, user chooses next path.

### Stage 4: Identity & Access Engineering (Sessions 15-19)
*OR*
### Stage 4 (alt): Supply Chain & CI/CD Security

**Identity path - VEGA attacks:** Cross-account role assumption chains, OIDC trust abuse, STS session persistence, backdoor IAM users.

**User learns:**
- Investigate compromised roles via CloudTrail
- Trace AssumeRole chains across accounts
- Trust policy engineering
- OIDC federation security
- Secrets rotation and blast radius assessment

**Supply Chain path - VEGA attacks:** GitHub Actions cache poisoning, dependency confusion, compromised build artifacts, OIDC pipeline trust abuse.

**User learns:**
- Pipeline integrity verification
- SBOM generation and validation (SLSA framework)
- Build artifact signing (cosign + KMS)
- Secrets in CI/CD (detection and rotation)
- IaC security scanning (Checkov, tfsec)

**Environment:** "Messy" from here on. Pre-existing imperfect configs, legacy IAM roles, console-created resources mixed with IaC. User must assess before acting.

### Stage 5: Advanced Defense (Sessions 20-24)

**VEGA attacks:** Multi-technique campaign. Combines identity abuse, data exfiltration, persistence, and evasion. AI-augmented: automated recon, adaptive persistence.

**User learns:**
- Deception engineering: honeytokens, canary credentials, decoy resources
- Data exfiltration detection: DNS tunneling, presigned URL abuse, VPC flow analysis
- Multi-account incident response
- Container/EKS security (if container path chosen)
- Compliance as Code (AWS Config rules, CloudFormation Guard)
- Architecture hardening at scale

**VEGA behavior:** Evasive. Cleans up after itself. Avoids obvious traps. Multiple simultaneous attack paths.

**Win condition:** Detect, deceive, contain, and remediate. Full defense-in-depth demonstrated.

### Stage 6: The Final Campaign (Sessions 25-30, Certification Exam)

**VEGA attacks:** Full multi-stage campaign. Nation-state level sophistication. AI-augmented throughout. Combines everything from all previous stages.

**User must:**
1. Threat model the environment (no threat briefing provided)
2. Prioritize defenses given limited time/resources
3. Build and deploy a complete security architecture
4. Defend in real-time against VEGA's campaign
5. Document their approach and decisions (written report)

**No hints. No AI tutor. No threat briefing.** This is the certification exam.

**Format:** 24-hour practical exam. Simulated environment (MVP) or real AWS (Phase 3).

**Win condition:** VEGA achieves no primary objectives. Report demonstrates sound reasoning.

---

## 6. AI Tutor: DefensiveWorks Skill

A Claude Code skill users install locally. The tutor is a context-aware companion, not an answer machine.

### 6.1 What It Knows
- Current mission state and environment configuration
- What the user has built and tried
- Learning objectives for the current stage
- The user's overall skill profile and progress
- VEGA's capabilities for the current stage (for hint calibration)

### 6.2 Behavior
- **Socratic method:** "What do you notice about that trust policy?" not "The trust policy is wrong."
- **Tiered hints:** Level 1 (strategic), Level 2 (tactical), Level 3 (implementation template)
- **Proactive feedback:** Reviews defenses during build phase. "Your SCP covers 3 of 5 attack vectors. Want me to help identify the gaps?"
- **Post-failure explanation:** Walks through exactly what VEGA did and why the defense missed it
- **Real-time during Defend phase:** "Alert: VEGA just called sts:AssumeRole to account 234567. Your cross-account detection didn't fire. Want to investigate?"
- **Not available in Stage 6** (certification exam)

### 6.3 Guardrails

**Technical approach:** RAG (Retrieval-Augmented Generation) constrained to a curated knowledge base per stage.
- System prompt restricts tutor to reference validated AWS documentation, stage-specific defense patterns, and curated CloudTrail event schemas
- Tutor uses tool-use pattern: queries a knowledge base API rather than relying on parametric knowledge for AWS-specific facts
- Pre-release validation: every stage's tutor responses tested against 20+ known-good interaction scenarios before shipping
- Feedback button: "This advice was wrong" triggers human review pipeline with 48-hour response SLA
- Quarterly knowledge base refresh aligned with VEGA TTP updates

### 6.4 Embracing External AI
Users will use external AI tools. This is expected and encouraged. Real defenders use AI. The tutor's advantage: it sees the environment state and knows the learning objectives. External AI doesn't.

---

## 7. Feedback and Scoring

### 7.1 Real-Time Feedback
- **Traffic light dashboard:** Green/yellow/red per attack vector before VEGA attacks
- **VEGA probes:** Lightweight test attacks giving partial feedback before full assault
- **Static validation:** Automated checks on user's defenses during Fortify phase
- **AI tutor:** Proactive review during build

### 7.2 Post-Mission Scoring
- **MTTD:** Mean time to detect (seconds)
- **MTTC:** Mean time to contain (seconds)
- **Coverage:** Percentage of attack vectors defended
- **Efficiency:** Number of controls deployed (fewer is better for same coverage)
- **Deception bonus:** Did VEGA trigger a trap?
- **Partial credit:** "Blocked 3 of 4 attack steps"

### 7.3 Failure as Learning
- Checkpoint reset, not full stage reset
- Each failure reveals one piece of VEGA's strategy permanently (Intel mechanic)
- Progress bar: "You blocked 2/4 steps. Previous best: 1/4."
- After 5 failures: guided walkthrough option (reduced score, but progress)
- VEGA's attack path partially randomized in Stages 4+ (prevents rote memorization)

---

## 8. Retention and Engagement

### 8.1 Session Design
- Target session: 45-60 minutes
- Challenges: 10-20 minutes each (microlearning)
- Missions: completable in 1-2 sessions per stage
- "30 sessions" not "30 calendar days"

### 8.2 Between Sessions
- Daily VEGA probes: 10-minute micro-challenges between stages
- Streak mechanics with 2 rest days/week forgiveness
- "Comeback" mechanic: 10-minute recap for users who've been away 2+ weeks

### 8.3 Post-Completion
- Weekly VEGA scenarios (Elusive Targets model): time-limited, one attempt, leaderboard
- Role reversal mode: play as VEGA, attack a pre-configured environment
- Community defense challenges: "Build the most efficient defense for this attack chain"
- VEGA evolution: quarterly new attack families from real-world threat intelligence

### 8.4 Community

**MVP (minimum viable community):** One Discord server for all users. Manual cohort coordination (monthly start announcements). This is sufficient until 200+ active users.

**At scale (200+ users):**
- Cohort-specific Discord channels (monthly). Research shows 16x completion rate vs solo.
- Shared defense architecture browser (opt-in after winning a stage)
- Defense review pairing: review another user's approach

**Post-MVP:**
- Team mode: 3-4 people defend together, dividing responsibilities
- Per-cohort channels with dedicated mentors

---

## 9. Curriculum Scope

### Core (Stages 1-6)
1. CloudTrail analysis and detection engineering
2. IAM policy engineering and investigation
3. SCP and preventive controls
4. Response automation (Lambda, Step Functions, EventBridge)
5. Architecture hardening (least privilege, network segmentation, IMDS v2)
6. Deception engineering (honeytokens, canary credentials, decoy resources)
7. Multi-account security (Organizations, delegated admin, StackSets)
8. CI/CD pipeline security and attack simulation
9. Supply chain security (SLSA, SBOM, build verification)
10. Secrets management and credential rotation

### Extended (Post-MVP paths)
11. Container/Docker security (attack + defend)
12. Kubernetes/EKS security (RBAC abuse, admission controllers, pod identity)
13. IaC security scanning and exploitation paths
14. Compliance as Code (InSpec, AWS Config, CloudFormation Guard)
15. Data exfiltration detection (DNS tunneling, presigned URLs, VPC flow analysis)
16. Threat modeling as code

### Integrated Throughout (Not a Separate Track)
- AI-augmented attacks: how real adversaries use AI to hack organizations
- AI-assisted defense: using Claude Code to analyze, build, and respond faster

---

## 10. Certification: DefensiveWorks Certified (DWC)

### 10.1 Format
- 24-hour practical exam
- Live adversary (VEGA Final Campaign)
- Real AWS environment (Phase 3) or high-fidelity simulation
- No hints, no AI tutor, no threat briefing
- Report submission required (technical decisions, architecture rationale, timeline)

### 10.2 Assessment
- Did VEGA achieve its primary objectives? (binary pass/fail gate)
- Quality of defensive architecture (depth, coverage, efficiency)
- Quality of report (communication, reasoning, technical accuracy)
- Time metrics (MTTD, MTTC)

### 10.3 Credibility
- Target pass rate: 40-50% (hard enough to be meaningful)
- Publish pass rate statistics transparently
- Lifetime certification, no renewal fees
- Seed credibility: first 100 certified must be strong practitioners
- Get 5-10 recognized cloud security practitioners to complete and publicly review
- Long-term goal: CISA/NICCS listing

### 10.4 Scope of Certification
**What DWC certifies:** Technical implementation skill in cloud defense. Ability to detect, prevent, respond to, and contain cloud attacks using real tools under adversarial pressure.

**What DWC does not certify:** Incident communication, organizational politics, forensic depth, compliance program management, risk assessment at the business level. Be transparent about this.

---

## 11. Technical Architecture (MVP)

### 11.1 Platform
- **Frontend:** Next.js on Vercel. MDX for scenario content.
- **Auth/Progress:** Supabase (auth, user profiles, progress tracking, scoring)
- **Challenge Engine:** Browser-based terminal (xterm.js or similar) connected to simulated environment
- **Content:** YAML for challenge/mission definitions. MDX for scenarios.

### 11.2 Simulated Cloud Environment

**Critical path: Week 1 technical spike required before committing to MVP timeline.**

**Spike scope:** Validate that LocalStack (or Moto + custom layer) can accurately simulate the following for Stages 1-2 only:

| API Calls Required (Stage 1) | Fidelity Required |
|------|------|
| sts:GetCallerIdentity | Exact response format |
| iam:ListUsers, iam:ListAccessKeys | Correct response schema |
| s3:ListBuckets, s3:GetObject | Standard behavior |
| cloudtrail:LookupEvents | Real CloudTrail JSON event structure with correct userIdentity block variations |

| API Calls Required (Stage 2) | Fidelity Required |
|------|------|
| organizations:CreatePolicy (SCP) | Correct SCP enforcement on child account API calls |
| iam:CreatePolicyVersion | IAM evaluation logic: explicit deny > explicit allow > implicit deny |
| s3:PutBucketPolicy | Resource-based policy evaluation |

**Spike deliverable:** Go/no-go decision. If LocalStack fidelity is insufficient for IAM evaluation logic, fallback to: (a) pre-recorded CloudTrail events + static validation of user's defenses (lower fidelity, ships faster), or (b) real AWS accounts with aggressive cost controls from day one.

**Accepted trade-offs:** Eventual consistency (instant in sim), cross-service edge cases, console UI, GuardDuty finding generation timing.

**Transparency:** Every stage labels what is simulated vs what would differ in real AWS.

### 11.2.1 Browser Terminal Architecture (Phase 2)

Not in Phase 1 (users use local CLI). For Phase 2:
- **Frontend:** xterm.js terminal emulator in browser
- **Connection:** WebSocket to backend session manager
- **Backend:** Per-user Docker container (or Firecracker microVM) running a minimal Linux environment with AWS CLI pre-configured to hit the simulation layer
- **Session lifecycle:** Created on stage start, destroyed on stage completion or 2-hour idle timeout
- **Resource isolation:** One container per user session. No shared state between users.
- **Latency target:** <100ms keystroke-to-render
- **Cost model:** ~$0.02-0.05/hour per active session (containerized)

### 11.3 VEGA Engine
- Python/Go attack playbooks defined in YAML
- State machine: tracks attack progress, adapts based on user's defenses
- Deterministic mode (Stages 1-3) and randomized mode (Stages 4+)
- Probes: lightweight validation attacks before full campaign
- Attack chain logging for replay visualization

### 11.4 AI Tutor
- Claude Code skill distributed via GitHub
- Communicates with platform API for environment state and progress
- Constrained system prompt per stage with validated reference material
- Feedback pipeline for flagging incorrect advice

### 11.5 Phase 3 Additions
- Real AWS accounts (AWS Organizations, automated provisioning/teardown)
- Terraform-based environment setup per user/exam session
- Cost controls: Lambda-based auto-teardown, budget alerts, session time limits

---

## 12. MVP Scope

### 12.1 Phased Delivery

**Phase 0: Technical Spike (Week 1)**
- Validate simulation fidelity for Stage 1 API calls
- Go/no-go on LocalStack vs fallback approach
- Deliverable: working prototype of one VEGA attack + one user defense in simulated environment

**Phase 1: Alpha (Weeks 2-7, invite-only, 20-30 users)**
- 3 scenarios (free, public on defensive.works)
- Stage 0: The Breach (onboarding, can be a narrated terminal replay, not a full cinematic)
- Stage 1: Detection Fundamentals (4 sessions)
- Basic VEGA engine (scripted, deterministic YAML playbooks)
- User interacts via local CLI tools (AWS CLI against simulated environment). No browser terminal yet.
- Claude Code skill (basic version, Stage 1 content only)
- Simple auth (Supabase)
- One Discord server
- Full instrumentation (time per stage, hint usage, reset count, drop-off points)

**Phase 2: Beta (Weeks 8-14, public, 100+ users)**
- 5 scenarios total
- Stage 2: Preventive Controls added
- Browser-based terminal (xterm.js + WebSocket to sim backend)
- Traffic light dashboard
- Attack chain replay visualization
- Claude Code skill expanded to Stage 2
- Scoring and progress tracking

**Phase 3: Full Platform (Months 4-6)**
- Stages 3-5
- Adaptive VEGA (randomized attack families)
- Branching paths after Stage 3
- Community features at scale

**Phase 4: Certification (Month 6+)**
- Stage 6: Final Campaign
- Real AWS environments for exam
- Report submission and grading
- Credibility seeding: 10 recognized practitioners go through it first
- Public launch of DefensiveWorks Certified (DWC)

### 12.2 Phase 1 Success Criteria
- 20+ users complete Stage 0 and start Stage 1
- 70%+ of Stage 1 starters complete Stage 1
- Qualitative feedback: "I learned something I can use at work"
- Identify difficulty curve issues from instrumentation data
- At least 3 users voluntarily share their experience publicly

### 12.3 MVP is free. Pricing validation begins in Phase 3.

### 12.4 Ultimate Acceptance Criterion

The founder (Raajhesh) goes through the full experience as User #1. If he comes out feeling like an AI-native defender who learned things he can apply immediately, it ships. If he's bored or doesn't learn, it doesn't ship. No amount of reviewer approval overrides this.

---

## 12.5 Deployment Models

**Phase 1-2: Hosted only**
- We run everything. User opens browser or connects Claude Code skill.
- Zero setup friction. Best for individuals and small teams.
- We control experience, quality, and updates.

**Phase 3+ (post-validation): Self-hosted option for enterprise**
- Company deploys DefensiveWorks on their own AWS/infrastructure
- VEGA attacks their actual (sandboxed) environment topology
- Scenarios customizable to match their architecture
- Data never leaves their environment (compliance: SOC 2, HIPAA, FedRAMP)
- Delivered as container images / Helm chart + VEGA engine + content packs
- Enterprise licensing model TBD

**Phase 3+ (post-validation): Hybrid option**
- Content and VEGA engine hosted by us
- User's environment is their own AWS sandbox account
- Claude Code skill runs locally, connects to our API for progress/scoring
- Best for users who want real AWS experience without full self-hosted complexity

---

## 13. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Simulation fidelity (IAM eval doesn't match real AWS) | Trains bad habits, destroys credibility | Use LocalStack where possible. Validate IAM logic against real AWS. Be transparent about boundaries. |
| VEGA feels unfair | Users quit, negative word-of-mouth | Every attack must be defensible and explainable. "Unfair" = platform bug. |
| AI tutor gives wrong advice | Erodes trust, teaches bad habits | Constrain to validated content. Human review pipeline for flagged responses. |
| No community | 85-95% dropout (solo online course baseline) | Cohort-based starts from day one. Discord per cohort. Shared defense browser. |
| Expert blind spot in content | Stages too hard or skip assumed knowledge | Beta test every stage with 10+ target-audience users before launch. |
| Content staleness | Platform becomes irrelevant within 6 months | Quarterly VEGA updates. Modular architecture for new attack families. |
| Scope creep | Never ships | MVP is 2 stages + 5 scenarios. Ship, validate, iterate. |

---

## 14. What This Platform Does NOT Teach

Transparency about scope builds trust.

- Incident communication (writing executive summaries, customer notifications, post-mortems)
- Organizational politics ("that role runs payment processing, you can't revoke it")
- Deep forensics (memory acquisition, disk analysis, malware reverse engineering)
- Compliance program management (SOC 2 audit prep, control mapping)
- Business risk assessment
- Legal considerations during incidents
- Multi-cloud (Azure, GCP) in V1

These are important skills. They're out of scope for V1. Some may be added in future stages.

---

## 15. References

Market statistics cited in this spec:
- 4.8M unfilled cybersecurity roles: ISC2 Cybersecurity Workforce Study 2025
- Cloud security #2 skills shortage (30%): ISC2 Workforce Study 2025
- 52% skills misalignment: ISC2 Workforce Study 2025
- $136K-$167K average salary: Skillsoft IT Skills and Salary Report 2025, BLS
- 29% job growth through 2034: U.S. Bureau of Labor Statistics
- 16x completion rate for cohort-based: 360Learning research (altMBA 96% completion rate)
- Simulation effect size 0.85: Chernikova et al., Review of Educational Research, 2020
- 65-70% narrative retention: Pluralsight/Harvard (Dr. Paul Zak) research

Full research files: ~/Vault/research/cloud-security-education-landscape-2026.md

---

## 16. Open Questions

1. **Environment fidelity:** LocalStack vs custom simulation vs hybrid? Needs technical spike.
2. **VEGA complexity:** How adaptive can we make VEGA in MVP without over-engineering?
3. **Pricing model:** Parked for now. Validate content quality and engagement first.
4. **Name:** DefensiveWorks with tagline "Attack to Defend" or "Engineer your defense. Prove it works." Final decision pending.
5. **Mobile experience:** Terminal-based platform is desktop-first. Is mobile needed?
6. **Accessibility:** Screen reader support for terminal-based UI needs investigation.

---

*This spec incorporates feedback from 5 independent reviewers: education/learning science expert, game designer, senior security practitioner, external research on simulation training effectiveness, and PracticalDevSecOps curriculum analysis.*
