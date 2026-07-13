import { Link } from "react-router-dom";

const features = [
  {
    icon: (
      <svg className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
      </svg>
    ),
    title: "CIS Benchmark Scanning",
    desc: "Automated checks against CIS AWS Foundations Benchmark for comprehensive security compliance.",
  },
  {
    icon: (
      <svg className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
      </svg>
    ),
    title: "Real-Time Visibility",
    desc: "Continuous monitoring of your cloud infrastructure with instant misconfiguration detection.",
  },
  {
    icon: (
      <svg className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M11.42 15.17l-5.1-5.1a7.065 7.065 0 010-10 7.065 7.065 0 0110 0l.71.71.71-.71a7.065 7.065 0 0110 0 7.065 7.065 0 010 10l-5.1 5.1L12 21.5l-.58-.58z" />
      </svg>
    ),
    title: "Actionable Remediation",
    desc: "Step-by-step fix guidance for every finding so your team can resolve issues fast.",
  },
  {
    icon: (
      <svg className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3v11.25A2.25 2.25 0 006 16.5h2.25M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-2.25m-7.5 0h7.5m-7.5 0l-1 3m8.5-3l1 3m0 0l.5 1.5m-.5-1.5h-9.5m0 0l-.5 1.5m.75-9l3-3 2.148 2.148A12.061 12.061 0 0116.5 7.605" />
      </svg>
    ),
    title: "Compliance Reports",
    desc: "Export findings as PDF/CSV reports mapped to CIS, DPDP, RBI, and SBE frameworks.",
  },
  {
    icon: (
      <svg className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 0v3.75m-16.5-3.75v3.75m16.5 0v3.75C20.25 16.153 16.556 18 12 18s-8.25-1.847-8.25-4.125v-3.75m16.5 0c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" />
      </svg>
    ),
    title: "7 AWS Services",
    desc: "Deep scanning across S3, EC2, IAM, RDS, KMS, CloudTrail, and Security Groups.",
  },
  {
    icon: (
      <svg className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z" />
      </svg>
    ),
    title: "Graph Visualization",
    desc: "Neo4j-powered resource relationship mapping to understand your cloud topology.",
  },
];

const stats = [
  { value: "350+", label: "Security Checks" },
  { value: "7", label: "AWS Services" },
  { value: "4", label: "Compliance Frameworks" },
  { value: "12", label: "Rego Policies" },
];

const steps = [
  { num: "01", title: "Connect", desc: "Link your AWS account with a read-only IAM role in under 2 minutes." },
  { num: "02", title: "Scan", desc: "One-click scan across all supported services. Results in seconds." },
  { num: "03", title: "Remediate", desc: "Review findings, follow remediation steps, and export compliance reports." },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-slate-950 text-white">
      {/* Navbar */}
      <nav className="sticky top-0 z-50 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
          <div className="flex items-center gap-2">
            <img src="/logo.png" alt="CloudSecure" className="h-9 w-9 object-contain" />
            <span className="text-xl font-bold tracking-tight">CloudSecure</span>
          </div>
          <div className="hidden items-center gap-8 md:flex">
            <a href="#features" className="text-sm text-slate-300 transition hover:text-white">Features</a>
            <a href="#how-it-works" className="text-sm text-slate-300 transition hover:text-white">How It Works</a>
            <a href="#pricing" className="text-sm text-slate-300 transition hover:text-white">Pricing</a>
            <a href="#about" className="text-sm text-slate-300 transition hover:text-white">About</a>
            <Link to="/docs" className="text-sm text-slate-300 transition hover:text-white">Docs</Link>
          </div>
          <div className="flex items-center gap-3">
            <Link to="/login" className="text-sm text-slate-300 transition hover:text-white">
              Sign In
            </Link>
            <Link
              to="/login?tab=signup"
              className="rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-white transition hover:bg-emerald-400"
            >
              Get Started
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-emerald-900/20 via-transparent to-cyan-900/20" />
        <div className="absolute inset-0">
          <div className="absolute left-1/4 top-1/4 h-96 w-96 rounded-full bg-emerald-500/5 blur-3xl" />
          <div className="absolute bottom-1/4 right-1/4 h-96 w-96 rounded-full bg-cyan-500/5 blur-3xl" />
        </div>
        <div className="relative mx-auto max-w-7xl px-6 py-24 lg:py-36">
          <div className="mx-auto max-w-3xl text-center">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-4 py-1.5 text-sm text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              Securing Cloud Infrastructure
            </div>
            <h1 className="text-4xl font-bold leading-tight tracking-tight sm:text-5xl lg:text-6xl">
              Find & Fix{" "}
              <span className="bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">
                Cloud Misconfigurations
              </span>{" "}
              Before Attackers Do
            </h1>
            <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-slate-400">
              Audit your AWS infrastructure against CIS benchmarks, detect security misconfigurations
              across S3, EC2, IAM, RDS, KMS, and CloudTrail — with actionable remediation steps.
            </p>
            <div className="mt-10 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
              <Link
                to="/login?tab=signup"
                className="w-full rounded-lg bg-emerald-500 px-8 py-3.5 text-center font-semibold text-white shadow-lg shadow-emerald-500/25 transition hover:bg-emerald-400 sm:w-auto"
              >
                Launch Scanner
              </Link>
              <Link
                to="/login"
                className="w-full rounded-lg border border-slate-700 bg-slate-800/50 px-8 py-3.5 text-center font-semibold text-slate-300 transition hover:border-slate-600 hover:text-white sm:w-auto"
              >
                Sign In
              </Link>
            </div>
          </div>

          {/* Terminal preview */}
          <div className="mx-auto mt-16 max-w-2xl">
            <div className="overflow-hidden rounded-xl border border-slate-700/50 bg-slate-900 shadow-2xl shadow-black/50">
              <div className="flex items-center gap-2 border-b border-slate-700/50 px-4 py-3">
                <div className="h-3 w-3 rounded-full bg-red-500/80" />
                <div className="h-3 w-3 rounded-full bg-yellow-500/80" />
                <div className="h-3 w-3 rounded-full bg-green-500/80" />
                <span className="ml-2 text-xs text-slate-500">CloudSecure Scanner</span>
              </div>
              <div className="p-6 font-mono text-sm leading-relaxed">
                <p className="text-slate-500">$ cloudsecure scan --provider aws</p>
                <p className="mt-2 text-emerald-400">[*] Assuming role CloudSecureRole...</p>
                <p className="text-emerald-400">[*] Scanning 7 services across us-east-1...</p>
                <p className="mt-2 text-slate-300">&nbsp;&nbsp;S3 buckets ............. <span className="text-emerald-400">12 scanned</span></p>
                <p className="text-slate-300">&nbsp;&nbsp;EC2 instances .......... <span className="text-emerald-400">8 scanned</span></p>
                <p className="text-slate-300">&nbsp;&nbsp;IAM users/roles ........ <span className="text-emerald-400">23 scanned</span></p>
                <p className="text-slate-300">&nbsp;&nbsp;RDS instances .......... <span className="text-emerald-400">3 scanned</span></p>
                <p className="text-slate-300">&nbsp;&nbsp;KMS keys ............... <span className="text-emerald-400">5 scanned</span></p>
                <p className="text-slate-300">&nbsp;&nbsp;CloudTrail trails ...... <span className="text-emerald-400">2 scanned</span></p>
                <p className="mt-2 text-yellow-400">[!] 14 findings: 2 CRITICAL, 5 HIGH, 4 MEDIUM, 3 LOW</p>
                <p className="text-emerald-400">[*] Report saved to findings_report.pdf</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section className="border-y border-slate-800 bg-slate-900/50">
        <div className="mx-auto grid max-w-7xl grid-cols-2 gap-8 px-6 py-16 lg:grid-cols-4">
          {stats.map((s) => (
            <div key={s.label} className="text-center">
              <p className="text-3xl font-bold text-emerald-400 sm:text-4xl">{s.value}</p>
              <p className="mt-2 text-sm text-slate-400">{s.label}</p>
            </div>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section id="how-it-works" className="mx-auto max-w-7xl px-6 py-24">
        <div className="text-center">
          <p className="text-sm font-semibold uppercase tracking-wider text-emerald-400">How It Works</p>
          <h2 className="mt-2 text-3xl font-bold sm:text-4xl">Three Simple Steps</h2>
        </div>
        <div className="mt-16 grid gap-8 md:grid-cols-3">
          {steps.map((step) => (
            <div
              key={step.num}
              className="relative rounded-2xl border border-slate-800 bg-slate-900/50 p-8 transition hover:border-emerald-500/30"
            >
              <span className="absolute right-6 top-6 text-5xl font-black text-slate-800">{step.num}</span>
              <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-400">
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <h3 className="text-xl font-semibold">{step.title}</h3>
              <p className="mt-2 text-slate-400">{step.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section id="features" className="border-t border-slate-800 bg-slate-900/30">
        <div className="mx-auto max-w-7xl px-6 py-24">
          <div className="text-center">
            <p className="text-sm font-semibold uppercase tracking-wider text-emerald-400">What We Offer</p>
            <h2 className="mt-2 text-3xl font-bold sm:text-4xl">Comprehensive Cloud Security</h2>
          </div>
          <div className="mt-16 grid gap-8 sm:grid-cols-2 lg:grid-cols-3">
            {features.map((f) => (
              <div
                key={f.title}
                className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 transition hover:border-emerald-500/30"
              >
                <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-400">
                  {f.icon}
                </div>
                <h3 className="text-lg font-semibold">{f.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-400">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing — Coming Soon */}
      <section id="pricing" className="mx-auto max-w-7xl px-6 py-24">
        <div className="text-center">
          <p className="text-sm font-semibold uppercase tracking-wider text-emerald-400">Pricing</p>
          <h2 className="mt-2 text-3xl font-bold sm:text-4xl">Simple, Transparent Pricing</h2>
          <p className="mx-auto mt-4 max-w-xl text-slate-400">
            Flexible plans for individuals, teams, and enterprises — no hidden costs, no complexity.
          </p>
        </div>

        {/* Toggle (visual only) */}
        <div className="mt-10 flex items-center justify-center gap-4">
          <span className="text-sm font-medium text-white">Monthly</span>
          <div className="relative h-7 w-12 rounded-full bg-slate-700 p-1 cursor-not-allowed">
            <div className="h-5 w-5 rounded-full bg-emerald-400 shadow transition" />
          </div>
          <span className="text-sm text-slate-400">Annual</span>
          <span className="rounded-full bg-emerald-500/20 px-3 py-0.5 text-xs font-semibold text-emerald-400">
            Save 20%
          </span>
        </div>

        {/* Cards */}
        <div className="mt-12 grid gap-8 md:grid-cols-3">
          {/* Starter */}
          <div className="relative rounded-2xl border border-slate-800 bg-slate-900/50 p-8 transition hover:border-emerald-500/30">
            <h3 className="text-lg font-semibold">Starter</h3>
            <p className="mt-2 text-sm text-slate-400">For individuals getting started with cloud security.</p>
            <div className="mt-6 flex items-baseline gap-1">
              <span className="text-4xl font-bold text-white">—</span>
            </div>
            <ul className="mt-8 space-y-3 text-sm text-slate-400">
              <li className="flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
                1 AWS Account
              </li>
              <li className="flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
                Basic CIS Checks
              </li>
              <li className="flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
                Email Reports
              </li>
            </ul>
            <button
              disabled
              className="mt-8 w-full rounded-lg border border-slate-700 bg-slate-800/50 py-3 text-sm font-semibold text-slate-400 cursor-not-allowed"
            >
              Coming Soon
            </button>
          </div>

          {/* Pro — Popular */}
          <div className="relative rounded-2xl border-2 border-emerald-500/50 bg-slate-900/80 p-8 shadow-lg shadow-emerald-500/5 transition hover:border-emerald-500/70">
            <span className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-emerald-500 px-4 py-1 text-xs font-bold uppercase tracking-wider text-white">
              Popular
            </span>
            <h3 className="text-lg font-semibold">Pro</h3>
            <p className="mt-2 text-sm text-slate-400">For teams that need scale, compliance, and priority support.</p>
            <div className="mt-6 flex items-baseline gap-1">
              <span className="text-4xl font-bold text-white">—</span>
            </div>
            <ul className="mt-8 space-y-3 text-sm text-slate-400">
              <li className="flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
                Up to 10 AWS Accounts
              </li>
              <li className="flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
                Deep Scan + Graph Analysis
              </li>
              <li className="flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
                Custom Rego Policies
              </li>
              <li className="flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
                Priority Support
              </li>
            </ul>
            <button
              disabled
              className="mt-8 w-full rounded-lg bg-emerald-600/40 py-3 text-sm font-semibold text-emerald-300 cursor-not-allowed"
            >
              Coming Soon
            </button>
          </div>

          {/* Enterprise */}
          <div className="relative rounded-2xl border border-slate-800 bg-slate-900/50 p-8 transition hover:border-emerald-500/30">
            <h3 className="text-lg font-semibold">Enterprise</h3>
            <p className="mt-2 text-sm text-slate-400">For large organizations requiring unlimited resources and dedicated support.</p>
            <div className="mt-6 flex items-baseline gap-1">
              <span className="text-4xl font-bold text-white">—</span>
            </div>
            <ul className="mt-8 space-y-3 text-sm text-slate-400">
              <li className="flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
                Unlimited AWS Accounts
              </li>
              <li className="flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
                Multi-Cloud (AWS, Azure, GCP)
              </li>
              <li className="flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
                SSO & RBAC Integration
              </li>
              <li className="flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
                Dedicated Account Manager
              </li>
            </ul>
            <button
              disabled
              className="mt-8 w-full rounded-lg border border-slate-700 bg-slate-800/50 py-3 text-sm font-semibold text-slate-400 cursor-not-allowed"
            >
              Coming Soon
            </button>
          </div>
        </div>

        <p className="mt-10 text-center text-sm text-slate-500">
          Contact us for multi-year or volume discounts.
        </p>
      </section>

      {/* About / Mission */}
      <section id="about" className="mx-auto max-w-7xl px-6 py-24">
        <div className="grid gap-16 lg:grid-cols-2 lg:items-center">
          <div>
            <p className="text-sm font-semibold uppercase tracking-wider text-emerald-400">About CloudSecure</p>
            <h2 className="mt-2 text-3xl font-bold sm:text-4xl">
              Built for Cloud Security Compliance
            </h2>
            <p className="mt-4 leading-relaxed text-slate-400">
              CloudSecure is a Cloud Security Posture Management (CSPM) tool that continuously audits your
              AWS infrastructure configurations and detects security misconfigurations against industry
              benchmarks like CIS and India-specific compliance frameworks.
            </p>
            <div className="mt-8 space-y-6">
              <div className="flex gap-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400">
                  <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <div>
                  <h4 className="font-semibold">Our Mission</h4>
                  <p className="mt-1 text-sm text-slate-400">
                    Make cloud security accessible by automating misconfiguration detection with
                    actionable, framework-mapped remediation guidance.
                  </p>
                </div>
              </div>
              <div className="flex gap-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400">
                  <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                    <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  </svg>
                </div>
                <div>
                  <h4 className="font-semibold">Our Vision</h4>
                  <p className="mt-1 text-sm text-slate-400">
                    A multi-cloud CSPM platform supporting AWS, Azure, and GCP with full CIS, NIST,
                    and regional compliance coverage.
                  </p>
                </div>
              </div>
            </div>
          </div>
          <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8">
            <h3 className="text-lg font-semibold">Supported Frameworks</h3>
            <div className="mt-6 grid grid-cols-2 gap-4">
              {[
                { name: "CIS AWS", desc: "Foundations Benchmark v1.5" },
                { name: "India DPDP", desc: "Data Protection Act 2023" },
                { name: "RBI", desc: "Reserve Bank of India" },
                { name: "SBE / CERT-In", desc: "Security Best Practices" },
              ].map((fw) => (
                <div key={fw.name} className="rounded-xl border border-slate-700 bg-slate-800/50 p-4">
                  <p className="font-semibold text-emerald-400">{fw.name}</p>
                  <p className="mt-1 text-xs text-slate-400">{fw.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="border-t border-slate-800">
        <div className="mx-auto max-w-7xl px-6 py-24 text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">Ready to Secure Your Cloud?</h2>
          <p className="mx-auto mt-4 max-w-xl text-slate-400">
            Connect your AWS account and get your first security scan in under 5 minutes.
          </p>
          <Link
            to="/login?tab=signup"
            className="mt-8 inline-block rounded-lg bg-emerald-500 px-8 py-3.5 font-semibold text-white shadow-lg shadow-emerald-500/25 transition hover:bg-emerald-400"
          >
            Start Free Scan
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-900/50">
        <div className="mx-auto max-w-7xl px-6 py-8">
          <div className="flex flex-col items-center justify-between gap-4 sm:flex-row">
            <div className="flex items-center gap-2">
              <img src="/logo.png" alt="CloudSecure" className="h-7 w-7 object-contain" />
              <span className="font-semibold">CloudSecure</span>
            </div>
            <p className="text-sm text-slate-500">
              Built by Team Kaalitopi | Cloud Misconfiguration Security Scanner
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
