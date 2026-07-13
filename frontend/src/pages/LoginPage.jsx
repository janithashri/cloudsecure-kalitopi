import { useState } from "react";
import { useNavigate, useSearchParams, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function LoginPage() {
  const [searchParams] = useSearchParams();
  const [tab, setTab] = useState(searchParams.get("tab") === "signup" ? "signup" : "signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { login, api } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    if (tab === "signup" && password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    setLoading(true);
    try {
      if (tab === "signup") {
        await api.post("/api/auth/register/", {
          username: email.trim(),
          email: email.trim(),
          password,
        });
      }
      await login(email.trim(), password);
      navigate("/dashboard");
    } catch (err) {
      if (err.code === "ECONNABORTED" || err.message === "Network Error" || !err.response) {
        setError("Can't reach the backend. Is the server running?");
      } else {
        const data = err.response?.data;
        if (typeof data === "object" && !data.detail) {
          const msgs = Object.values(data).flat().join(". ");
          setError(msgs || "Request failed");
        } else {
          setError(data?.detail || "Request failed");
        }
      }
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setError("");
    setLoading(true);
    try {
      // Demo: auto-create and login a Google demo user
      const demoEmail = "demo@gmail.com";
      const demoPass = "CloudSecure2026!";
      try {
        await api.post("/api/auth/register/", {
          username: demoEmail,
          email: demoEmail,
          password: demoPass,
        });
      } catch {
        // User may already exist, that's fine
      }
      await login(demoEmail, demoPass);
      navigate("/dashboard");
    } catch (err) {
      setError("Google sign-in failed. Try email login instead.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-slate-950">
      {/* Left panel - branding */}
      <div className="hidden w-1/2 flex-col justify-between bg-gradient-to-br from-slate-900 via-slate-900 to-emerald-950 p-12 lg:flex">
        <Link to="/" className="flex items-center gap-2">
          <img src="/logo.png" alt="CloudSecure" className="h-9 w-9 object-contain" />
          <span className="text-xl font-bold text-white">CloudSecure</span>
        </Link>

        <div>
          <h2 className="text-4xl font-bold leading-tight text-white">
            Secure your cloud
            <br />
            <span className="bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">
              infrastructure
            </span>
          </h2>
          <p className="mt-4 max-w-md text-slate-400">
            Automated CIS benchmark scanning, real-time misconfiguration detection,
            and actionable remediation across your AWS environment.
          </p>
          <div className="mt-10 grid grid-cols-2 gap-4">
            {[
              { val: "350+", label: "Security Checks" },
              { val: "7", label: "AWS Services" },
              { val: "4", label: "Frameworks" },
              { val: "<5min", label: "First Scan" },
            ].map((s) => (
              <div key={s.label} className="rounded-xl border border-slate-800 bg-slate-800/30 p-4">
                <p className="text-2xl font-bold text-emerald-400">{s.val}</p>
                <p className="text-xs text-slate-500">{s.label}</p>
              </div>
            ))}
          </div>
        </div>

        <p className="text-xs text-slate-600">Team Kaalitopi | Cloud Security Scanner</p>
      </div>

      {/* Right panel - form */}
      <div className="flex w-full flex-col items-center justify-center px-6 lg:w-1/2">
        {/* Mobile logo */}
        <Link to="/" className="mb-8 flex items-center gap-2 lg:hidden">
          <img src="/logo.png" alt="CloudSecure" className="h-9 w-9 object-contain" />
          <span className="text-xl font-bold text-white">CloudSecure</span>
        </Link>

        <div className="w-full max-w-md">
          {/* Tab switcher */}
          <div className="mb-8 flex rounded-xl bg-slate-900 p-1">
            <button
              onClick={() => { setTab("signin"); setError(""); }}
              className={`flex-1 rounded-lg py-2.5 text-sm font-medium transition ${
                tab === "signin"
                  ? "bg-emerald-500 text-white shadow"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              Sign In
            </button>
            <button
              onClick={() => { setTab("signup"); setError(""); }}
              className={`flex-1 rounded-lg py-2.5 text-sm font-medium transition ${
                tab === "signup"
                  ? "bg-emerald-500 text-white shadow"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              Sign Up
            </button>
          </div>

          <h1 className="text-2xl font-bold text-white">
            {tab === "signin" ? "Welcome back" : "Create your account"}
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            {tab === "signin"
              ? "Sign in to access your security dashboard"
              : "Start scanning your cloud infrastructure"}
          </p>

          {/* Google sign-in */}
          <button
            type="button"
            onClick={handleGoogleSignIn}
            className="mt-6 flex w-full items-center justify-center gap-3 rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-sm font-medium text-slate-200 transition hover:border-slate-600 hover:bg-slate-800"
          >
            <svg className="h-5 w-5" viewBox="0 0 24 24">
              <path
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 01-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"
                fill="#4285F4"
              />
              <path
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                fill="#34A853"
              />
              <path
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                fill="#FBBC05"
              />
              <path
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                fill="#EA4335"
              />
            </svg>
            Continue with Google
          </button>

          <div className="my-6 flex items-center gap-3">
            <div className="h-px flex-1 bg-slate-800" />
            <span className="text-xs text-slate-500">or continue with email</span>
            <div className="h-px flex-1 bg-slate-800" />
          </div>

          {/* Email form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-slate-300">
                Email
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-white placeholder-slate-500 outline-none transition focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                placeholder="you@company.com"
                required
                autoComplete="username"
              />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-slate-300">
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-white placeholder-slate-500 outline-none transition focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                placeholder="Enter your password"
                required
                autoComplete={tab === "signin" ? "current-password" : "new-password"}
              />
            </div>

            {tab === "signup" && (
              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-slate-300">
                  Confirm Password
                </label>
                <input
                  id="confirmPassword"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-white placeholder-slate-500 outline-none transition focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                  placeholder="Confirm your password"
                  required
                  autoComplete="new-password"
                />
              </div>
            )}

            {error && (
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-emerald-500 py-3 font-semibold text-white shadow-lg shadow-emerald-500/25 transition hover:bg-emerald-400 disabled:opacity-50"
            >
              {loading ? (
                <span className="inline-block h-5 w-5 animate-spin rounded-full border-2 border-white border-t-transparent" />
              ) : tab === "signin" ? (
                "Sign In"
              ) : (
                "Create Account"
              )}
            </button>
          </form>

          <p className="mt-6 text-center text-sm text-slate-500">
            {tab === "signin" ? "Don't have an account? " : "Already have an account? "}
            <button
              type="button"
              onClick={() => { setTab(tab === "signin" ? "signup" : "signin"); setError(""); }}
              className="text-emerald-400 hover:text-emerald-300"
            >
              {tab === "signin" ? "Sign up" : "Sign in"}
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}
