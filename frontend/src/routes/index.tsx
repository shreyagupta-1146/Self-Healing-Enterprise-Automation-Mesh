import { createFileRoute, useRouter } from "@tanstack/react-router";
import { motion, AnimatePresence } from "motion/react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  ShieldCheck,
  Activity,
  User,
  Lock,
  Eye,
  EyeOff,
  ChevronRight,
  Loader2,
  Terminal,
  ShieldAlert,
  KeyRound,
  AlertTriangle,
  
} from "lucide-react";
import {
  appendEmergencyAudit,
  nowStamp as auditNow,
} from "@/lib/audit-log";

export const Route = createFileRoute("/")({
  component: LoginPage,
  head: () => ({
    meta: [
      { title: "SentiHealth — Secure Access" },
      {
        name: "description",
        content:
          "SentiHealth secure access portal. AI-powered threat detection for healthcare infrastructure.",
      },
    ],
  }),
});

type LogLevel = "INFO" | "WARN" | "ALERT";
interface LogEntry {
  time: string;
  level: LogLevel;
  message: string;
}

const initialLogs: LogEntry[] = [
  { time: "14:38:11", level: "INFO", message: "System initialized. Secure gateway online." },
  { time: "14:38:14", level: "INFO", message: "Connection established from IP 203.0.113.45" },
];

function nowStamp() {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function WorldMapBackdrop() {
  const nodes = useMemo(() => {
    const pts: { x: number; y: number; r: number; d: number }[] = [];
    let seed = 7;
    const rand = () => {
      seed = (seed * 9301 + 49297) % 233280;
      return seed / 233280;
    };
    for (let i = 0; i < 60; i++) {
      pts.push({
        x: rand() * 1440,
        y: 120 + rand() * 560,
        r: 1.2 + rand() * 1.8,
        d: rand() * 3,
      });
    }
    return pts;
  }, []);

  const lines = useMemo(() => {
    const ls: { x1: number; y1: number; x2: number; y2: number }[] = [];
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        if (Math.hypot(dx, dy) < 140) {
          ls.push({ x1: nodes[i].x, y1: nodes[i].y, x2: nodes[j].x, y2: nodes[j].y });
        }
      }
    }
    return ls;
  }, [nodes]);

  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden">
      <div
        aria-hidden
        className="absolute inset-0 opacity-[0.18]"
        style={{
          backgroundImage:
            "radial-gradient(circle, #94a3b8 1px, transparent 1.2px)",
          backgroundSize: "14px 14px",
          maskImage:
            "radial-gradient(ellipse 70% 55% at 50% 50%, black 55%, transparent 80%)",
          WebkitMaskImage:
            "radial-gradient(ellipse 70% 55% at 50% 50%, black 55%, transparent 80%)",
        }}
      />
      <svg
        className="absolute inset-0 h-full w-full"
        viewBox="0 0 1440 800"
        preserveAspectRatio="xMidYMid slice"
      >
        {lines.map((l, i) => (
          <line
            key={i}
            x1={l.x1}
            y1={l.y1}
            x2={l.x2}
            y2={l.y2}
            stroke="#1E90FF"
            strokeWidth="0.6"
            opacity="0.07"
          />
        ))}
        {nodes.map((n, i) => (
          <circle
            key={i}
            cx={n.x}
            cy={n.y}
            r={n.r}
            fill="#1E90FF"
            className="animate-node"
            style={{ animationDelay: `${n.d}s`, transformOrigin: `${n.x}px ${n.y}px` }}
            opacity="0.55"
          />
        ))}
      </svg>

      {[
        { top: "22%", left: "8%" },
        { top: "32%", right: "10%" },
        { bottom: "28%", left: "12%" },
        { bottom: "20%", right: "14%" },
      ].map((pos, i) => (
        <div
          key={i}
          className="absolute flex h-12 w-12 items-center justify-center rounded-full border border-sentinel/20 bg-sentinel/5 text-sentinel/40"
          style={pos as React.CSSProperties}
        >
          <Lock className="h-4 w-4" />
        </div>
      ))}
    </div>
  );
}

function ShieldLogo({ className = "h-12 w-12" }: { className?: string }) {
  return (
    <div className={`relative inline-flex items-center justify-center ${className}`}>
      <ShieldCheck
        className="absolute inset-0 h-full w-full text-sentinel"
        strokeWidth={1.4}
      />
      <Activity
        className="relative h-1/2 w-1/2 text-sentinel"
        strokeWidth={2.2}
      />
    </div>
  );
}

const VALID_OTP = "123456";
const CURRENT_IP = "198.51.100.22"; // simulated current request IP
const SESSION_KNOWN_IP_KEY = "sentihealth.knownIP";

type Stage = "login" | "otp" | "granted" | "suspended";function LoginPage() {
  const router = useRouter();
  const [tab, setTab] = useState<"login" | "register">("login");
  const [adminId, setAdminId] = useState("");
  const [securityKey, setSecurityKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [loading, setLoading] = useState(false);
  const [failedCount, setFailedCount] = useState(0);
  const [lockUntil, setLockUntil] = useState<number | null>(null);
  const [now, setNow] = useState(Date.now());
  const [logs, setLogs] = useState<LogEntry[]>(initialLogs);
  const logEndRef = useRef<HTMLDivElement>(null);

  const [stage, setStage] = useState<Stage>("login");
  const [loginUsername, setLoginUsername] = useState("");
  const [isAdminFlow, setIsAdminFlow] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [regSuccessMsg, setRegSuccessMsg] = useState("");

  const isLocked = lockUntil !== null && now < lockUntil;
  const lockRemaining = isLocked ? Math.ceil((lockUntil! - now) / 1000) : 0;

  useEffect(() => {
    if (typeof window !== "undefined" && sessionStorage.getItem("emergencyAccessLocked") === "true") {
      setStage("suspended");
    }
  }, []);

  useEffect(() => {
    if (!isLocked) return;
    const t = setInterval(() => setNow(Date.now()), 500);
    return () => clearInterval(t);
  }, [isLocked]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [logs]);

  const pushLog = (level: LogLevel, message: string) => {
    setLogs((prev) => [...prev, { time: nowStamp(), level, message }]);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isLocked || loading) return;
    if (!adminId.trim() || !securityKey.trim()) return;

    setLoading(true);
    setErrorMsg(null);
    setRegSuccessMsg("");

    try {
      if (tab === "register") {
        const response = await fetch("/api/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: adminId.trim(), password: securityKey.trim() })
        });
        const data = await response.json();
        setLoading(false);
        if (response.ok && data.success) {
          setRegSuccessMsg(data.message || "Registration request submitted!");
          pushLog("INFO", `Registration request submitted for "${adminId.trim()}". Awaiting Telegram approval.`);
          setAdminId("");
          setSecurityKey("");
        } else {
          setErrorMsg(data.message || "Registration failed.");
          pushLog("WARN", `Registration failed for "${adminId.trim()}": ${data.message}`);
        }
      } else {
        // Login mode
        const response = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: adminId.trim(), password: securityKey.trim() })
        });
        const data = await response.json();
        setLoading(false);
        if (response.ok && data.success) {
          pushLog("INFO", `Credentials accepted for "${adminId.trim()}".`);
          setLoginUsername(adminId.trim());
          setIsAdminFlow(data.is_admin);
          setStage("otp");

          if (data.is_admin) {
            pushLog("WARN", "Risk-adaptive MFA: Dynamic OTP written to logs/logs_dashboard.txt (SSHA).");
          } else {
            pushLog("INFO", "Approved context. Enter static access code.");
          }
        } else {
          setErrorMsg(data.message || "Invalid credentials.");
          pushLog("WARN", `Failed login attempt for "${adminId.trim()}"`);
          const newFailed = failedCount + 1;
          setFailedCount(newFailed);
          if (newFailed >= 3) {
            const until = Date.now() + 30000;
            setLockUntil(until);
            pushLog("ALERT", "Multiple failed login attempts. Account temporarily locked.");
          }
        }
      }
    } catch (err) {
      console.error(err);
      setLoading(false);
      setErrorMsg("Connection to security server failed.");
      pushLog("ALERT", "Security server offline or unreachable.");
    }
  };

  return (
    <main className="relative min-h-screen w-full overflow-hidden bg-background">
      <WorldMapBackdrop />

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.6 }}
        className="relative z-10 mx-auto flex min-h-screen w-full max-w-[1200px] flex-col items-center px-4 pt-10 pb-12"
      >
        <header className="mb-10 flex items-center gap-4">
          <div className="flex items-center gap-2">
            <ShieldLogo className="h-7 w-7" />
            <span className="text-[13px] font-semibold tracking-[0.18em] text-foreground">
              SENTIHEALTH
            </span>
          </div>
          <div className="h-5 w-px bg-border" />
          <span className="text-[13px] font-semibold tracking-[0.18em] text-sentinel">
            SECURE ACCESS
          </span>
        </header>

        <AnimatePresence mode="wait">
          {stage === "login" && (
            <motion.section
              key="login"
              initial={{ opacity: 0, y: 24 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.5, ease: "easeOut" }}
              className="w-full max-w-[560px] rounded-3xl border border-border bg-card/95 p-8 backdrop-blur-sm shadow-card sm:p-12"
            >
              <div className="flex flex-col items-center text-center">
                <ShieldLogo className="h-14 w-14" />
                <h1 className="mt-5 text-2xl font-semibold tracking-[0.18em] text-foreground sm:text-[28px]">
                  SENTI<span className="text-sentinel">HEALTH</span>
                </h1>
                <p className="mt-1.5 text-[11px] font-medium tracking-[0.28em] text-muted-foreground">
                  AI-POWERED THREAT DETECTION
                </p>
              </div>

              {/* Dual segment toggle for Login and Registration */}
              <div className="mt-6 flex rounded-xl bg-secondary p-1 border border-border">
                <button
                  type="button"
                  onClick={() => {
                    setTab("login");
                    setErrorMsg(null);
                    setRegSuccessMsg("");
                  }}
                  className={`flex-1 rounded-lg py-2.5 text-xs font-semibold uppercase tracking-wider transition-all duration-200 ${
                    tab === "login"
                      ? "bg-card text-foreground shadow-sm"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Sign In
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setTab("register");
                    setErrorMsg(null);
                    setRegSuccessMsg("");
                  }}
                  className={`flex-1 rounded-lg py-2.5 text-xs font-semibold uppercase tracking-wider transition-all duration-200 ${
                    tab === "register"
                      ? "bg-card text-foreground shadow-sm"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  Create Account
                </button>
              </div>

              <form onSubmit={handleSubmit} className="mt-6 space-y-5">
                <Field
                  label={tab === "login" ? "USER ID" : "CHOOSE USERNAME"}
                  icon={<User className="h-4 w-4" />}
                  value={adminId}
                  onChange={setAdminId}
                  placeholder={tab === "login" ? "Enter Admin or User ID" : "Enter a new username"}
                  autoComplete="username"
                  disabled={isLocked || loading}
                />

                <Field
                  label={tab === "login" ? "SECURITY KEY" : "CHOOSE PASSWORD"}
                  icon={<Lock className="h-4 w-4" />}
                  value={securityKey}
                  onChange={setSecurityKey}
                  placeholder={tab === "login" ? "Enter Security Key" : "Enter a strong password"}
                  type={showKey ? "text" : "password"}
                  autoComplete="current-password"
                  disabled={isLocked || loading}
                  trailing={
                    <button
                      type="button"
                      onClick={() => setShowKey((s) => !s)}
                      className="text-muted-foreground transition-colors hover:text-sentinel"
                      aria-label={showKey ? "Hide key" : "Show key"}
                      tabIndex={-1}
                    >
                      {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  }
                />

                {errorMsg && (
                  <motion.div
                    initial={{ opacity: 0, y: -4 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="flex items-center gap-2 rounded-lg border border-alert/30 bg-alert/5 px-3 py-2 text-[12.5px] text-alert"
                  >
                    <AlertTriangle className="h-4 w-4 shrink-0" />
                    <span>{errorMsg}</span>
                  </motion.div>
                )}

                {regSuccessMsg && (
                  <motion.div
                    initial={{ opacity: 0, y: -4 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="flex items-center gap-2 rounded-lg border border-success/30 bg-success/5 px-3 py-2 text-[12.5px] text-success"
                  >
                    <ShieldCheck className="h-4 w-4 shrink-0 text-success" />
                    <span>{regSuccessMsg}</span>
                  </motion.div>
                )}

                <motion.button
                  type="submit"
                  whileHover={!isLocked && !loading ? { y: -2 } : undefined}
                  whileTap={!isLocked && !loading ? { y: 0 } : undefined}
                  disabled={isLocked || loading}
                  className="btn-shimmer group relative flex h-14 w-full items-center justify-center gap-2 rounded-xl bg-gradient-sentinel text-[13px] font-semibold uppercase tracking-[0.22em] text-white transition-shadow duration-300 hover:shadow-glow disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {loading ? (
                    <Loader2 className="h-5 w-5 animate-spin" />
                  ) : isLocked ? (
                    <span>LOCKED · {lockRemaining}s</span>
                  ) : (
                    <>
                      <span>{tab === "login" ? "LOGIN" : "SUBMIT REQUEST"}</span>
                      <ChevronRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
                    </>
                  )}
                </motion.button>
              </form>

              <div className="mt-7 flex items-center justify-between rounded-2xl border border-border bg-secondary/50 px-4 py-3">
                <div className="flex items-center gap-3">
                  <span className="relative flex h-2.5 w-2.5">
                    <span className="absolute inline-flex h-full w-full rounded-full bg-success animate-status" />
                    <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-success" />
                  </span>
                  <div className="leading-tight">
                    <p className="text-[10px] font-semibold tracking-[0.22em] text-muted-foreground">
                      SYSTEM STATUS
                    </p>
                    <p className="text-[11px] font-semibold tracking-[0.18em] text-success">
                      ENCRYPTED SESSION ACTIVE
                    </p>
                  </div>
                </div>
                <div className="flex h-9 w-9 items-center justify-center rounded-full border border-success/40 bg-success/10 text-success">
                  <Lock className="h-4 w-4" />
                </div>
              </div>
            </motion.section>
          )}

          {stage === "otp" && (
            <EmergencyOtpCard
              key="otp"
              username={loginUsername}
              isAdmin={isAdminFlow}
              onSuccess={(token, isAdmin) => {
                appendEmergencyAudit({
                  type: "Emergency Access",
                  timestamp: auditNow(),
                  ip: CURRENT_IP,
                  status: "Verified",
                });
                pushLog("INFO", "Emergency verification succeeded. Session recorded in audit chain.");
                setStage("granted");
                sessionStorage.setItem("auth_token", token);
                sessionStorage.setItem("is_admin", isAdmin ? "1" : "0");
                sessionStorage.setItem(SESSION_KNOWN_IP_KEY, CURRENT_IP);
                setTimeout(() => router.navigate({ to: "/dashboard" }), 2000);
              }}
              onLockout={() => {
                appendEmergencyAudit({
                  type: "Emergency Access",
                  timestamp: auditNow(),
                  ip: CURRENT_IP,
                  status: "Blocked",
                });
                sessionStorage.setItem("emergencyAccessLocked", "true");
                pushLog("ALERT", "Emergency verification failed three times. Security team notified.");
                console.log("SECURITY: repeated failed login attempts from IP address");
                setStage("suspended");
              }}
            />
          )}

          {stage === "suspended" && <SuspendedCard key="suspended" />}
        </AnimatePresence>

        {stage === "login" && (
          <>
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.4, duration: 0.4 }}
              className="mt-5 flex items-center gap-2 text-[12px] text-muted-foreground"
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              Demo credentials — change before production deployment.
            </motion.p>

            <motion.section
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.25, duration: 0.5 }}
              className="mt-8 w-full max-w-[900px] overflow-hidden rounded-[18px] border border-border bg-card shadow-card"
            >
              <div className="flex items-center justify-between border-b border-border px-5 py-3">
                <div className="flex items-center gap-2 text-[12px] font-semibold tracking-[0.18em] text-foreground">
                  <Terminal className="h-4 w-4 text-muted-foreground" />
                  <span className="font-mono">&gt;_</span>
                  <span>SECURITY TERMINAL</span>
                </div>
                <div className="flex items-center gap-2 text-[11px] font-semibold tracking-[0.22em] text-muted-foreground">
                  <span className="relative flex h-2 w-2">
                    <span className="absolute inline-flex h-full w-full rounded-full bg-success animate-status" />
                    <span className="relative inline-flex h-2 w-2 rounded-full bg-success" />
                  </span>
                  LIVE FEED
                </div>
              </div>
              <div className="max-h-[260px] overflow-y-auto px-5 py-4 font-mono text-[12.5px] leading-relaxed">
                <AnimatePresence initial={false}>
                  {logs.map((l, i) => (
                    <motion.div
                      key={`${l.time}-${i}-${l.message}`}
                      initial={{ opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      className="flex gap-3 whitespace-pre-wrap break-words"
                    >
                      <span className="text-muted-foreground">[{l.time}]</span>
                      <span className={levelClass(l.level)}>{l.level.padEnd(5, " ")}</span>
                      <span className={l.level === "ALERT" ? "text-alert" : "text-foreground/85"}>
                        {l.message}
                      </span>
                    </motion.div>
                  ))}
                </AnimatePresence>
                <div ref={logEndRef} />
              </div>
            </motion.section>

            <footer className="mt-8 flex items-center gap-2 text-center text-[12px] text-muted-foreground">
              <Lock className="h-3.5 w-3.5" />
              <p>
                Level 4 Clearance Required. All actions are logged to the{" "}
                <span className="text-sentinel">SHA-256 Cryptographic Hash Chain</span>.
              </p>
            </footer>
          </>
        )}
      </motion.div>

      <AnimatePresence>
        {stage === "granted" && (
          <motion.div
            key="granted-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.4 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-white/95 backdrop-blur-md"
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ duration: 0.45, ease: "easeOut" }}
              className="flex flex-col items-center text-center"
            >
              <div className="relative flex h-20 w-20 items-center justify-center rounded-full border border-success/30 bg-success/10">
                <ShieldCheck className="h-10 w-10 text-success" strokeWidth={1.6} />
                <span className="absolute inset-0 rounded-full animate-status" />
              </div>
              <h2 className="mt-6 text-[22px] font-semibold tracking-[0.04em] text-success">
                Access Authorized
              </h2>
              <p className="mt-2 max-w-sm text-[13px] text-muted-foreground">
                This session has been recorded in the blockchain audit chain.
              </p>
              <div className="mt-5 flex items-center gap-2 text-[11px] font-semibold tracking-[0.22em] text-muted-foreground">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                LOADING DASHBOARD
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </main>
  );
}

function EmergencyOtpCard({
  onSuccess,
  onLockout,
  username,
  isAdmin,
}: {
  onSuccess: (token: string, isAdmin: boolean) => void;
  onLockout: () => void;
  username: string;
  isAdmin: boolean;
}) {
  const [code, setCode] = useState("");
  const [attempts, setAttempts] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (verifying || code.length !== 6) return;
    setVerifying(true);
    setError(null);

    try {
      const response = await fetch("/api/auth/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, code })
      });
      const data = await response.json();
      setVerifying(false);

      if (response.ok && data.success) {
        onSuccess(data.token, !!data.is_admin);
        return;
      }

      const next = attempts + 1;
      setAttempts(next);
      setCode("");

      if (next >= 3) {
        onLockout();
        return;
      }

      const remaining = 3 - next;
      setError(data.message || `Incorrect code. ${remaining} attempt${remaining === 1 ? "" : "s"} remaining.`);
    } catch (err) {
      setVerifying(false);
      setError("MFA server unreachable.");
    }
  };

  return (
    <motion.section
      initial={{ opacity: 0, y: 24 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -12 }}
      transition={{ duration: 0.5, ease: "easeOut" }}
      className="w-full max-w-[560px] rounded-3xl border border-border bg-card/95 p-8 backdrop-blur-sm shadow-card sm:p-12"
    >
      <div className="flex flex-col items-center text-center">
        <div className="relative flex h-14 w-14 items-center justify-center rounded-2xl border border-warn/30 bg-warn/10">
          <ShieldAlert className="h-7 w-7 text-warn" strokeWidth={1.6} />
        </div>
        <h1 className="mt-5 text-[22px] font-semibold tracking-[0.04em] text-foreground sm:text-[24px]">
          {isAdmin ? "Admin MFA Verification" : "User Security Verification"}
        </h1>
        <p className="mt-1.5 max-w-sm text-[13px] text-muted-foreground">
          {isAdmin
            ? "A dynamic OTP has been generated on the server console (on-prem, zero-cloud)."
            : "Please enter the static access code assigned by the administrator."}
        </p>
      </div>

      <form onSubmit={handleVerify} className="mt-8 space-y-5">
        <Field
          label="VERIFICATION CODE"
          icon={<KeyRound className="h-4 w-4" />}
          value={code}
          onChange={(v) => {
            setError(null);
            setCode(v.replace(/\D/g, "").slice(0, 6));
          }}
          placeholder="6-digit code"
          inputMode="numeric"
          disabled={verifying}
        />

        {error && (
          <motion.div
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-2 rounded-lg border border-alert/30 bg-alert/5 px-3 py-2 text-[12.5px] text-alert"
          >
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </motion.div>
        )}

        <motion.button
          type="submit"
          whileHover={code.length === 6 && !verifying ? { y: -2 } : undefined}
          whileTap={code.length === 6 && !verifying ? { y: 0 } : undefined}
          disabled={code.length !== 6 || verifying}
          className="btn-shimmer group relative flex h-14 w-full items-center justify-center gap-2 rounded-xl bg-gradient-sentinel text-[13px] font-semibold uppercase tracking-[0.22em] text-white transition-shadow duration-300 hover:shadow-glow disabled:cursor-not-allowed disabled:opacity-60"
        >
          {verifying ? (
            <Loader2 className="h-5 w-5 animate-spin" />
          ) : (
            <>
              <span>VERIFY ACCESS</span>
              <ChevronRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
            </>
          )}
        </motion.button>
      </form>

      <div className="mt-6 space-y-2 text-center">
        <p className="text-[12.5px] text-foreground/80">
          {isAdmin
            ? "Check logs/logs_dashboard.txt for the dynamic OTP — no external service required."
            : "Use the code assigned to you when your account was approved."}
        </p>
        <p className="text-[11.5px] text-muted-foreground">
          This access attempt has been logged in the audit chain with your IP address and timestamp.
        </p>
      </div>
    </motion.section>
  );
}

function SuspendedCard() {
  return (
    <motion.section
      initial={{ opacity: 0, y: 24 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: "easeOut" }}
      className="w-full max-w-[560px] rounded-3xl border border-alert/30 bg-card/95 p-10 text-center backdrop-blur-sm shadow-card sm:p-14"
    >
      <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-full border border-alert/30 bg-alert/10">
        <ShieldAlert className="h-10 w-10 text-alert" strokeWidth={1.6} />
      </div>
      <h1 className="mt-6 text-[24px] font-semibold tracking-[0.04em] text-alert">
        Access Suspended
      </h1>
      <p className="mt-3 text-[13.5px] text-muted-foreground">
        Security team has been notified.
      </p>
      
      <button
        onClick={() => {
          sessionStorage.removeItem("emergencyAccessLocked");
          window.location.reload();
        }}
        className="mt-6 inline-flex items-center gap-2 rounded-lg border border-alert/30 bg-alert/5 px-4 py-2 text-xs font-semibold text-alert hover:bg-alert/10 transition-colors"
      >
        Clear Lockout & Retry
      </button>

      <div className="mt-8 flex items-center justify-center gap-2 text-[11px] font-semibold tracking-[0.22em] text-muted-foreground">
        <Lock className="h-3.5 w-3.5" />
        SESSION LOCKED
      </div>
    </motion.section>
  );
}

function levelClass(level: LogLevel) {
  switch (level) {
    case "INFO":
      return "text-sentinel font-semibold";
    case "WARN":
      return "text-warn font-semibold";
    case "ALERT":
      return "text-alert font-semibold";
  }
}

interface FieldProps {
  label: string;
  icon: React.ReactNode;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  autoComplete?: string;
  disabled?: boolean;
  trailing?: React.ReactNode;
  inputMode?: "text" | "numeric" | "decimal" | "email" | "tel" | "url" | "search";
}

function Field({
  label,
  icon,
  value,
  onChange,
  placeholder,
  type = "text",
  autoComplete,
  disabled,
  trailing,
  inputMode,
}: FieldProps) {
  return (
    <div>
      <label className="mb-2 block text-[11px] font-semibold tracking-[0.22em] text-foreground">
        {label}
      </label>
      <div className="group relative">
        <span className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground transition-colors group-focus-within:text-sentinel">
          {icon}
        </span>
        <input
          type={type}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete={autoComplete}
          disabled={disabled}
          inputMode={inputMode}
          className="focus-sentinel h-14 w-full rounded-xl border border-input bg-card pl-11 pr-12 text-[14px] text-foreground placeholder:text-[#94A3B8] transition-shadow disabled:opacity-60"
        />
        {trailing && (
          <div className="absolute right-4 top-1/2 -translate-y-1/2">{trailing}</div>
        )}
      </div>
    </div>
  );
}


