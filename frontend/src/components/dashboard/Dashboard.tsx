import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  ShieldCheck, ShieldAlert, Timer, Lock, ChevronDown, ChevronUp,
  Clock, Filter, Link2, Search, LogOut, BarChart2, X, Info,
} from "lucide-react";
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, LabelList,
} from "recharts";
import { useSentinel, useMLMetrics, authHeaders, formatMTTR, type Tier, type Action, type MLMetricRow } from "@/lib/sentinel-data";
import { Link } from "@tanstack/react-router";
import { toast, Toaster } from "sonner";

/* ---------- real-time High-tier alert hook (SSE) ---------- */

function useHighTierSSE() {
  const seenRef = useRef<Set<string>>(new Set());

  // Ask for browser notification permission once on mount
  useEffect(() => {
    if ("Notification" in window && Notification.permission === "default") {
      Notification.requestPermission();
    }
  }, []);

  useEffect(() => {
    const token = sessionStorage.getItem("auth_token");
    if (!token) return;

    /** Inline YES/NO respond — used by the toast buttons */
    const respondInline = async (incidentId: string, decision: "YES" | "DENY") => {
      try {
        const res = await fetch(`/api/alerts/${incidentId}/respond`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          body: JSON.stringify({ decision }),
        });
        const d = await res.json();
        if (d.success) {
          toast.success(
            decision === "YES"
              ? "✓ Approved — forensic report generating."
              : "✗ Denied — defensive posture held.",
          );
        }
      } catch {
        toast.error("Failed to send response. Check your connection.");
      }
    };

    const es = new EventSource(`/api/stream?token=${encodeURIComponent(token)}`);

    es.addEventListener("high_alert", (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data) as {
          incident_id: string;
          prompt: string;
          timeout_sec: number;
          timestamp: string;
        };
        if (seenRef.current.has(data.incident_id)) return;
        seenRef.current.add(data.incident_id);

        const deadline = data.timeout_sec ?? 90;

        // ── Browser notification for background-tab alert ──────────────────
        if ("Notification" in window && Notification.permission === "granted") {
          new Notification("🚨 SentiHealth — High-Tier Threat", {
            body: `${data.prompt.slice(0, 100)}  |  Auto-lockdown in ${deadline}s`,
            icon: "/favicon.ico",
          });
        }

        // ── Inline YES/NO toast (lasts the full timeout window) ────────────
        toast.custom(
          (t) => (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: 10,
                borderRadius: 14,
                border: "2px solid rgba(248,113,113,0.45)",
                background: "rgba(30,0,0,0.97)",
                padding: "14px 16px",
                width: 360,
                boxShadow: "0 8px 32px rgba(0,0,0,0.55)",
              }}
            >
              {/* header */}
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span
                  style={{
                    display: "inline-block",
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    background: "#f87171",
                    animation: "pulse 1.5s infinite",
                    flexShrink: 0,
                  }}
                />
                <span
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    color: "#fca5a5",
                  }}
                >
                  High-Tier Threat — Action Required
                </span>
              </div>

              {/* prompt */}
              <p style={{ fontSize: 12, color: "rgba(255,255,255,0.88)", lineHeight: 1.55, margin: 0 }}>
                {data.prompt}
              </p>

              {/* deadline label */}
              <p style={{ fontSize: 11, color: "#fbbf24", margin: 0 }}>
                ⏱ Auto-lockdown fires in {deadline}s if no response
              </p>

              {/* YES / NO buttons */}
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  onClick={() => { respondInline(data.incident_id, "YES"); toast.dismiss(t); }}
                  style={{
                    flex: 1, borderRadius: 8, background: "#16a34a",
                    color: "white", fontWeight: 700, fontSize: 12,
                    padding: "8px 0", border: "none", cursor: "pointer",
                  }}
                  onMouseEnter={(e) => { (e.target as HTMLElement).style.background = "#22c55e"; }}
                  onMouseLeave={(e) => { (e.target as HTMLElement).style.background = "#16a34a"; }}
                >
                  ✓ YES — Approve
                </button>
                <button
                  onClick={() => { respondInline(data.incident_id, "DENY"); toast.dismiss(t); }}
                  style={{
                    flex: 1, borderRadius: 8, background: "#b91c1c",
                    color: "white", fontWeight: 700, fontSize: 12,
                    padding: "8px 0", border: "none", cursor: "pointer",
                  }}
                  onMouseEnter={(e) => { (e.target as HTMLElement).style.background = "#ef4444"; }}
                  onMouseLeave={(e) => { (e.target as HTMLElement).style.background = "#b91c1c"; }}
                >
                  ✗ NO — Deny
                </button>
              </div>

              {/* scroll-to console link */}
              <button
                onClick={() =>
                  document.getElementById("ssha-auth-console")?.scrollIntoView({ behavior: "smooth" })
                }
                style={{
                  background: "none", border: "none", color: "rgba(255,255,255,0.45)",
                  fontSize: 10, cursor: "pointer", padding: 0, textAlign: "left",
                  textDecoration: "underline",
                }}
              >
                View full Auth Console ↓
              </button>
            </div>
          ),
          { duration: deadline * 1000 },
        );
      } catch {}
    });

    es.onerror = () => es.close();
    return () => es.close();
  }, []);
}

/* ---------- rich hover tooltip ---------- */

/**
 * Wraps any element. On hover, renders a styled card (via portal so it
 * never gets clipped by overflow:hidden or table stacking contexts).
 */
function HoverCard({
  children,
  content,
  maxWidth = 340,
}: {
  children: React.ReactNode;
  content: React.ReactNode;
  maxWidth?: number;
}) {
  const [show, setShow] = useState(false);
  const [coords, setCoords] = useState({ x: 0, y: 0, above: false });

  const handleEnter = (e: React.MouseEvent) => {
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const spaceBelow = window.innerHeight - rect.bottom;
    const above = spaceBelow < 220 && rect.top > 220;
    const x = Math.max(8, Math.min(rect.left, window.innerWidth - maxWidth - 8));
    const y = above ? rect.top - 8 : rect.bottom + 6;
    setCoords({ x, y, above });
    setShow(true);
  };

  return (
    <>
      <span
        className="inline-block cursor-default"
        onMouseEnter={handleEnter}
        onMouseLeave={() => setShow(false)}
      >
        {children}
      </span>
      {show &&
        createPortal(
          <div
            style={{
              position: "fixed",
              left: coords.x,
              top: coords.above ? undefined : coords.y,
              bottom: coords.above ? window.innerHeight - coords.y : undefined,
              width: maxWidth,
              zIndex: 9999,
            }}
            className="pointer-events-none rounded-xl border border-border bg-card shadow-2xl ring-1 ring-black/5 p-4 text-sm text-foreground backdrop-blur-sm"
          >
            {content}
          </div>,
          document.body
        )}
    </>
  );
}

/* ---------- action-badge labels ---------- */

const ACTION_INFO: Record<string, { label: string; color: string; detail: string }> = {
  pending: {
    label: "AWAITING AUTH",
    color: "text-amber-400 bg-amber-400/10 ring-amber-400/30",
    detail:
      "A High-tier threat is waiting for your decision. You have 90 seconds to respond via the Auth Console below. YES generates a full forensic report and maintains containment. DENY holds defensive posture only. No response → auto-lockdown fires automatically.",
  },
  resolved: {
    label: "RESOLVED",
    color: "text-green-400 bg-green-400/10 ring-green-400/30",
    detail: "Event handled. Low or Medium-tier threat was contained autonomously (account locked, IP throttled). No human action required.",
  },
  "auto-locked": {
    label: "AUTO-LOCKED",
    color: "text-orange-400 bg-orange-400/10 ring-orange-400/30",
    detail:
      "Stasis state: admin did not respond within 90 seconds, so the system auto-executed containment — attacker IP permanently blocked, database snapshotted, bandwidth throttled to 1%. The threat is neutralised but services are frozen. Human team must manually restore. Forensic report was NOT generated (requires a human YES).",
  },
  forensics_generated: {
    label: "FORENSICS DONE",
    color: "text-blue-400 bg-blue-400/10 ring-blue-400/30",
    detail: "Admin approved. Full forensic report generated, attacker IP permanently blocked. Human team must restore services manually after reviewing the report.",
  },
  denied: {
    label: "DENIED",
    color: "text-muted-foreground bg-muted/40 ring-border",
    detail: "Admin denied the action. Defensive posture maintained — no escalation executed.",
  },
  blocked: {
    label: "BLOCKED",
    color: "text-red-300 bg-red-500/15 ring-red-400/30",
    detail: "IP was already in the blocklist and is still attempting connections. Block is active — no new challenge needed.",
  },
  admin_released: {
    label: "RELEASED",
    color: "text-green-300 bg-green-500/15 ring-green-400/30",
    detail: "Admin retroactively reviewed this auto-locked threat and released the IP block. Access restored.",
  },
};

function ActionBadge({ action }: { action: Action }) {
  const info = ACTION_INFO[action] ?? {
    label: action,
    color: "text-muted-foreground bg-muted/40 ring-border",
    detail: action,
  };
  return (
    <HoverCard
      content={
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <Info className="h-3.5 w-3.5 shrink-0 text-brand" />
            <span className="text-xs font-semibold uppercase tracking-wide">{info.label}</span>
          </div>
          <p className="text-[12px] leading-relaxed text-foreground/80">{info.detail}</p>
        </div>
      }
    >
      <span
        className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold ring-1 uppercase tracking-wide ${info.color}`}
      >
        {info.label}
      </span>
    </HoverCard>
  );
}

/* ---------- helpers ---------- */

function useCountUp(target: number, duration = 900) {
  const [val, setVal] = useState(target);
  const prev = useRef(target);
  useEffect(() => {
    const start = prev.current;
    const delta = target - start;
    if (delta === 0) return;
    const t0 = performance.now();
    let raf = 0;
    const step = (now: number) => {
      const p = Math.min(1, (now - t0) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      setVal(Math.round(start + delta * eased));
      if (p < 1) raf = requestAnimationFrame(step);
      else prev.current = target;
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, duration]);
  return val;
}

const tierTextClass: Record<Tier, string> = {
  High: "text-tier-high",
  Medium: "text-tier-medium",
  Low: "text-tier-low",
};
const tierDotClass: Record<Tier, string> = {
  High: "bg-tier-high",
  Medium: "bg-tier-medium",
  Low: "bg-tier-low",
};
const actionClass: Record<Action, string> = {
  pending:             "text-action-pending",
  resolved:            "text-action-resolved",
  "auto-locked":       "text-action-locked",
  forensics_generated: "text-action-forensics",
  denied:              "text-action-denied",
  blocked:             "text-red-400",
  admin_released:      "text-green-400",
};

/* ---------- shell ---------- */

function Sidebar() {
  return (
    <aside className="hidden lg:flex sticky top-0 h-screen w-[224px] shrink-0 flex-col border-r border-border bg-card px-4 py-6">
      <div className="mb-8 flex items-center gap-2 px-2">
        <div className="grid h-9 w-9 place-items-center rounded-xl bg-brand-soft text-brand">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <div className="text-base font-semibold tracking-tight">SentiHealth</div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">AI-Powered Threat Detection</div>
        </div>
      </div>
      <div className="mt-auto flex items-center gap-2 rounded-xl border border-border px-3 py-2.5">
        <span className="live-dot inline-block h-2 w-2 rounded-full bg-status-normal" />
        <div className="text-xs">
          <div className="font-medium">System Health</div>
          <div className="text-muted-foreground">All systems operational</div>
        </div>
      </div>
    </aside>
  );
}

function TopBar({
  lastUpdated,
  autoRefresh,
  setAutoRefresh,
}: {
  lastUpdated: string;
  autoRefresh: boolean;
  setAutoRefresh: (v: boolean) => void;
}) {
  return (
    <header className="flex flex-wrap items-center justify-between gap-4 border-b border-border bg-card/60 px-6 py-4 lg:px-10">
      <div className="flex items-center gap-2 lg:hidden">
        <div className="grid h-8 w-8 place-items-center rounded-lg bg-brand-soft text-brand">
          <ShieldCheck className="h-4 w-4" />
        </div>
        <span className="text-sm font-semibold">SentiHealth</span>
      </div>
      <div className="hidden lg:block text-sm text-muted-foreground">Welcome back · Security Operations</div>

      <div className="flex items-center gap-3 rounded-full border border-border bg-card px-3 py-1.5">
        <span className="live-dot inline-block h-2 w-2 rounded-full bg-status-normal" />
        <span className="text-xs text-muted-foreground">Auto-refresh every 5s</span>
        <button
          type="button"
          onClick={() => setAutoRefresh(!autoRefresh)}
          className={`relative h-5 w-9 rounded-full transition-colors ${autoRefresh ? "bg-status-normal" : "bg-muted"}`}
          aria-pressed={autoRefresh}
        >
          <span
            className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-all ${autoRefresh ? "left-[18px]" : "left-0.5"}`}
          />
        </button>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Clock className="h-4 w-4" />
          <span>Last updated:</span>
          <span className="font-mono-sec text-foreground">{lastUpdated}</span>
        </div>
        <button
          onClick={() => {
            sessionStorage.removeItem("auth_token");
            window.location.href = "/";
          }}
          className="inline-flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:bg-muted"
        >
          <LogOut className="h-3.5 w-3.5" /> Sign out
        </button>
      </div>
    </header>
  );
}

/* ---------- card primitive ---------- */

function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <section className={`card-soft fade-in-up p-6 ${className}`}>{children}</section>;
}

function CardTitle({ children, action }: { children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between">
      <h2 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{children}</h2>
      {action}
    </div>
  );
}

/* ---------- row 1 ---------- */

function StatusCard({ status }: { status: "NORMAL" | "THREAT" | "LOCKDOWN" }) {
  const cfg = {
    NORMAL: {
      label: "NORMAL",
      pill: "bg-emerald-50 text-status-normal ring-1 ring-emerald-100",
      icon: <ShieldCheck className="h-5 w-5" />,
      sub: "All systems nominal.",
      pulse: "",
    },
    THREAT: {
      label: "THREAT",
      pill: "bg-red-50 text-status-threat ring-1 ring-red-100",
      icon: <ShieldAlert className="h-5 w-5" />,
      sub: "System is operating under elevated threat conditions.",
      pulse: "pulse-threat",
    },
    LOCKDOWN: {
      label: "LOCKDOWN",
      pill: "bg-orange-50 text-status-lockdown ring-1 ring-orange-100",
      icon: <Lock className="h-5 w-5" />,
      sub: "Multiple simultaneous High-tier threats are active and pending human authorization.",
      pulse: "pulse-threat",
    },
  }[status];
  return (
    <Card>
      <CardTitle>1. System Status</CardTitle>
      <div className="flex flex-col items-center gap-4 py-2">
        <div
          className={`inline-flex items-center gap-3 rounded-2xl px-10 py-4 text-2xl font-bold tracking-widest ${cfg.pill} ${cfg.pulse}`}
        >
          {cfg.icon}
          {cfg.label}
        </div>
        <p className="max-w-[280px] text-center text-xs text-muted-foreground">{cfg.sub}</p>
      </div>
    </Card>
  );
}

function LedgerCard({ ledger, total }: { ledger: "INTACT" | "COMPROMISED"; total: number }) {
  const ok = ledger === "INTACT";
  const num = useCountUp(total);
  return (
    <Card>
      <CardTitle>2. Blockchain Audit Ledger</CardTitle>
      <div className="flex flex-col items-center gap-4 py-1">
        <div
          className={`inline-flex items-center gap-2 rounded-2xl px-8 py-3 text-base font-semibold ${
            ok
              ? "bg-emerald-50 text-status-normal ring-1 ring-emerald-100"
              : "bg-red-50 text-status-threat ring-1 ring-red-100"
          }`}
        >
          <Link2 className="h-4 w-4" />
          {ledger}
        </div>
        <div className="text-center">
          <div className="text-xs text-muted-foreground">Total Blocked IPs</div>
          <div className="flex items-baseline justify-center gap-2">
            <span className="font-mono-sec text-3xl font-bold tracking-tight">{num.toLocaleString()}</span>
          </div>
          <div className="mt-1 flex items-center justify-center gap-1 text-[11px] text-muted-foreground">
            <ShieldCheck className={`h-3 w-3 ${ok ? "text-status-normal" : "text-status-threat"}`} />
            {ok ? "Ledger intact — all blocks verified" : "Ledger integrity compromised"}
          </div>
        </div>
      </div>
    </Card>
  );
}

function MTTRCard({ since }: { since: number }) {
  const [, force] = useState(0);
  useEffect(() => {
    const id = setInterval(() => force((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <Card>
      <CardTitle>3. MTTR — Time Since Last High-Tier Alert</CardTitle>
      <div className="flex items-center justify-center gap-4 py-4">
        <Timer className="h-12 w-12 text-status-threat" />
        <div>
          <div className="font-mono-sec text-5xl font-bold tracking-tight text-status-threat">
            {formatMTTR(since)}
          </div>
          <div className="text-xs text-muted-foreground">hh:mm:ss</div>
        </div>
      </div>
    </Card>
  );
}

/* ---------- SHAP modal ---------- */

function ShapModal({ url, ip, onClose }: { url: string; ip: string; onClose: () => void }) {
  const token = typeof window !== "undefined" ? sessionStorage.getItem("auth_token") ?? "" : "";
  const [imgSrc, setImgSrc] = useState<string | null>(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    if (!url) return;
    fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
      .then((r) => {
        if (!r.ok) throw new Error("not found");
        return r.blob();
      })
      .then((b) => setImgSrc(URL.createObjectURL(b)))
      .catch(() => setErr(true));
    return () => { if (imgSrc) URL.revokeObjectURL(imgSrc); };
  }, [url]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-2xl rounded-2xl border border-border bg-card p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold">SHAP Feature Importance</h3>
            <p className="text-[11px] text-muted-foreground">
              ML model explanation · IP: <span className="font-mono-sec">{ip}</span>
            </p>
          </div>
          <button onClick={onClose} className="rounded-lg p-1.5 hover:bg-muted text-muted-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>
        {err ? (
          <p className="py-8 text-center text-sm text-muted-foreground">
            SHAP chart not yet generated for this event.
          </p>
        ) : imgSrc ? (
          <img src={imgSrc} alt="SHAP chart" className="w-full rounded-lg" />
        ) : (
          <div className="flex items-center justify-center py-12">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-brand border-t-transparent" />
          </div>
        )}
        <p className="mt-3 text-[11px] text-muted-foreground">
          Visible only to authenticated administrators — Custodian gate active.
        </p>
      </div>
    </div>
  );
}

/* ---------- row 2 ---------- */

function RecentTable({
  rows,
  onSelect,
}: {
  rows: ReturnType<typeof useSentinel>["recent"];
  onSelect?: (t: ReturnType<typeof useSentinel>["recent"][0]) => void;
}) {
  const [tier, setTier] = useState<"All" | Tier>("All");
  const [shapTarget, setShapTarget] = useState<{ url: string; ip: string } | null>(null);

  const filtered = useMemo(() => {
    const base = tier === "All" ? rows : rows.filter((r) => r.tier === tier);
    return [...base].sort((a, b) => {
      const pri = (r: typeof a) => (r.tier === "High" && r.action === "pending" ? 0 : 1);
      return pri(a) - pri(b);
    });
  }, [rows, tier]);

  return (
    <>
      {shapTarget && (
        <ShapModal url={shapTarget.url} ip={shapTarget.ip} onClose={() => setShapTarget(null)} />
      )}
      <Card className="lg:col-span-2">
        <CardTitle
          action={
            <div className="flex items-center gap-2">
              <select
                value={tier}
                onChange={(e) => setTier(e.target.value as "All" | Tier)}
                className="rounded-lg border border-border bg-card px-3 py-1.5 text-xs font-medium text-foreground focus:outline-none focus:ring-2 focus:ring-brand/30"
              >
                <option value="All">All Tiers</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
              <button type="button" className="grid h-8 w-8 place-items-center rounded-lg border border-border text-muted-foreground hover:bg-muted">
                <Filter className="h-3.5 w-3.5" />
              </button>
            </div>
          }
        >
          4. Recent Threat Detections (Last 10)
        </CardTitle>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                <th className="py-3 pr-4 font-medium">Timestamp</th>
                <th className="py-3 pr-4 font-medium">IP Address</th>
                <th className="py-3 pr-4 font-medium">Tier</th>
                <th className="py-3 pr-4 font-medium">Score</th>
                <th className="py-3 pr-4 font-medium">Action</th>
                <th className="py-3 pr-4 font-medium">Attack Nature</th>
                <th className="py-3 font-medium">SHAP</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => {
                const isUrgent = r.tier === "High" && r.action === "pending";
                return (
                  <tr
                    key={r.id}
                    onClick={() => onSelect?.(r)}
                    className={`border-b last:border-0 transition-colors cursor-pointer ${
                      isUrgent
                        ? "border-red-400/30 bg-red-500/10 hover:bg-red-500/15"
                        : "border-border/60 hover:bg-muted/40"
                    }`}
                    title="Click to view threat details"
                  >
                    <td className={`py-2.5 pr-4 font-mono-sec text-xs ${isUrgent ? "text-red-400" : "text-muted-foreground"}`}>{r.timestamp.slice(0,19).replace("T"," ")}</td>
                    <td className={`py-2.5 pr-4 font-mono-sec text-xs ${isUrgent ? "font-semibold text-red-300" : ""}`}>{r.ip}</td>
                    <td className={`py-2.5 pr-4 text-xs font-semibold ${isUrgent ? "text-red-400" : tierTextClass[r.tier]}`}>
                      {isUrgent && <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />}
                      {r.tier}
                    </td>
                    <td className={`py-2.5 pr-4 font-mono-sec text-xs ${isUrgent ? "font-bold text-red-400" : ""}`}>{r.score.toFixed(3)}</td>
                    <td className="py-2.5 pr-4">
                      <ActionBadge action={r.action} />
                    </td>
                    <td className="py-2.5 pr-4 max-w-[200px]">
                      <HoverCard
                        content={
                          <div className="space-y-2">
                            <div className="flex items-center gap-2 border-b border-border pb-2">
                              <span className={`text-xs font-semibold ${tierTextClass[r.tier]}`}>{r.tier}</span>
                              <span className="text-[10px] text-muted-foreground font-mono-sec">{r.ip}</span>
                              <span className="ml-auto font-mono-sec text-[10px] text-muted-foreground">score {r.score.toFixed(3)}</span>
                            </div>
                            <p className="text-[12px] leading-relaxed text-foreground/90">{r.reason || "No additional detail."}</p>
                          </div>
                        }
                      >
                        <span className={`text-[11px] leading-tight ${isUrgent ? "text-red-300" : "text-muted-foreground"}`}>
                          {r.reason ? r.reason.slice(0, 55) + (r.reason.length > 55 ? "…" : "") : "—"}
                        </span>
                      </HoverCard>
                    </td>
                    <td className="py-2.5">
                      {r.shap_url ? (
                        <button
                          onClick={() => setShapTarget({ url: r.shap_url, ip: r.ip })}
                          className="inline-flex items-center gap-1 rounded-lg border border-border px-2 py-1 text-[10px] font-semibold text-brand hover:bg-brand-soft transition-colors"
                          title="View SHAP feature importance"
                        >
                          <BarChart2 className="h-3 w-3" />
                          SHAP
                        </button>
                      ) : (
                        <span className="text-[10px] text-muted-foreground">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}

function TierBreakdown({ counts }: { counts: { High: number; Medium: number; Low: number; total: number } }) {
  const data = [
    { name: "High",   value: counts.High,   color: "var(--tier-high)" },
    { name: "Medium", value: counts.Medium, color: "var(--tier-medium)" },
    { name: "Low",    value: counts.Low,    color: "var(--tier-low)" },
  ];
  const total = useCountUp(counts.total);
  const pct = (n: number) => ((n / Math.max(1, counts.total)) * 100).toFixed(1);
  return (
    <Card>
      <CardTitle>5. Threat Tier Breakdown (This Session)</CardTitle>
      <div className="flex items-center gap-6">
        <div className="relative h-[170px] w-[170px] shrink-0">
          <ResponsiveContainer>
            <PieChart>
              <Pie data={data} dataKey="value" innerRadius={56} outerRadius={80} paddingAngle={2} stroke="none" animationDuration={700}>
                {data.map((d) => <Cell key={d.name} fill={d.color} />)}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
            <div>
              <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Total</div>
              <div className="font-mono-sec text-2xl font-bold">{total.toLocaleString()}</div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Threats</div>
            </div>
          </div>
        </div>
        <ul className="space-y-3 text-sm">
          {data.map((d) => (
            <li key={d.name} className="flex items-start gap-2">
              <span className="mt-1.5 h-2.5 w-2.5 rounded-full" style={{ background: d.color }} />
              <div>
                <div className={`font-semibold ${tierTextClass[d.name as Tier]}`}>{d.name}</div>
                <div className="font-mono-sec text-xs text-muted-foreground">
                  {(d.value as number).toLocaleString()} ({pct(d.value as number)}%)
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </Card>
  );
}

/* ---------- row 3 ---------- */


function MLMetrics({ rows }: { rows: MLMetricRow[] }) {
  if (!rows.length) {
    return (
      <Card className="lg:col-span-2">
        <CardTitle>6. Machine Learning Ensemble Metrics</CardTitle>
        <p className="py-8 text-center text-sm text-muted-foreground">Loading metrics…</p>
      </Card>
    );
  }
  return (
    <Card className="lg:col-span-2">
      <CardTitle>6. Machine Learning Ensemble Metrics</CardTitle>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-[11px] uppercase tracking-wider text-muted-foreground">
              <th className="py-3 pr-4 font-medium">Model</th>
              <th className="py-3 pr-4 font-medium">Accuracy</th>
              <th className="py-3 pr-4 font-medium">Precision</th>
              <th className="py-3 pr-4 font-medium">Recall</th>
              <th className="py-3 pr-4 font-medium">F1 Score</th>
              <th className="py-3 pr-4 font-medium">AUC-ROC</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((m) => (
              <tr
                key={m.model}
                className={
                  m.ensemble
                    ? "rounded-xl bg-brand-soft text-brand font-semibold"
                    : "border-b border-border/60 last:border-0"
                }
              >
                <td className={`py-2.5 pr-4 ${m.ensemble ? "rounded-l-lg pl-3" : ""}`}>{m.model}</td>
                <td className="py-2.5 pr-4 font-mono-sec">{m.accuracy.toFixed(2)}</td>
                <td className="py-2.5 pr-4 font-mono-sec">{m.precision.toFixed(2)}</td>
                <td className="py-2.5 pr-4 font-mono-sec">{m.recall.toFixed(2)}</td>
                <td className="py-2.5 pr-4 font-mono-sec">{m.f1.toFixed(2)}</td>
                <td className={`py-2.5 pr-4 font-mono-sec ${m.ensemble ? "rounded-r-lg" : ""}`}>{m.auc.toFixed(4)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function AucBars({ rows }: { rows: MLMetricRow[] }) {
  const data = rows.map((m) => ({
    name: m.model.split(" (")[0] === "ENSEMBLE" ? "ENSEMBLE (weighted)" : m.model,
    short: m.model,
    auc: m.auc,
    fill: m.ensemble ? "oklch(0.55 0.2 255)" : "oklch(0.7 0.13 250)",
  }));
  if (!data.length) return (
    <Card>
      <CardTitle>7. AUC-ROC Comparison</CardTitle>
      <p className="py-8 text-center text-sm text-muted-foreground">Loading…</p>
    </Card>
  );
  return (
    <Card>
      <CardTitle>7. AUC-ROC Comparison</CardTitle>
      <div className="h-[300px] w-full">
        <ResponsiveContainer>
          <BarChart data={data} layout="vertical" margin={{ top: 4, right: 44, left: 8, bottom: 18 }}>
            <XAxis
              type="number"
              domain={[0.9, 1.0]}
              tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
              stroke="var(--border)"
              label={{ value: "AUC-ROC", position: "insideBottom", offset: -8, fill: "var(--muted-foreground)", fontSize: 11 }}
            />
            <YAxis
              type="category"
              dataKey="short"
              tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
              stroke="var(--border)"
              width={150}
            />
            <Bar dataKey="auc" radius={[0, 8, 8, 0]} animationDuration={800}>
              {data.map((d, i) => <Cell key={i} fill={d.fill} />)}
              <LabelList
                dataKey="auc"
                position="right"
                formatter={(v: number) => v.toFixed(4)}
                style={{ fill: "var(--foreground)", fontSize: 11, fontFamily: "ui-monospace, monospace" }}
              />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}

/* ---------- row 4 — expandable detailed ---------- */

function DetailedAnalysis({
  feed,
  blocked,
}: {
  feed: ReturnType<typeof useSentinel>["feed"];
  blocked: ReturnType<typeof useSentinel>["blocked"];
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const filteredBlocked = blocked.filter((b) => b.ip.includes(search));
  return (
    <Card>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between gap-4 text-left"
      >
        <div className="flex items-center gap-4">
          <div className="grid h-11 w-11 place-items-center rounded-xl bg-brand-soft text-brand">
            <ChevronDown className={`h-5 w-5 transition-transform ${open ? "rotate-180" : ""}`} />
          </div>
          <div>
            <div className="text-sm font-semibold">View Detailed Threat Analysis</div>
            <div className="text-xs text-muted-foreground">
              Live feed, geolocation map, and blocked IPs list
            </div>
          </div>
        </div>
        <span className="inline-flex items-center gap-1 rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-muted-foreground">
          {open ? "Collapse" : "Expand"}
          {open ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
        </span>
      </button>

      {open && (
        <div className="mt-6 grid grid-cols-1 gap-6 fade-in">
          {/* live feed */}
          <div className="rounded-2xl border border-border p-5">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Live Threat Feed</h3>
              <span className="live-dot inline-block h-2 w-2 rounded-full bg-status-threat" />
            </div>
            <ul className="space-y-2 text-sm">
              {feed.map((f, i) => (
                <li key={f.id} className="fade-in-up flex items-center gap-3 rounded-xl border border-border bg-muted/30 px-3 py-2">
                  <span className={`h-2 w-2 rounded-full ${tierDotClass[f.tier]}`} />
                  <span className="font-mono-sec text-xs text-muted-foreground">{f.timestamp.slice(11, 19)}</span>
                  {i === 0 && <span className="rounded-full bg-red-100 px-2 py-0.5 text-[10px] font-semibold uppercase text-status-threat">New</span>}
                  <span className={`text-xs font-semibold ${tierTextClass[f.tier]}`}>{f.tier}</span>
                  <span className="font-mono-sec text-xs">{f.ip}</span>
                  <span className="ml-auto font-mono-sec text-xs text-muted-foreground">{f.score.toFixed(3)}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* blocked */}
          <div className="rounded-2xl border border-border p-5">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Blocked IPs</h3>
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search IP…"
                  className="w-48 rounded-lg border border-border bg-card py-1.5 pl-8 pr-3 text-xs focus:outline-none focus:ring-2 focus:ring-brand/30"
                />
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                    <th className="py-2 pr-4 font-medium">IP Address</th>
                    <th className="py-2 pr-4 font-medium">Blocked At (UTC)</th>
                    <th className="py-2 pr-4 font-medium">Tier</th>
                    <th className="py-2 pr-4 font-medium">Reason</th>
                    <th className="py-2 pr-4 font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredBlocked.map((b) => (
                    <tr key={b.id} className="border-b border-border/60 last:border-0 hover:bg-muted/40">
                      <td className="py-2.5 pr-4 font-mono-sec text-xs">{b.ip}</td>
                      <td className="py-2.5 pr-4 font-mono-sec text-xs text-muted-foreground whitespace-nowrap">{b.timestamp}</td>
                      <td className={`py-2.5 pr-4 text-xs font-semibold whitespace-nowrap ${tierTextClass[b.tier]}`}>{b.tier}</td>
                      <td className="py-2.5 pr-4 max-w-[220px]">
                        <HoverCard
                          content={
                            <div className="space-y-1.5">
                              <div className="flex items-center gap-2 border-b border-border pb-1.5">
                                <span className={`text-xs font-semibold ${tierTextClass[b.tier]}`}>{b.tier}</span>
                                <span className="font-mono-sec text-[10px] text-muted-foreground">{b.ip}</span>
                              </div>
                              <p className="text-[12px] leading-relaxed text-foreground/90">{b.reason || "No detail."}</p>
                            </div>
                          }
                        >
                          <span className="text-xs text-foreground/80">
                            {b.reason ? b.reason.slice(0, 50) + (b.reason.length > 50 ? "…" : "") : "—"}
                          </span>
                        </HoverCard>
                      </td>
                      <td className="py-2.5 pr-4 whitespace-nowrap">
                        <ActionBadge action={b.action} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}

/* ---------- bottom toolbar ---------- */

function BottomToolbar({
  autoRefresh,
  setAutoRefresh,
  filter,
  setFilter,
}: {
  autoRefresh: boolean;
  setAutoRefresh: (v: boolean) => void;
  filter: "All" | Tier;
  setFilter: (v: "All" | Tier) => void;
}) {
  const tabs: ("All" | Tier)[] = ["All", "High", "Medium", "Low"];
  return (
    <div className="sticky bottom-4 mx-auto mt-8 flex w-fit items-center gap-3 rounded-full border border-border bg-card/90 px-3 py-2 shadow-lg backdrop-blur">
      <div className="flex items-center gap-2 px-2">
        <span className="text-xs text-muted-foreground">Auto-refresh</span>
        <button
          type="button"
          onClick={() => setAutoRefresh(!autoRefresh)}
          className={`relative h-5 w-9 rounded-full transition-colors ${autoRefresh ? "bg-status-normal" : "bg-muted"}`}
        >
          <span
            className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-all ${autoRefresh ? "left-[18px]" : "left-0.5"}`}
          />
        </button>
      </div>
      <span className="h-5 w-px bg-border" />
      <div className="flex items-center gap-1">
        {tabs.map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setFilter(t)}
            className={`rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
              filter === t
                ? "bg-brand text-primary-foreground"
                : "text-muted-foreground hover:bg-muted hover:text-foreground"
            }`}
          >
            {t}
          </button>
        ))}
      </div>
    </div>
  );
}

/* ---------- SSHA Admin Panels (admin-only) ---------- */

interface PendingChallenge {
  incident_id: string;
  timestamp: string;
  prompt_summary: string;
  resolved: boolean;
  timeout_sec?: number;
  metadata?: { ip?: string; tier?: string; score?: number; reason?: string; shap_file?: string };
}

interface StasisChallenge {
  incident_id: string;
  timestamp: string;
  prompt_summary: string;
  timeout_sec: number;
  auto_locked_at: string;
  ip?: string;
  tier?: string;
  score?: number | null;
  reason?: string;
  is_currently_blocked?: boolean;
  metadata?: { ip?: string; tier?: string; score?: number; reason?: string; shap_file?: string };
}

interface AdminUser {
  username: string;
  role: string;
  status: string;
  requested_at: string;
}

/** Live countdown showing seconds remaining before auto-lockdown. */
function Countdown({ issuedAt, timeoutSec = 90 }: { issuedAt: string; timeoutSec?: number }) {
  const [remaining, setRemaining] = useState<number | null>(null);
  useEffect(() => {
    const deadline = new Date(issuedAt).getTime() + timeoutSec * 1000;
    const tick = () => {
      const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
      setRemaining(left);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [issuedAt, timeoutSec]);

  if (remaining === null) return null;
  const pct = Math.round((remaining / timeoutSec) * 100);
  const color = remaining > 45 ? "text-green-400" : remaining > 20 ? "text-amber-400" : "text-red-400";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-24 overflow-hidden rounded-full bg-muted">
        <div
          className={`h-full rounded-full transition-all ${remaining > 45 ? "bg-green-400" : remaining > 20 ? "bg-amber-400" : "bg-red-400"}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className={`font-mono-sec text-[11px] font-semibold ${color}`}>
        {remaining}s
      </span>
    </div>
  );
}

interface AlertLogEntry {
  incident_id: string;
  timestamp: string;
  type: "alert" | "authorization_challenge" | "authorization_resolution";
  summary?: string;
  decision?: string;
  status?: string;
  timeout_sec?: number;
}

function AdminAlerts() {
  const [challenges, setChallenges] = useState<PendingChallenge[]>([]);
  const [recentAlerts, setRecentAlerts] = useState<AlertLogEntry[]>([]);
  const [deciding, setDeciding] = useState<Record<string, boolean>>({});

  const fetchAlerts = async () => {
    try {
      const res = await fetch("/api/alerts", { headers: authHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      setChallenges(data.pending_challenges ?? []);
      setRecentAlerts(data.recent_alerts ?? []);
    } catch {}
  };

  useEffect(() => {
    fetchAlerts();
    const id = setInterval(fetchAlerts, 4000);
    return () => clearInterval(id);
  }, []);

  const respond = async (incidentId: string, decision: "YES" | "DENY") => {
    setDeciding((d) => ({ ...d, [incidentId]: true }));
    try {
      const res = await fetch(`/api/alerts/${incidentId}/respond`, {
        method: "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ decision }),
      });
      const data = await res.json();
      if (data.success) {
        setChallenges((c) => c.filter((x) => x.incident_id !== incidentId));
        toast.success(decision === "YES" ? "Approved — forensic report generating." : "Denied — defensive posture held.");
      }
    } finally {
      setDeciding((d) => ({ ...d, [incidentId]: false }));
    }
  };

  return (
    <Card>
      <CardTitle>
        8. SSHA — Threat Authorization Console
        {challenges.length > 0 && (
          <span className="ml-2 inline-flex items-center gap-1 rounded-full bg-red-500/15 px-2 py-0.5 text-[10px] font-bold text-red-400 ring-1 ring-red-400/30 animate-pulse">
            {challenges.length} PENDING
          </span>
        )}
        <span className="ml-2 text-[10px] font-normal text-muted-foreground">
          (Admin only · self-hosted · zero-cloud)
        </span>
      </CardTitle>

      {/* legend */}
      <div className="mb-4 grid grid-cols-1 gap-2 rounded-xl border border-border bg-muted/20 p-3 text-[11px] sm:grid-cols-2">
        <div className="flex gap-2">
          <span className="mt-0.5 inline-block h-2 w-2 shrink-0 rounded-full bg-green-400" />
          <span><strong className="text-foreground">YES — Approve</strong><span className="text-muted-foreground"> — authorises full forensic report generation + maintains IP block &amp; DB snapshot.</span></span>
        </div>
        <div className="flex gap-2">
          <span className="mt-0.5 inline-block h-2 w-2 shrink-0 rounded-full bg-red-400" />
          <span><strong className="text-foreground">NO — Deny</strong><span className="text-muted-foreground"> — holds defensive posture, no further escalation. IP remains monitored.</span></span>
        </div>
        <div className="flex gap-2 sm:col-span-2">
          <span className="mt-0.5 inline-block h-2 w-2 shrink-0 rounded-full bg-orange-400" />
          <span><strong className="text-foreground">No response in 90s → Auto-lockdown</strong><span className="text-muted-foreground"> — system autonomously blocks IP, snapshots DB, throttles bandwidth to 1%. Threat is in stasis — fully contained but human team must restore services manually.</span></span>
        </div>
      </div>

      {challenges.length === 0 ? (
        <div className="flex items-center gap-3 rounded-xl border border-border bg-muted/30 px-4 py-3 text-sm text-muted-foreground">
          <ShieldCheck className="h-4 w-4 text-status-normal" />
          No pending authorization challenges. All High-tier decisions are up to date.
        </div>
      ) : (
        <ul className="space-y-4">
          {challenges.map((ch) => (
            <li
              key={ch.incident_id}
              className="rounded-xl border-2 border-red-400/50 bg-red-500/10 p-4 shadow-md"
            >
              {/* header row */}
              <div className="mb-3 flex flex-wrap items-center gap-3">
                <span className="inline-block h-2.5 w-2.5 rounded-full bg-red-400 animate-pulse" />
                <span className="text-sm font-bold text-red-300 uppercase tracking-wide">
                  High-Tier Threat — Authorization Required
                </span>
                <span className="font-mono-sec text-[10px] text-muted-foreground ml-auto">
                  ID: {ch.incident_id.slice(0, 12)}
                </span>
              </div>

              {/* full prompt — no truncation */}
              <p className="mb-3 rounded-lg border border-red-400/20 bg-red-950/30 px-3 py-2 text-sm leading-relaxed text-foreground/90">
                {ch.prompt_summary}
              </p>

              {/* timestamp + countdown */}
              <div className="mb-4 flex flex-wrap items-center gap-4 text-[11px] text-muted-foreground">
                <span>Detected: {ch.timestamp.slice(0, 19).replace("T", " ")} UTC</span>
                <Countdown issuedAt={ch.timestamp} timeoutSec={ch.timeout_sec ?? 90} />
                <span className="text-amber-400 font-medium">
                  If timer expires → auto-lockdown fires
                </span>
              </div>

              {/* YES / NO buttons — large and clear */}
              <div className="flex flex-wrap gap-3">
                <button
                  onClick={() => respond(ch.incident_id, "YES")}
                  disabled={deciding[ch.incident_id]}
                  className="flex-1 rounded-xl bg-green-600 px-6 py-2.5 text-sm font-bold text-white shadow hover:bg-green-500 disabled:opacity-50 transition-colors"
                >
                  ✓ YES — Approve &amp; Generate Forensic Report
                </button>
                <button
                  onClick={() => respond(ch.incident_id, "DENY")}
                  disabled={deciding[ch.incident_id]}
                  className="flex-1 rounded-xl bg-red-700 px-6 py-2.5 text-sm font-bold text-white shadow hover:bg-red-600 disabled:opacity-50 transition-colors"
                >
                  ✗ NO — Deny Action
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-3 text-[11px] text-muted-foreground">
        Authorization decisions are recorded in the SHA-256 audit chain with admin identity and timestamp.
        Real IP addresses visible here only because you are an authenticated administrator (Custodian gate).
      </p>

      {/* ── Alert log ── */}
      {recentAlerts.length > 0 && (
        <div className="mt-6">
          <h3 className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            Authorization &amp; Alert Log
          </h3>
          <ul className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
            {recentAlerts.map((entry) => {
              const isChallenge   = entry.type === "authorization_challenge";
              const isResolution  = entry.type === "authorization_resolution";
              const decision      = entry.decision?.toUpperCase();
              const approved      = decision === "YES";
              const timedOut      = decision === "TIMEOUT";
              const denied        = decision === "DENY" || decision === "IGNORE";

              const dot = isChallenge
                ? "bg-red-400 animate-pulse"
                : isResolution
                  ? approved ? "bg-green-400" : timedOut ? "bg-amber-400" : "bg-red-400"
                  : "bg-brand";

              const label = isChallenge
                ? "🔐 AUTH REQUIRED"
                : isResolution
                  ? approved ? "✅ APPROVED" : timedOut ? "⏱ TIMED OUT → AUTO-LOCK" : "✗ DENIED"
                  : "📋 ALERT";

              const labelColor = isChallenge
                ? "text-red-400"
                : isResolution
                  ? approved ? "text-green-400" : timedOut ? "text-amber-400" : "text-red-400"
                  : "text-brand";

              return (
                <li
                  key={entry.incident_id + entry.timestamp}
                  className="flex items-start gap-3 rounded-xl border border-border bg-muted/20 px-3 py-2"
                >
                  <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${dot}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[10px] font-bold uppercase tracking-wide ${labelColor}`}>
                        {label}
                      </span>
                      <span className="font-mono-sec text-[10px] text-muted-foreground">
                        {entry.timestamp.slice(0, 19).replace("T", " ")} UTC
                      </span>
                      <span className="ml-auto font-mono-sec text-[10px] text-muted-foreground">
                        {entry.incident_id.slice(0, 10)}
                      </span>
                    </div>
                    {entry.summary && (
                      <p className="mt-0.5 text-[11px] leading-snug text-foreground/75 whitespace-pre-wrap break-words">
                        {entry.summary}
                      </p>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </Card>
  );
}

/* ---------- stasis panel (post-timeout review queue) ---------- */

function StasisPanel() {
  const [items, setItems] = useState<StasisChallenge[]>([]);
  const [acting, setActing] = useState<Record<string, boolean>>({});

  const fetchStasis = async () => {
    try {
      const res = await fetch("/api/alerts/stasis", { headers: authHeaders() });
      if (!res.ok) return;
      const d = await res.json();
      setItems(d.stasis ?? []);
    } catch {}
  };

  useEffect(() => {
    fetchStasis();
    const id = setInterval(fetchStasis, 8000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const token = sessionStorage.getItem("auth_token");
    if (!token) return;
    const es = new EventSource(`/api/stream?token=${encodeURIComponent(token)}`);
    es.addEventListener("stasis_resolved", () => fetchStasis());
    return () => es.close();
  }, []);

  const act = async (incidentId: string, action: "release" | "confirm") => {
    setActing((a) => ({ ...a, [incidentId]: true }));
    try {
      const res = await fetch(`/api/alerts/${incidentId}/retroactive`, {
        method: "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      const d = await res.json();
      if (d.success) {
        setItems((prev) => prev.filter((x) => x.incident_id !== incidentId));
        toast.success(
          action === "release"
            ? `✓ Block released for ${d.ip || "IP"}. Access restored and forensic report generated.`
            : `✓ Auto-lock confirmed for ${d.ip || "IP"}. Marked as reviewed.`,
        );
      } else {
        toast.error(d.message ?? "Action failed.");
      }
    } finally {
      setActing((a) => ({ ...a, [incidentId]: false }));
    }
  };

  return (
    <Card>
      <CardTitle>
        9. Stasis Review Queue — Post-Timeout Auto-Locked Threats
        {items.length > 0 && (
          <span className="ml-2 inline-flex items-center gap-1 rounded-full bg-red-500/15 px-2 py-0.5 text-[10px] font-bold text-red-400 ring-1 ring-red-400/30">
            {items.length} PENDING ADMIN DECISION
          </span>
        )}
        <span className="ml-2 text-[10px] font-normal text-muted-foreground">(Admin only)</span>
      </CardTitle>

      <div className="mb-3 rounded-xl border border-amber-400/20 bg-amber-500/5 p-3 text-[11px] text-muted-foreground leading-relaxed">
        These High-tier threats expired before you responded — the system auto-blocked the IPs immediately.
        <strong className="text-foreground"> You must now decide for each one:</strong> restore access if it was a false positive,
        or confirm the block is correct.
      </div>

      {items.length === 0 ? (
        <div className="flex items-center gap-3 rounded-xl border border-border bg-muted/30 px-4 py-3 text-sm text-muted-foreground">
          <ShieldCheck className="h-4 w-4 text-status-normal" />
          No stasis threats — all auto-locked events have been reviewed.
        </div>
      ) : (
        <ul className="space-y-4">
          {items.map((item) => {
            const isLoading = acting[item.incident_id];
            const ip        = item.ip || item.metadata?.ip || "";
            const tier      = item.tier || item.metadata?.tier || "High";
            const score     = item.score ?? item.metadata?.score;
            const reason    = item.reason || item.metadata?.reason || item.prompt_summary || "";
            const blocked   = item.is_currently_blocked ?? true;

            return (
              <li
                key={item.incident_id}
                className="rounded-xl border border-red-400/30 bg-red-500/5 p-4"
              >
                {/* ── header row ── */}
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <span className="inline-block h-2.5 w-2.5 rounded-full bg-red-400 animate-pulse" />

                  {ip ? (
                    <span className="font-mono text-[13px] font-bold text-foreground">{ip}</span>
                  ) : (
                    <span className="text-[12px] italic text-muted-foreground">IP unavailable</span>
                  )}

                  {blocked ? (
                    <span className="inline-flex items-center gap-1 rounded-full bg-red-500/20 px-2 py-0.5 text-[10px] font-bold text-red-400 ring-1 ring-red-400/30">
                      <Lock className="h-2.5 w-2.5" /> STILL BLOCKED
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 rounded-full bg-green-500/20 px-2 py-0.5 text-[10px] font-bold text-green-400">
                      UNBLOCKED
                    </span>
                  )}

                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    tier === "High" ? "bg-red-500/20 text-red-400" : "bg-amber-500/20 text-amber-400"
                  }`}>
                    {tier}
                  </span>

                  {score != null && (
                    <span className="font-mono text-[10px] text-muted-foreground">
                      score {Number(score).toFixed(3)}
                    </span>
                  )}

                  <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                    {item.incident_id.slice(0, 12)}
                  </span>
                </div>

                {/* ── reason / summary ── */}
                {reason && (
                  <p className="mb-3 text-[12px] text-foreground/80 leading-relaxed">{reason}</p>
                )}

                {/* ── timestamps ── */}
                <div className="mb-4 flex flex-wrap gap-4 text-[11px] text-muted-foreground">
                  <span>Detected: {item.timestamp.slice(0, 19).replace("T", " ")} UTC</span>
                  {item.auto_locked_at && (
                    <span className="text-red-400">
                      Auto-locked: {item.auto_locked_at.slice(0, 19).replace("T", " ")} UTC
                    </span>
                  )}
                </div>

                {/* ── action buttons ── */}
                <div className="grid grid-cols-2 gap-3">
                  <button
                    onClick={() => act(item.incident_id, "release")}
                    disabled={isLoading}
                    className="rounded-xl bg-green-600 px-4 py-2.5 text-xs font-bold text-white hover:bg-green-500 disabled:opacity-50 transition-colors"
                  >
                    ✓ Release Block
                    <span className="block text-[10px] font-normal opacity-80 mt-0.5">
                      Unblock IP · restore access · generate forensics
                    </span>
                  </button>
                  <button
                    onClick={() => act(item.incident_id, "confirm")}
                    disabled={isLoading}
                    className="rounded-xl border border-amber-400/40 bg-amber-500/10 px-4 py-2.5 text-xs font-bold text-amber-300 hover:bg-amber-500/20 disabled:opacity-50 transition-colors"
                  >
                    ✗ Confirm Block
                    <span className="block text-[10px] font-normal opacity-80 mt-0.5">
                      Keep IP blocked · mark as reviewed
                    </span>
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

/* ---------- threat detail drawer ---------- */

function ThreatDetailDrawer({
  threat,
  onClose,
}: {
  threat: ReturnType<typeof useSentinel>["recent"][0];
  onClose: () => void;
}) {
  const tierColors: Record<string, string> = {
    High:   "text-red-400 bg-red-500/10 border-red-400/40",
    Medium: "text-amber-400 bg-amber-500/10 border-amber-400/40",
    Low:    "text-green-400 bg-green-500/10 border-green-400/40",
  };
  const actionLabel: Record<string, string> = {
    pending:             "🔴 Pending Admin Decision",
    "auto-locked":       "🔒 Auto-Locked (timeout)",
    forensics_generated: "📋 Forensic Report Generated",
    resolved:            "✅ Resolved",
    denied:              "🚫 Denied",
    blocked:             "🚷 IP Already Blocked (repeat attempt)",
    admin_released:      "🔓 Block Released by Admin",
  };

  const scorePct = Math.min(100, Math.round(threat.score * 100));
  const scoreColor = threat.tier === "High" ? "bg-red-500" : threat.tier === "Medium" ? "bg-amber-500" : "bg-green-500";

  return createPortal(
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* backdrop */}
      <div className="absolute inset-0 bg-black/50 backdrop-blur-[2px]" onClick={onClose} />

      {/* panel */}
      <div className="relative z-10 flex h-full w-full max-w-lg flex-col overflow-y-auto bg-card shadow-2xl ring-1 ring-border">
        {/* header */}
        <div className={`flex items-center justify-between border-b border-border p-5 ${threat.tier === "High" ? "bg-red-500/10" : threat.tier === "Medium" ? "bg-amber-500/10" : "bg-green-500/10"}`}>
          <div className="flex items-center gap-3">
            <div className={`rounded-xl border px-3 py-1.5 text-sm font-bold ${tierColors[threat.tier]}`}>
              {threat.tier === "High" ? "🔴" : threat.tier === "Medium" ? "🟡" : "🟢"} {threat.tier.toUpperCase()} TIER THREAT
            </div>
          </div>
          <button onClick={onClose} className="rounded-lg p-1.5 text-muted-foreground hover:bg-muted/50 transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 space-y-5 p-5">
          {/* IP + geo */}
          <div>
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Source IP</div>
            <div className="flex items-center gap-3">
              <span className="font-mono-sec text-xl font-bold tracking-tight">{threat.ip}</span>
              <span className="rounded-lg border border-border bg-muted/30 px-2 py-1 text-[11px] text-muted-foreground">
                {threat.city}, {threat.country}
              </span>
            </div>
          </div>

          {/* score gauge */}
          <div>
            <div className="mb-2 flex items-center justify-between">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">ML Risk Score</div>
              <span className={`font-mono-sec text-lg font-bold ${threat.tier === "High" ? "text-red-400" : threat.tier === "Medium" ? "text-amber-400" : "text-green-400"}`}>
                {threat.score.toFixed(4)}
              </span>
            </div>
            <div className="h-3 w-full overflow-hidden rounded-full bg-muted">
              <div
                className={`h-full rounded-full transition-all ${scoreColor}`}
                style={{ width: `${scorePct}%` }}
              />
            </div>
            <div className="mt-1 flex justify-between text-[10px] text-muted-foreground">
              <span>0.0 — Safe</span>
              <span>1.0 — Critical</span>
            </div>
          </div>

          {/* reason */}
          <div>
            <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Attack Nature (ML Explanation)</div>
            <p className="rounded-xl border border-border bg-muted/30 px-4 py-3 text-sm leading-relaxed">
              {threat.reason || "No explanation available."}
            </p>
          </div>

          {/* action + timestamp */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Action Taken</div>
              <div className="text-sm font-medium">{actionLabel[threat.action] ?? threat.action}</div>
            </div>
            <div>
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Detected At (UTC)</div>
              <div className="font-mono-sec text-sm">{threat.timestamp.slice(0, 19).replace("T", " ")}</div>
            </div>
          </div>

          {/* SHAP chart */}
          {threat.shap_url && (
            <div>
              <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                SHAP Feature Importance
              </div>
              <div className="overflow-hidden rounded-xl border border-border bg-muted/20">
                <img
                  src={threat.shap_url}
                  alt={`SHAP explanation for ${threat.ip}`}
                  className="w-full object-contain"
                  style={{ maxHeight: "280px" }}
                  onError={(e) => {
                    (e.target as HTMLImageElement).style.display = "none";
                  }}
                />
              </div>
              <div className="mt-1.5 text-[11px] text-muted-foreground">
                Shows which features pushed the model score up (red) or down (blue).
                Authenticated endpoint — only visible to admins.
              </div>
            </div>
          )}

          {/* forensic report */}
          {threat.action === "forensics_generated" && (
            <div className="rounded-xl border border-brand/30 bg-brand/5 p-4">
              <div className="flex items-center gap-2 text-sm font-semibold text-brand">
                <Info className="h-4 w-4" />
                Forensic Report Generated
              </div>
              <p className="mt-1 text-[12px] text-muted-foreground">
                A full forensic report JSON has been written to <code className="font-mono-sec">logs/forensic_report_*.json</code> and
                added to the retraining queue for model improvement.
              </p>
            </div>
          )}

          {threat.action === "auto-locked" && (
            <div className="rounded-xl border border-amber-400/30 bg-amber-500/8 p-4">
              <div className="flex items-center gap-2 text-sm font-semibold text-amber-400">
                <Lock className="h-4 w-4" />
                Auto-Lockdown Active
              </div>
              <p className="mt-1 text-[12px] text-muted-foreground">
                Admin response timed out. System auto-blocked this IP, snapshotted the DB, and throttled bandwidth to 1%.
                Check the <strong>Stasis Review Queue</strong> (section 9 below) to retroactively generate forensics.
              </p>
            </div>
          )}
        </div>

        <div className="border-t border-border p-4">
          <button
            onClick={onClose}
            className="w-full rounded-xl border border-border py-2.5 text-sm font-medium text-muted-foreground hover:bg-muted/50 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}

function PendingUsers() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [acting, setActing] = useState<Record<string, boolean>>({});

  const fetchUsers = async () => {
    try {
      const res = await fetch("/api/admin/users", { headers: authHeaders() });
      if (!res.ok) return;
      const data: AdminUser[] = await res.json();
      setUsers(data.filter((u) => u.status === "pending"));
    } catch {}
  };

  useEffect(() => {
    fetchUsers();
    const id = setInterval(fetchUsers, 8000);
    return () => clearInterval(id);
  }, []);

  const act = async (username: string, action: "approve" | "reject") => {
    setActing((a) => ({ ...a, [username]: true }));
    try {
      await fetch(`/api/admin/users/${username}/${action}`, {
        method: "POST",
        headers: authHeaders(),
      });
      setUsers((u) => u.filter((x) => x.username !== username));
    } finally {
      setActing((a) => ({ ...a, [username]: false }));
    }
  };

  if (users.length === 0) return null;

  return (
    <Card>
      <CardTitle>9. Pending Registration Approvals</CardTitle>
      <ul className="space-y-2">
        {users.map((u) => (
          <li
            key={u.username}
            className="flex items-center justify-between rounded-xl border border-border bg-muted/30 px-4 py-2.5"
          >
            <div>
              <span className="text-sm font-semibold">{u.username}</span>
              <span className="ml-3 text-[11px] text-muted-foreground">{u.requested_at.slice(0, 16).replace("T", " ")} UTC</span>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => act(u.username, "approve")}
                disabled={acting[u.username]}
                className="rounded-lg bg-status-normal px-3 py-1 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
              >
                Approve
              </button>
              <button
                onClick={() => act(u.username, "reject")}
                disabled={acting[u.username]}
                className="rounded-lg bg-status-threat px-3 py-1 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
              >
                Reject
              </button>
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}

/* ---------- main ---------- */

export function Dashboard() {
  const [autoRefresh, setAutoRefresh] = useState(true);
  const snap = useSentinel(autoRefresh);
  const mlRows = useMLMetrics();
  const [filter, setFilter] = useState<"All" | Tier>("All");
  const [authorized, setAuthorized] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState<ReturnType<typeof useSentinel>["recent"][0] | null>(null);

  // Real-time SSE — shows a toast the moment a High-tier challenge arrives
  useHighTierSSE();

  useEffect(() => {
    const token = sessionStorage.getItem("auth_token");
    if (!token) {
      window.location.href = "/";
    } else {
      setAuthorized(true);
      setIsAdmin(sessionStorage.getItem("is_admin") === "1");
    }
  }, []);

  const filteredRecent = useMemo(
    () => (filter === "All" ? snap.recent : snap.recent.filter((r) => r.tier === filter)),
    [snap.recent, filter]
  );

  if (!authorized) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="text-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-brand border-t-transparent mx-auto"></div>
          <p className="mt-4 text-sm text-muted-foreground">Verifying secure authorization...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-background">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar lastUpdated={snap.lastUpdated} autoRefresh={autoRefresh} setAutoRefresh={setAutoRefresh} />
        <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 sm:px-6 lg:px-10">
          {/* row 1 */}
          <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-3">
            <StatusCard status={snap.status} />
            <LedgerCard ledger={snap.ledger} total={snap.totalBlockedIPs} />
            <MTTRCard since={snap.lastHighAt} />
          </div>

          {/* row 2 */}
          <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
            <RecentTable rows={filteredRecent} onSelect={setSelectedThreat} />
            <TierBreakdown counts={snap.tierCounts} />
          </div>

          {/* row 3 */}
          <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
            <MLMetrics rows={mlRows} />
            <AucBars rows={mlRows} />
          </div>


          {/* row 4 */}
          <div className="mt-6">
            <DetailedAnalysis feed={snap.feed} blocked={snap.blocked} />
          </div>

          {/* row 5 — admin-only SSHA panels */}
          {isAdmin && (
            <div id="ssha-auth-console" className="mt-6 space-y-6">
              <AdminAlerts />
              <StasisPanel />
              <PendingUsers />
            </div>
          )}

          <BottomToolbar
            autoRefresh={autoRefresh}
            setAutoRefresh={setAutoRefresh}
            filter={filter}
            setFilter={setFilter}
          />

          <footer className="mt-8 flex items-center justify-between text-[11px] text-muted-foreground">
            <span>SentiHealth · AI-Powered Healthcare Cybersecurity Monitoring</span>
            <span className="font-mono-sec">v2.4.1</span>
          </footer>
        </main>
      </div>

      {/* Threat detail drawer */}
      {selectedThreat && (
        <ThreatDetailDrawer
          threat={selectedThreat}
          onClose={() => setSelectedThreat(null)}
        />
      )}

      {/* Toast container — shows real-time High-tier alerts via SSE */}
      <Toaster richColors position="top-right" closeButton />
    </div>
  );
}
