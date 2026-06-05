import { useEffect, useMemo, useRef, useState } from "react";
import {
  ShieldCheck, ShieldAlert, Timer, Lock, ChevronDown, ChevronUp,
  Clock, Filter, Link2, Search, LogOut,
} from "lucide-react";
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, LabelList,
} from "recharts";
import { useSentinel, useMLMetrics, formatMTTR, type Tier, type Action, type MLMetricRow } from "@/lib/sentinel-data";
import { Link } from "@tanstack/react-router";

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
  pending: "text-action-pending",
  resolved: "text-action-resolved",
  "auto-locked": "text-action-locked",
  forensics_generated: "text-action-forensics",
  denied: "text-action-denied",
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
            <span className="text-xs font-medium text-status-normal">↑ 12 (5.3%)</span>
          </div>
          <div className="mt-1 flex items-center justify-center gap-1 text-[11px] text-muted-foreground">
            <ShieldCheck className="h-3 w-3 text-status-normal" /> Ledger validated · 3s ago
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

/* ---------- row 2 ---------- */

function RecentTable({ rows }: { rows: ReturnType<typeof useSentinel>["recent"] }) {
  const [tier, setTier] = useState<"All" | Tier>("All");
  const filtered = useMemo(() => {
    const base = tier === "All" ? rows : rows.filter((r) => r.tier === tier);
    // Pending High-tier threats always float to the top
    return [...base].sort((a, b) => {
      const pri = (r: typeof a) => (r.tier === "High" && r.action === "pending" ? 0 : 1);
      return pri(a) - pri(b);
    });
  }, [rows, tier]);
  return (
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
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => {
              const isUrgent = r.tier === "High" && r.action === "pending";
              return (
                <tr
                  key={r.id}
                  className={`border-b last:border-0 transition-colors ${
                    isUrgent
                      ? "border-red-400/30 bg-red-500/10 hover:bg-red-500/15"
                      : "border-border/60 hover:bg-muted/40"
                  }`}
                >
                  <td className={`py-2.5 pr-4 font-mono-sec text-xs ${ isUrgent ? "text-red-400" : "text-muted-foreground" }`}>{r.timestamp}</td>
                  <td className={`py-2.5 pr-4 font-mono-sec text-xs ${ isUrgent ? "font-semibold text-red-300" : "" }`}>{r.ip}</td>
                  <td className={`py-2.5 pr-4 text-xs font-semibold ${ isUrgent ? "text-red-400" : tierTextClass[r.tier] }`}>
                    {isUrgent && <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />}
                    {r.tier}
                  </td>
                  <td className={`py-2.5 pr-4 font-mono-sec text-xs ${ isUrgent ? "font-bold text-red-400" : "" }`}>{r.score.toFixed(3)}</td>
                  <td className={`py-2.5 pr-4 font-mono-sec text-xs ${ isUrgent ? "font-bold text-red-400 uppercase tracking-wide" : actionClass[r.action] }`}>{r.action}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
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
                      <td className="py-2.5 pr-4 font-mono-sec text-xs text-muted-foreground">{b.timestamp}</td>
                      <td className={`py-2.5 pr-4 text-xs font-semibold ${tierTextClass[b.tier]}`}>{b.tier}</td>
                      <td className="py-2.5 pr-4 text-xs">{b.reason}</td>
                      <td className={`py-2.5 pr-4 font-mono-sec text-xs ${actionClass[b.action]}`}>{b.action}</td>
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

/* ---------- main ---------- */

export function Dashboard() {
  const snap = useSentinel();
  const mlRows = useMLMetrics();
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [filter, setFilter] = useState<"All" | Tier>("All");
  const [authorized, setAuthorized] = useState(false);

  useEffect(() => {
    const token = sessionStorage.getItem("auth_token");
    if (!token) {
      window.location.href = "/";
    } else {
      setAuthorized(true);
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
            <RecentTable rows={filteredRecent} />
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
    </div>
  );
}
