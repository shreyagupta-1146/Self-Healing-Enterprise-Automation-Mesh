import { useCallback, useEffect, useRef, useState } from "react";

export type Tier = "High" | "Medium" | "Low";
export type Action = "pending" | "resolved" | "auto-locked" | "forensics_generated" | "denied" | "blocked" | "admin_released";
export type SystemStatus = "NORMAL" | "THREAT" | "LOCKDOWN";

export interface ThreatEvent {
  id: string;
  timestamp: string;
  ip: string;
  tier: Tier;
  score: number;
  action: Action;
  reason: string;       // plain_english_explanation from ML model
  shap_url: string;     // /api/shap/<filename> — served behind auth gate
  lat: number;
  lng: number;
  country: string;
  city: string;
}

export interface MLMetricRow {
  model: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  auc: number;
  ensemble?: boolean;
}

export interface SentinelSnapshot {
  status: SystemStatus;
  ledger: "INTACT" | "COMPROMISED";
  totalBlockedIPs: number;
  recent: ThreatEvent[];
  feed: ThreatEvent[];
  blocked: ThreatEvent[];
  tierCounts: { High: number; Medium: number; Low: number; total: number };
  riskSeries: { t: string; score: number }[];
  lastHighAt: number;
  totalIPsPlotted: number;
  lastUpdated: string;
}

// IP prefix → approximate geolocation (Option A: offline, no API key needed)
const IP_GEO: { prefix: string; lat: number; lng: number; city: string; country: string }[] = [
  { prefix: "198.51",   lat: 40.71,  lng: -74.00, city: "New York",    country: "USA" },
  { prefix: "203.0",    lat: 35.68,  lng: 139.69, city: "Tokyo",       country: "Japan" },
  { prefix: "185.199",  lat: 52.52,  lng: 13.40,  city: "Berlin",      country: "Germany" },
  { prefix: "185.220",  lat: 55.75,  lng: 37.61,  city: "Moscow",      country: "Russia" },
  { prefix: "45.33",    lat: 37.38,  lng: -122.0, city: "San Jose",    country: "USA" },
  { prefix: "192.0",    lat: 48.86,  lng: 2.35,   city: "Paris",       country: "France" },
  { prefix: "8.8",      lat: 37.42,  lng: -122.08,city: "Mountain View","country": "USA" },
  { prefix: "10.",      lat: 39.90,  lng: 116.40, city: "Beijing",     country: "China" },
  { prefix: "172.",     lat: 1.35,   lng: 103.82, city: "Singapore",   country: "Singapore" },
];

const REASONS: Record<Tier, string[]> = {
  High:   ["Brute Force Login Attempt", "Exploit Attempt Detected", "Privilege Escalation Attempt", "Malicious Payload Detected"],
  Medium: ["Suspicious User-Agent", "Abnormal Request Rate", "Repeated 401 Responses", "Suspicious Payload Pattern"],
  Low:    ["Reconnaissance Activity", "Port Scan Detected", "Header Anomaly", "Slow Probe Detected"],
};

function geoForIP(ip: string): { lat: number; lng: number; city: string; country: string } {
  const match = IP_GEO.find((g) => ip.startsWith(g.prefix));
  if (match) return match;
  // deterministic fallback based on IP sum
  const parts = ip.split(".").map(Number);
  const seed = (parts[0] * 13 + parts[1] * 7 + parts[2]) % IP_GEO.length;
  return IP_GEO[seed] ?? IP_GEO[0];
}

function reasonForTier(tier: Tier): string {
  const arr = REASONS[tier];
  return arr[Math.floor(Math.random() * arr.length)];
}

function mapFlaskEvent(raw: {
  ip: string; tier: string; score: number; timestamp: string; action: string;
  reason?: string; shap_url?: string;
}, idx: number): ThreatEvent {
  const tier = raw.tier as Tier;
  const geo = geoForIP(raw.ip);
  return {
    id: `${raw.timestamp}-${idx}`,
    timestamp: raw.timestamp,
    ip: raw.ip,
    tier,
    score: raw.score,
    action: raw.action as Action,
    // Use real model explanation if present, fall back to tier-based label
    reason: raw.reason || reasonForTier(tier),
    shap_url: raw.shap_url || "",
    lat: geo.lat + (Math.random() - 0.5) * 0.8,
    lng: geo.lng + (Math.random() - 0.5) * 0.8,
    country: geo.country,
    city: geo.city,
  };
}

/** Derive a full SentinelSnapshot from a flat list of already-mapped ThreatEvents. */
function buildSnapshotFromEvents(
  recent: ThreatEvent[],
  status: SystemStatus,
  ledger: "INTACT" | "COMPROMISED",
  totalBlockedIPs: number,
): SentinelSnapshot {
  const feed    = recent.slice(0, 20);
  const blocked = recent.filter((e) => e.action === "auto-locked" || e.tier === "High");

  const tierCounts = { High: 0, Medium: 0, Low: 0, total: recent.length };
  for (const e of recent) tierCounts[e.tier]++;

  const riskSeries = recent
    .slice()
    .reverse()
    .slice(-30)            // keep last 30 points so the chart stays readable
    .map((e) => ({ t: e.timestamp.slice(11, 16), score: e.score }));

  const lastHigh = recent.find((e) => e.tier === "High");
  const lastHighAt = lastHigh
    ? new Date(lastHigh.timestamp).getTime()
    : Date.now() - 14 * 60_000;

  return {
    status,
    ledger,
    totalBlockedIPs,
    recent,
    feed,
    blocked,
    tierCounts,
    riskSeries,
    lastHighAt,
    totalIPsPlotted: recent.length,
    lastUpdated: new Date().toISOString().slice(11, 19),
  };
}

function buildSnapshot(apiData: {
  status: string;
  blockchain_status: string;
  blocked_count: number;
  total_threat_count?: number;
  all_tier_counts?: { High: number; Medium: number; Low: number };
  threats: { ip: string; tier: string; score: number; timestamp: string; action: string; reason?: string; shap_url?: string }[];
}): SentinelSnapshot {
  const recent = apiData.threats.map(mapFlaskEvent);
  const status: SystemStatus =
    apiData.status === "LOCKDOWN" ? "LOCKDOWN" :
    apiData.status === "THREAT"   ? "THREAT"   : "NORMAL";
  const ledger: "INTACT" | "COMPROMISED" =
    apiData.blockchain_status === "INTACT" ? "INTACT" : "COMPROMISED";

  const snap = buildSnapshotFromEvents(recent, status, ledger, apiData.blocked_count);

  // Override tier counts with the real full-log totals from the backend
  if (apiData.total_threat_count !== undefined && apiData.all_tier_counts) {
    snap.tierCounts = {
      High:   apiData.all_tier_counts.High,
      Medium: apiData.all_tier_counts.Medium,
      Low:    apiData.all_tier_counts.Low,
      total:  apiData.total_threat_count,
    };
  }

  return snap;
}

const FALLBACK: SentinelSnapshot = {
  status: "NORMAL",
  ledger: "INTACT",
  totalBlockedIPs: 0,
  recent: [],
  feed: [],
  blocked: [],
  tierCounts: { High: 0, Medium: 0, Low: 0, total: 0 },
  riskSeries: [],
  lastHighAt: Date.now(),
  totalIPsPlotted: 0,
  lastUpdated: "--:--:--",
};

function authHeaders(): HeadersInit {
  const token = typeof window !== "undefined"
    ? sessionStorage.getItem("auth_token") ?? ""
    : "";
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export function useSentinel(autoRefresh = true): SentinelSnapshot {
  const [snap, setSnap] = useState<SentinelSnapshot>(FALLBACK);

  // Keep a ref to the latest events so the SSE merger can read it without
  // being in the dependency list (avoids re-subscribing on every update).
  const snapRef = useRef<SentinelSnapshot>(FALLBACK);
  snapRef.current = snap;

  // ── Polling fallback: full snapshot from /api/status ────────────────────
  const fetchSnap = useCallback(async () => {
    try {
      const res = await fetch("/api/status", { headers: authHeaders() });
      if (res.status === 401) {
        if (typeof window !== "undefined") window.location.href = "/";
        return;
      }
      if (!res.ok) return;
      const data = await res.json();
      setSnap(buildSnapshot(data));
    } catch {
      // Flask offline — keep last known state
    }
  }, []);

  useEffect(() => {
    fetchSnap();
    if (!autoRefresh) return;
    const id = setInterval(fetchSnap, 5000);
    return () => clearInterval(id);
  }, [autoRefresh, fetchSnap]);

  // ── Real-time push: SSE threat_update events ────────────────────────────
  // When live_sentinel.py writes a new scored threat to threat_log.json the
  // backend tail-follows the file and pushes it here immediately — no poll lag.
  useEffect(() => {
    const token = typeof window !== "undefined"
      ? sessionStorage.getItem("auth_token") ?? ""
      : "";
    if (!token) return;

    const es = new EventSource(`/api/stream?token=${encodeURIComponent(token)}`);

    es.addEventListener("threat_update", (e: MessageEvent) => {
      try {
        const raw = JSON.parse(e.data) as {
          ip: string; tier: string; score: number;
          timestamp: string; action: string;
          reason?: string; shap_url?: string;
        };
        const incoming = mapFlaskEvent(raw, Date.now());
        setSnap(prev => {
          // Dedup by ip+timestamp to avoid double-counting
          const key = `${raw.ip}-${raw.timestamp}`;
          if (prev.recent.some(r => `${r.ip}-${r.timestamp}` === key)) return prev;

          const newRecent = [incoming, ...prev.recent].slice(0, 100);

          // Re-derive status: if there's any pending High, it's LOCKDOWN
          const hasPending  = newRecent.some(r => r.action === "pending");
          const hasAnyHigh  = newRecent.some(r => r.tier === "High");
          const newStatus: SystemStatus = hasPending ? "LOCKDOWN" : hasAnyHigh ? "THREAT" : "NORMAL";

          const newSnap = buildSnapshotFromEvents(
            newRecent,
            newStatus,
            prev.ledger,
            prev.totalBlockedIPs,
          );

          // Preserve the real running totals from the backend rather than
          // rebuilding from the in-memory slice (which is capped at 100).
          // Only increment — the next full poll will reconcile if needed.
          newSnap.tierCounts = {
            High:   prev.tierCounts.High   + (incoming.tier === "High"   ? 1 : 0),
            Medium: prev.tierCounts.Medium + (incoming.tier === "Medium" ? 1 : 0),
            Low:    prev.tierCounts.Low    + (incoming.tier === "Low"    ? 1 : 0),
            total:  prev.tierCounts.total  + 1,
          };

          return newSnap;
        });
      } catch {}
    });

    es.onerror = () => {};   // suppress noise; reconnect is automatic
    return () => es.close();
  }, []);

  return snap;
}

export { authHeaders };

export function useMLMetrics(): MLMetricRow[] {
  const [rows, setRows] = useState<MLMetricRow[]>([]);

  const MODEL_LABELS: Record<string, string> = {
    RF: "RF (Random Forest)",
    GB: "GB (Gradient Boosting)",
    SVM: "SVM (Support Vector Machine)",
    LR: "LR (Logistic Regression)",
    XGB: "XGB (XGBoost)",
    "ENSEMBLE (weighted)": "ENSEMBLE (weighted)",
  };

  useEffect(() => {
    fetch("/api/metrics", { headers: authHeaders() })
      .then((r) => r.json())
      .then((data: { model: string; accuracy: number; precision: number; recall: number; f1: number; auc_roc: number }[]) => {
        setRows(
          data.map((m) => ({
            model: MODEL_LABELS[m.model] ?? m.model,
            accuracy: m.accuracy,
            precision: m.precision,
            recall: m.recall,
            f1: m.f1,
            auc: m.auc_roc,
            ensemble: m.model.toLowerCase().includes("ensemble"),
          }))
        );
      })
      .catch(() => {});
  }, []);

  return rows;
}

export function formatMTTR(sinceMs: number): string {
  const total = Math.max(0, Math.floor((Date.now() - sinceMs) / 1000));
  const h = String(Math.floor(total / 3600)).padStart(2, "0");
  const m = String(Math.floor((total % 3600) / 60)).padStart(2, "0");
  const s = String(total % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}