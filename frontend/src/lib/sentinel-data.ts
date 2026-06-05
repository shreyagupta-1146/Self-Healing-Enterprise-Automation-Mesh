import { useEffect, useState } from "react";

export type Tier = "High" | "Medium" | "Low";
export type Action = "pending" | "resolved" | "auto-locked" | "forensics_generated" | "denied";
export type SystemStatus = "NORMAL" | "THREAT" | "LOCKDOWN";

export interface ThreatEvent {
  id: string;
  timestamp: string;
  ip: string;
  tier: Tier;
  score: number;
  action: Action;
  reason: string;
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
    reason: reasonForTier(tier),
    lat: geo.lat + (Math.random() - 0.5) * 0.8,
    lng: geo.lng + (Math.random() - 0.5) * 0.8,
    country: geo.country,
    city: geo.city,
  };
}

function buildSnapshot(apiData: {
  status: string;
  blockchain_status: string;
  blocked_count: number;
  threats: { ip: string; tier: string; score: number; timestamp: string; action: string }[];
}): SentinelSnapshot {
  const recent = apiData.threats.map(mapFlaskEvent);
  const feed = recent.slice(0, 8);
  const blocked = recent.filter((e) => e.action === "auto-locked" || e.tier === "High");

  const tierCounts = { High: 0, Medium: 0, Low: 0, total: recent.length };
  for (const e of recent) tierCounts[e.tier]++;

  const riskSeries = recent
    .slice()
    .reverse()
    .map((e) => ({ t: e.timestamp.slice(11, 16), score: e.score }));

  // Find epoch of last High-tier event, or fall back to 14 min ago
  const lastHigh = recent.find((e) => e.tier === "High");
  const lastHighAt = lastHigh
    ? new Date(lastHigh.timestamp).getTime()
    : Date.now() - 14 * 60_000;

  return {
    status: (apiData.status === "LOCKDOWN" ? "LOCKDOWN" : apiData.status === "THREAT" ? "THREAT" : "NORMAL") as SystemStatus,
    ledger: apiData.blockchain_status === "INTACT" ? "INTACT" : "COMPROMISED",
    totalBlockedIPs: apiData.blocked_count,
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

export function useSentinel(): SentinelSnapshot {
  const [snap, setSnap] = useState<SentinelSnapshot>(FALLBACK);

  const fetchSnap = async () => {
    try {
      const res = await fetch("/api/status");
      if (!res.ok) return;
      const data = await res.json();
      setSnap(buildSnapshot(data));
    } catch {
      // Flask offline — keep last known state
    }
  };

  useEffect(() => {
    fetchSnap();
    const id = setInterval(fetchSnap, 5000);
    return () => clearInterval(id);
  }, []);

  return snap;
}

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
    fetch("/api/metrics")
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