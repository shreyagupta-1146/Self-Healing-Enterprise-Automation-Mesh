export type EmergencyStatus = "Verified" | "Blocked";

export interface EmergencyAuditEntry {
  type: "Emergency Access";
  timestamp: string;
  ip: string;
  status: EmergencyStatus;
}

const KEY = "sentihealth.emergencyAudit";

export function getEmergencyAudit(): EmergencyAuditEntry[] {
  if (typeof window === "undefined") return [];
  try {
    return JSON.parse(sessionStorage.getItem(KEY) || "[]");
  } catch {
    return [];
  }
}

export function appendEmergencyAudit(entry: EmergencyAuditEntry) {
  if (typeof window === "undefined") return;
  const list = getEmergencyAudit();
  list.unshift(entry);
  sessionStorage.setItem(KEY, JSON.stringify(list.slice(0, 50)));
}

export function nowStamp() {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
