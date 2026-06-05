const express = require('express');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { faker } = require('@faker-js/faker');

const app = express();
app.use(express.json());

const dbDir = '../data';
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir);
fs.writeFileSync('../data/app.db', 'MOCK DB FOR DEMO');

// ---------------------------------------------------------------------------
// Real patient pool (served to legitimate users)
// ---------------------------------------------------------------------------
const patients = [];
for (let i = 0; i < 1000; i++) {
  patients.push({ id: uuidv4(), name: faker.person.fullName(), dob: faker.date.past().toISOString() });
}

// ---------------------------------------------------------------------------
// Mirage deception layer
// ---------------------------------------------------------------------------
// live_sentinel.py writes a JSON file of flagged sessions so the webapp
// knows which sessions to deceive without making a synchronous call.
// Schema: { "<session_id>": { "mode": "full|noise_only|none", "canary_id": "...", "score": 0.9 } }

const FLAGGED_SESSIONS_PATH = path.join('..', 'logs', 'mirage_sessions.json');
const CANARY_LOG_PATH = path.join('..', 'logs', 'canary_registry.jsonl');

function loadFlaggedSessions() {
  try {
    if (!fs.existsSync(FLAGGED_SESSIONS_PATH)) return {};
    return JSON.parse(fs.readFileSync(FLAGGED_SESSIONS_PATH, 'utf8'));
  } catch (_) { return {}; }
}

function mintCanary(sessionId, endpoint, canaryId) {
  const token = canaryId || `canary_${uuidv4().replace(/-/g,'').slice(0,16)}`;
  const entry = { canary_id: token, issued_at: new Date().toISOString(), session_id: sessionId, endpoint };
  try {
    fs.mkdirSync(path.dirname(CANARY_LOG_PATH), { recursive: true });
    fs.appendFileSync(CANARY_LOG_PATH, JSON.stringify(entry) + '\n');
  } catch (_) {}
  return token;
}

function syntheticPatients(count, canaryId) {
  return Array.from({ length: count }, () => ({
    id: `DECOY-${uuidv4().slice(0, 8).toUpperCase()}`,
    name: faker.person.fullName(),
    dob: faker.date.past({ years: 70 }).toISOString(),
    _canary: canaryId,
  }));
}

function addLaplaceNoise(value, sensitivity = 1, epsilon = 2.0) {
  const scale = sensitivity / epsilon;
  const u = Math.random() - 0.5;
  const noise = -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
  if (Number.isInteger(value)) return Math.max(0, Math.round(value + noise));
  return value + noise;
}

// Patient-safety fail-safe: never serve decoys to the clinical allowlist.
// Add verified clinical session IDs here (populated by the auth system).
const CLINICAL_ALLOWLIST = new Set();

function mirageMiddleware(req, res, next) {
  const sessionId = req.headers['session-id'] || '';
  if (!sessionId || CLINICAL_ALLOWLIST.has(sessionId)) return next();

  const flagged = loadFlaggedSessions();
  const entry = flagged[sessionId];
  if (!entry || entry.mode === 'none') return next();

  req._mirage = entry;
  req._mirage.sessionId = sessionId;
  next();
}

app.use(mirageMiddleware);

// ---------------------------------------------------------------------------
// Per-IP feature extractor (sliding 60-second window)
// Aggregates raw HTTP behaviour into the 8 ML features the sentinel expects.
// ---------------------------------------------------------------------------
const IP_WINDOW_MS = 60_000;
const ipState = new Map();   // ip -> { logins, loginFails, ehrRequests, exportBytes, endpoints, times, lastFlush }

function getIpState(ip) {
  if (!ipState.has(ip)) {
    // Initialize lastFlush to IP_WINDOW_MS ago so the first window counts as a full 60s,
    // preventing inflated per-hour rates on the very first request.
    ipState.set(ip, { logins: 0, loginFails: 0, ehrRequests: 0, exportBytes: 0,
                      endpoints: new Set(), times: [], lastFlush: Date.now() - IP_WINDOW_MS });
  }
  return ipState.get(ip);
}

function pruneOld(state, now) {
  state.times = state.times.filter(t => now - t < IP_WINDOW_MS);
}

function buildFeatures(ip, state) {
  const now = Date.now();
  pruneOld(state, now);
  const windowSecs = Math.max(1, (now - state.lastFlush) / 1000);
  const hour = new Date().getHours();
  const accessTimeDeviation = (hour < 6 || hour > 22) ? 0.9 : (hour < 8 || hour > 20) ? 0.5 : 0.1;
  // Source IP reputation: private/local IPs score 0.9, others default 0.5
  const isPrivate = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1$|127\.)/.test(ip);
  const sourceIpReputation = isPrivate ? 0.9 : 0.5;
  const cpu = process.cpuUsage();
  const memRatio = process.memoryUsage().heapUsed / process.memoryUsage().heapTotal;
  return {
    failed_logins: state.loginFails,
    cpu_usage: Math.min(memRatio * 1.5, 1.0),  // proxy for system load
    memory_spike: memRatio > 0.85 ? 1 : 0,
    ehr_access_per_hour: Math.round(state.ehrRequests / (windowSecs / 3600)),
    lateral_movement_events: state.endpoints.size,
    data_export_volume_kb: Math.round(state.exportBytes / 1024),
    access_time_deviation: accessTimeDeviation,
    source_ip_reputation: sourceIpReputation,
  };
}

// ---------------------------------------------------------------------------
// Event logger (attaches to every response)
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const ip = req.ip || '0.0.0.0';
    const state = getIpState(ip);
    const userId = req.headers['user-id'] || 'anonymous';
    const sessionId = req.headers['session-id'] || uuidv4();
    const isEhrEndpoint = /^\/(patients|records|appointments)/.test(req.path);
    const responseSize = parseInt(res.getHeader('content-length') || '0', 10) || 0;

    // Accumulate per-IP signals
    state.times.push(Date.now());
    state.endpoints.add(req.path);
    if (req.path === '/login') state.logins++;
    if (req.path === '/login' && res.statusCode === 401) state.loginFails++;
    if (isEhrEndpoint) state.ehrRequests++;
    state.exportBytes += responseSize;

    const features = buildFeatures(ip, state);

    // Determine heuristic attack_type for DAMAGE multiplier
    let attackType = 'normal';
    if (state.loginFails >= 5) attackType = 'brute_force';
    if (features.data_export_volume_kb > 1000) attackType = 'exfiltration';

    const log = {
      event_id: uuidv4(),
      timestamp: new Date().toISOString(),
      endpoint: req.path,
      method: req.method,
      user_id: userId,
      ip_address: ip,
      source_ip: ip,
      response_time_ms: Date.now() - start,
      status_code: res.statusCode,
      session_id: sessionId,
      mirage_mode: req._mirage ? req._mirage.mode : 'none',
      features: { ...features, attack_type: attackType, asset_type: isEhrEndpoint ? 'ehr' : 'workstation', user_id: userId },
    };
    try { fs.appendFileSync('../logs/events.jsonl', JSON.stringify(log) + '\n'); } catch (_) {}

    // Reset window counters every 60 s so signals don't accumulate unboundedly
    if (Date.now() - state.lastFlush > IP_WINDOW_MS) {
      state.loginFails = 0; state.ehrRequests = 0; state.exportBytes = 0;
      state.endpoints.clear(); state.lastFlush = Date.now();
    }
  });
  next();
});

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

app.post('/login', (req, res) =>
  res.status(401).json({ error: 'Unauthorized', attempt: req.body ? req.body.username : 'unknown' })
);

app.get('/patients', (req, res) => {
  const limit = parseInt(req.query.limit) || 10;

  if (req._mirage && req._mirage.mode === 'full') {
    // Serve synthetic decoys — attacker gets convincing-but-fake data
    const canary = mintCanary(req._mirage.sessionId, '/patients', req._mirage.canary_id);
    const decoys = syntheticPatients(limit, canary);
    return res.json(decoys);
  }

  if (req._mirage && req._mirage.mode === 'noise_only') {
    // Serve real data but add Laplace noise to any numeric fields
    const real = patients.slice(0, limit).map(p => ({ ...p }));
    return res.json(real);  // patient records have no sensitive numerics to noise here
  }

  res.json(patients.slice(0, limit));
});

app.get('/appointments', (req, res) => {
  if (req._mirage && req._mirage.mode === 'full') {
    const canary = mintCanary(req._mirage.sessionId, '/appointments', req._mirage.canary_id);
    const decoys = Array.from({ length: 5 }, () => ({
      id: uuidv4(), patient: faker.person.fullName(), doctor: `Dr. ${faker.person.lastName()}`,
      datetime: faker.date.soon({ days: 14 }).toISOString(), _canary: canary,
    }));
    return res.json(decoys);
  }
  res.json([]);
});

app.get('/records/:id', (req, res) => {
  if (req._mirage && req._mirage.mode === 'full') {
    const canary = mintCanary(req._mirage.sessionId, `/records/${req.params.id}`, req._mirage.canary_id);
    return res.json({
      id: req.params.id,
      name: faker.person.fullName(),
      dob: faker.date.past({ years: 70 }).toISOString(),
      diagnosis: 'Hypertension',
      _canary: canary,
    });
  }
  res.json({ id: req.params.id });
});

app.get('/health', (req, res) =>
  res.status(200).json({ status: 'ok', uptime: process.uptime() })
);

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => console.log(`EHR Server on :${PORT} | Mirage deception: active`));

process.on('uncaughtException', err => console.error('Uncaught:', err));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
