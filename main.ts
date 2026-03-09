import { exists } from "https://deno.land/std@0.224.0/fs/exists.ts";

// ─── Environment Variables ───────────────────────────────────────────
const envUUID = Deno.env.get("UUID") || "";
const proxyIPs = (Deno.env.get("PROXYIP") || "")
  .split(",")
  .map((ip) => ip.trim())
  .filter(Boolean);
const credit = Deno.env.get("CREDIT") || "";
const webPassword = Deno.env.get("WEB_PASSWORD") || "";
const wsPath = Deno.env.get("WS_PATH") || "/ws";
const webUsername = Deno.env.get("WEB_USERNAME") || "";
const stickyProxyIPEnv = Deno.env.get("STICKY_PROXYIP") || "";
const subToken = Deno.env.get("SUB_TOKEN") || "";
const REQUIRE_HTTPS = Deno.env.get("REQUIRE_HTTPS") !== "false";
const CONFIG_FILE = "config.json";

// ─── Stability Tuning Constants ──────────────────────────────────────
const TCP_KEEPALIVE_DELAY = 30; // seconds — send keepalive after 30s idle
const WS_PING_INTERVAL = 25_000; // ms — WebSocket heartbeat interval
const CONNECTION_TIMEOUT = 15_000; // ms — increased from 10s for slow networks
const MAX_RETRY_ATTEMPTS = 3;
const RETRY_BASE_DELAY = 1000; // ms — exponential backoff base
const DNS_CACHE_TTL = 300_000; // ms — cache DNS for 5 minutes
const WRITE_RETRY_ATTEMPTS = 2;
const WRITE_RETRY_DELAY = 500; // ms
const DOH_TIMEOUT = 5000; // ms — timeout for DNS-over-HTTPS queries

interface Config {
  uuid?: string;
}

// ─── DNS Cache ───────────────────────────────────────────────────────
const dnsCache = new Map<string, { data: ArrayBuffer; expiry: number }>();

function getCachedDNS(key: string): ArrayBuffer | null {
  const entry = dnsCache.get(key);
  if (entry && Date.now() < entry.expiry) {
    return entry.data;
  }
  if (entry) dnsCache.delete(key);
  return null;
}

function setCachedDNS(key: string, data: ArrayBuffer): void {
  // Limit cache size
  if (dnsCache.size > 1000) {
    const now = Date.now();
    for (const [k, v] of dnsCache) {
      if (now >= v.expiry) dnsCache.delete(k);
    }
    // If still too large, clear half
    if (dnsCache.size > 800) {
      const entries = Array.from(dnsCache.keys());
      for (let i = 0; i < entries.length / 2; i++) {
        dnsCache.delete(entries[i]);
      }
    }
  }
  dnsCache.set(key, { data, expiry: Date.now() + DNS_CACHE_TTL });
}

// ─── Multiple DoH Providers (fallback) ──────────────────────────────
const DOH_PROVIDERS = [
  "https://1.1.1.1/dns-query",
  "https://8.8.8.8/dns-query",
  "https://9.9.9.9:5053/dns-query",
];

// ─── Security Headers ────────────────────────────────────────────────
const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

function addSecurityHeaders(headers: Headers): Headers {
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    headers.set(key, value);
  }
  return headers;
}

function secureResponse(
  body: BodyInit | null,
  init: ResponseInit = {}
): Response {
  const headers = new Headers(init.headers || {});
  addSecurityHeaders(headers);
  return new Response(body, { ...init, headers });
}

// ─── HTML Escape (XSS Prevention) ───────────────────────────────────
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ─── Constant-Time Comparison ────────────────────────────────────────
function constantTimeEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);
  if (bufA.length !== bufB.length) {
    let dummy = 0;
    for (let i = 0; i < bufA.length; i++) {
      dummy |= bufA[i] ^ (bufB[i % (bufB.length || 1)] || 0);
    }
    void dummy;
    return false;
  }
  let result = 0;
  for (let i = 0; i < bufA.length; i++) {
    result |= bufA[i] ^ bufB[i];
  }
  return result === 0;
}

// ─── Rate Limiter ────────────────────────────────────────────────────
const MAX_TRACKED_IPS = 10000;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;
const RATE_LIMIT_MAX_ATTEMPTS = 5;
const loginAttempts = new Map<
  string,
  { count: number; lastAttempt: number }
>();

const rateLimitCleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of loginAttempts) {
    if (now - record.lastAttempt > RATE_LIMIT_WINDOW) {
      loginAttempts.delete(ip);
    }
  }
}, 30 * 60 * 1000);

// ─── DNS Cache Cleanup Interval ──────────────────────────────────────
const dnsCacheCleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of dnsCache) {
    if (now >= entry.expiry) dnsCache.delete(key);
  }
}, 60_000);

function pruneRateLimitMap(): void {
  if (loginAttempts.size > MAX_TRACKED_IPS) {
    const entries = Array.from(loginAttempts.entries());
    entries.sort((a, b) => a[1].lastAttempt - b[1].lastAttempt);
    const toRemove = Math.floor(entries.length / 2);
    for (let i = 0; i < toRemove; i++) {
      loginAttempts.delete(entries[i][0]);
    }
  }
}

function isRateLimited(ip: string): boolean {
  pruneRateLimitMap();
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record) {
    loginAttempts.set(ip, { count: 1, lastAttempt: now });
    return false;
  }
  if (now - record.lastAttempt > RATE_LIMIT_WINDOW) {
    loginAttempts.set(ip, { count: 1, lastAttempt: now });
    return false;
  }
  record.count++;
  record.lastAttempt = now;
  return record.count > RATE_LIMIT_MAX_ATTEMPTS;
}

function clearRateLimit(ip: string): void {
  loginAttempts.delete(ip);
}

// ─── Client IP Extraction ────────────────────────────────────────────
function getClientIP(request: Request): string {
  return (
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    request.headers.get("cf-connecting-ip") ||
    "unknown"
  );
}

// ─── HTTPS Enforcement ──────────────────────────────────────────────
function requireHTTPS(request: Request): Response | null {
  if (!REQUIRE_HTTPS) return null;
  const proto =
    request.headers.get("x-forwarded-proto") ||
    new URL(request.url).protocol.replace(":", "");
  if (proto !== "https") {
    const httpsUrl = request.url.replace(/^http:/, "https:");
    return new Response(null, {
      status: 301,
      headers: { Location: httpsUrl },
    });
  }
  return null;
}

// ─── Auth Middleware ─────────────────────────────────────────────────
function requireAuth(request: Request): Response | null {
  if (!webPassword) return null;
  const clientIP = getClientIP(request);
  if (isRateLimited(clientIP)) {
    return secureResponse("Too Many Requests. Try again later.", {
      status: 429,
      headers: { "Content-Type": "text/plain", "Retry-After": "900" },
    });
  }
  const authHeader = request.headers.get("Authorization") || "";
  const expectedAuth = `Basic ${btoa(`${webUsername}:${webPassword}`)}`;
  if (!constantTimeEqual(authHeader, expectedAuth)) {
    return secureResponse("Unauthorized", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="VLESS Proxy Admin"',
        "Content-Type": "text/plain",
      },
    });
  }
  clearRateLimit(clientIP);
  return null;
}

// ─── Token Auth for /sub ─────────────────────────────────────────────
function requireTokenOrAuth(request: Request): Response | null {
  if (subToken) {
    const url = new URL(request.url);
    const tokenParam = url.searchParams.get("token");
    if (tokenParam && constantTimeEqual(tokenParam, subToken)) {
      return null;
    }
  }
  return requireAuth(request);
}

// ─── UUID Helpers ────────────────────────────────────────────────────
function maskUUID(uuid: string): string {
  if (uuid.length < 8) return "****";
  return (
    uuid.slice(0, 4) + "****-****-****-****-********" + uuid.slice(-4)
  );
}

function isValidUUID(uuid: string): boolean {
  const uuidRegex =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

// ─── Proxy IP Selection (Sticky) ─────────────────────────────────────
let fixedProxyIP = "";
if (stickyProxyIPEnv) {
  fixedProxyIP = stickyProxyIPEnv.trim();
  console.log(`Using STICKY_PROXYIP (forced): ${fixedProxyIP}`);
} else if (proxyIPs.length > 0) {
  fixedProxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
  console.log(
    `Selected fixed Proxy IP from list: ${fixedProxyIP} (will not change until restart)`
  );
}

function getFixedProxyIP(): string {
  return fixedProxyIP;
}

// ─── Config File ─────────────────────────────────────────────────────
async function getUUIDFromConfig(): Promise<string | undefined> {
  if (await exists(CONFIG_FILE)) {
    try {
      const configText = await Deno.readTextFile(CONFIG_FILE);
      const config: Config = JSON.parse(configText);
      if (config.uuid && isValidUUID(config.uuid)) {
        console.log(
          `Loaded UUID from ${CONFIG_FILE}: ${maskUUID(config.uuid)}`
        );
        return config.uuid;
      }
    } catch (e) {
      console.warn(
        `Error reading or parsing ${CONFIG_FILE}:`,
        (e as Error).message
      );
    }
  }
  return undefined;
}

async function saveUUIDToConfig(uuid: string): Promise<void> {
  try {
    const config: Config = { uuid: uuid };
    await Deno.writeTextFile(CONFIG_FILE, JSON.stringify(config, null, 2), {
      mode: 0o600,
    });
    console.log(`Saved new UUID to ${CONFIG_FILE}: ${maskUUID(uuid)}`);
  } catch (e) {
    console.error(
      `Failed to save UUID to ${CONFIG_FILE}:`,
      (e as Error).message
    );
  }
}

// ─── UUID Initialization ─────────────────────────────────────────────
let userIDs: string[] = [];
if (envUUID) {
  userIDs = envUUID
    .split(",")
    .map((u) => u.trim().toLowerCase())
    .filter(isValidUUID);
  if (userIDs.length > 0) {
    console.log(
      `Using UUIDs from environment: ${userIDs.map(maskUUID).join(", ")}`
    );
  }
}

if (userIDs.length === 0) {
  const configUUID = await getUUIDFromConfig();
  if (configUUID) {
    userIDs.push(configUUID.toLowerCase());
  } else {
    const newUUID = crypto.randomUUID();
    console.log(`Generated new UUID: ${maskUUID(newUUID)}`);
    await saveUUIDToConfig(newUUID);
    userIDs.push(newUUID);
  }
}

if (userIDs.length === 0) {
  throw new Error("No valid UUID available");
}

const primaryUserID = userIDs[0];
console.log(Deno.version);
console.log(`UUIDs in use: ${userIDs.map(maskUUID).join(", ")}`);
console.log(`WebSocket path: ${wsPath}`);
console.log(
  `Fixed Proxy IP: ${fixedProxyIP || "(none — direct connection)"}`
);
console.log(`TCP Keep-Alive: ${TCP_KEEPALIVE_DELAY}s`);
console.log(`WS Ping Interval: ${WS_PING_INTERVAL}ms`);
console.log(`Connection Timeout: ${CONNECTION_TIMEOUT}ms`);
console.log(`Max Retry Attempts: ${MAX_RETRY_ATTEMPTS}`);
if (!webPassword) {
  console.warn(
    "⚠️  WARNING: WEB_PASSWORD is not set! /config and /sub endpoints are unprotected."
  );
}

// ─── Connection Tracking & Graceful Shutdown ─────────────────────────
const activeConnections = new Set<Deno.TcpConn>();
const activeWebSockets = new Set<WebSocket>();
const activePingIntervals = new Set<number>();

function trackConnection(conn: Deno.TcpConn): void {
  activeConnections.add(conn);
}

function untrackConnection(conn: Deno.TcpConn): void {
  activeConnections.delete(conn);
}

function trackWebSocket(ws: WebSocket): void {
  activeWebSockets.add(ws);
}

function untrackWebSocket(ws: WebSocket): void {
  activeWebSockets.delete(ws);
}

function gracefulShutdown(signal: string): void {
  console.log(`${signal} received, shutting down gracefully...`);
  clearInterval(rateLimitCleanupInterval);
  clearInterval(dnsCacheCleanupInterval);

  // Clear all ping intervals
  for (const intervalId of activePingIntervals) {
    clearInterval(intervalId);
  }
  activePingIntervals.clear();

  // Close all WebSockets
  for (const ws of activeWebSockets) {
    try {
      ws.close(1001, "Server shutting down");
    } catch (_) {
      /* ignore */
    }
  }

  // Close all TCP connections
  for (const conn of activeConnections) {
    try {
      conn.close();
    } catch (_) {
      /* ignore */
    }
  }

  Deno.exit(0);
}

try {
  Deno.addSignalListener("SIGINT", () => gracefulShutdown("SIGINT"));
} catch (_) {
  /* Signal listeners may not be available on all platforms */
}
try {
  Deno.addSignalListener("SIGTERM", () => gracefulShutdown("SIGTERM"));
} catch (_) {
  /* SIGTERM may not be available on Windows */
}

// ─── Buffer Concatenation Helper ─────────────────────────────────────
function concatUint8Arrays(...arrays: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const arr of arrays) {
    totalLength += arr.byteLength;
  }
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.byteLength;
  }
  return result;
}

// ─── Delay Helper ────────────────────────────────────────────────────
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── Retry with Exponential Backoff ──────────────────────────────────
async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  maxAttempts: number,
  baseDelay: number,
  log: (info: string, event?: string) => void
): Promise<T> {
  let lastError: Error | undefined;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (e) {
      lastError = e as Error;
      if (attempt < maxAttempts) {
        const jitter = Math.random() * 0.3 + 0.85; // 0.85–1.15
        const waitTime = Math.min(baseDelay * Math.pow(2, attempt - 1) * jitter, 10000);
        log(`Attempt ${attempt}/${maxAttempts} failed: ${lastError.message}. Retrying in ${Math.round(waitTime)}ms...`);
        await delay(waitTime);
      }
    }
  }
  throw lastError;
}

// ─── Safe Write to TCP with Retry ────────────────────────────────────
async function safeWriteToTCP(
  conn: Deno.TcpConn,
  data: Uint8Array,
  log: (info: string, event?: string) => void
): Promise<boolean> {
  for (let attempt = 1; attempt <= WRITE_RETRY_ATTEMPTS; attempt++) {
    try {
      const writer = conn.writable.getWriter();
      try {
        await writer.write(data);
      } finally {
        writer.releaseLock();
      }
      return true;
    } catch (e) {
      if (attempt < WRITE_RETRY_ATTEMPTS) {
        log(`TCP write attempt ${attempt} failed: ${(e as Error).message}, retrying...`);
        await delay(WRITE_RETRY_DELAY);
      } else {
        log(`TCP write failed after ${WRITE_RETRY_ATTEMPTS} attempts: ${(e as Error).message}`);
        return false;
      }
    }
  }
  return false;
}

// ─── Safe WebSocket Send with Buffering ──────────────────────────────
function safeWebSocketSend(ws: WebSocket, data: Uint8Array | ArrayBuffer): boolean {
  try {
    if (ws.readyState !== WS_READY_STATE_OPEN) {
      return false;
    }
    // Check bufferedAmount to avoid overwhelming the WebSocket
    // If more than 10MB is buffered, apply backpressure
    if (ws.bufferedAmount > 10 * 1024 * 1024) {
      console.warn(`WebSocket backpressure: bufferedAmount=${ws.bufferedAmount}`);
      return false;
    }
    ws.send(data);
    return true;
  } catch (_) {
    return false;
  }
}

// ─── HTML Template ───────────────────────────────────────────────────
const getHtml = (title: string, bodyContent: string) => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeHtml(title)}</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --text-main: #f8fafc;
            --text-sub: #94a3b8;
            --border: rgba(148, 163, 184, 0.1);
        }
        body {
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 0% 0%, rgba(59, 130, 246, 0.15) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(139, 92, 246, 0.15) 0px, transparent 50%);
            color: var(--text-main);
            min-height: 100vh;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            padding: 40px;
            border-radius: 24px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            max-width: 700px;
            width: 100%;
            text-align: center;
            animation: fadeIn 0.6s ease-out;
        }
        h1 {
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(to right, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 1rem;
            margin-top: 0;
        }
        p {
            color: var(--text-sub);
            font-size: 1.1rem;
            line-height: 1.6;
            margin-bottom: 2rem;
        }
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: var(--primary);
            color: white;
            padding: 12px 30px;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.2s;
            box-shadow: 0 4px 6px -1px rgba(59, 130, 246, 0.5);
            border: none;
            cursor: pointer;
            font-size: 1rem;
            margin: 5px;
        }
        .btn:hover {
            background: var(--primary-hover);
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(59, 130, 246, 0.5);
        }
        .config-box {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-top: 20px;
            text-align: left;
            position: relative;
        }
        .config-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .config-title {
            font-weight: 700;
            color: #e2e8f0;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        pre {
            margin: 0;
            white-space: pre-wrap;
            word-break: break-all;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.85rem;
            color: #94a3b8;
            max-height: 150px;
            overflow-y: auto;
            padding-right: 10px;
        }
        pre::-webkit-scrollbar { width: 6px; }
        pre::-webkit-scrollbar-track { background: transparent; }
        pre::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
        .copy-btn {
            background: rgba(59, 130, 246, 0.1);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.2);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.2s;
        }
        .copy-btn:hover { background: rgba(59, 130, 246, 0.2); }
        .user-section {
            border-top: 1px solid var(--border);
            margin-top: 30px;
            padding-top: 20px;
        }
        .user-label {
            display: inline-block;
            background: rgba(59, 130, 246, 0.1);
            color: #60a5fa;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-bottom: 10px;
        }
        .footer {
            margin-top: 40px;
            font-size: 0.85rem;
            color: #475569;
        }
        .footer a {
            color: #64748b;
            text-decoration: none;
            transition: color 0.2s;
        }
        .footer a:hover { color: #94a3b8; }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .countdown {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin: 30px 0;
        }
        .countdown-item {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 20px 24px;
            min-width: 80px;
        }
        .countdown-number {
            font-size: 2.2rem;
            font-weight: 800;
            background: linear-gradient(to bottom, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            line-height: 1;
        }
        .countdown-label {
            font-size: 0.75rem;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-top: 8px;
        }
        .progress-bar {
            background: rgba(15, 23, 42, 0.6);
            border-radius: 10px;
            height: 6px;
            margin: 30px 0;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            border-radius: 10px;
            background: linear-gradient(to right, #3b82f6, #a78bfa);
            animation: progressAnim 3s ease-in-out infinite;
            width: 65%;
        }
        @keyframes progressAnim {
            0% { width: 55%; }
            50% { width: 75%; }
            100% { width: 55%; }
        }
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin: 30px 0;
        }
        .feature-item {
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 12px;
        }
        .feature-icon { font-size: 1.8rem; margin-bottom: 8px; }
        .feature-name { font-size: 0.85rem; color: #94a3b8; font-weight: 500; }
        .toast {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%) translateY(100px);
            background: rgba(30, 41, 59, 0.95);
            border: 1px solid rgba(74, 222, 128, 0.2);
            color: #4ade80;
            padding: 14px 28px;
            border-radius: 12px;
            font-size: 0.9rem;
            font-weight: 500;
            transition: transform 0.4s ease;
            backdrop-filter: blur(8px);
            z-index: 100;
        }
        .toast.show { transform: translateX(-50%) translateY(0); }
        @media (max-width: 600px) {
            .container { padding: 28px 20px; }
            h1 { font-size: 1.8rem; }
            .countdown { gap: 10px; }
            .countdown-item { padding: 14px 16px; min-width: 60px; }
            .countdown-number { font-size: 1.6rem; }
            .feature-grid { grid-template-columns: repeat(3, 1fr); gap: 10px; }
            .feature-item { padding: 14px 8px; }
        }
    </style>
</head>
<body>
    <div class="container">
        ${bodyContent}
    </div>
    <script>
        function copyToClipboard(elementId, btn) {
            const text = document.getElementById(elementId).innerText;
            navigator.clipboard.writeText(text).then(() => {
                const originalText = btn.innerText;
                btn.innerText = 'Copied!';
                btn.style.background = 'rgba(34, 197, 94, 0.1)';
                btn.style.color = '#4ade80';
                btn.style.borderColor = 'rgba(34, 197, 94, 0.2)';
                setTimeout(() => {
                    btn.innerText = originalText;
                    btn.style = '';
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy', err);
            });
        }
    </script>
</body>
</html>
`;

// ─── Connection with Timeout + Keep-Alive ────────────────────────────
async function connectWithTimeout(
  hostname: string,
  port: number,
  timeout: number
): Promise<Deno.TcpConn> {
  let timeoutId: number;
  const connPromise = Deno.connect({ hostname, port });
  const timer = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(
      () =>
        reject(
          new Error(
            `Connection to ${hostname}:${port} timed out after ${timeout}ms`
          )
        ),
      timeout
    );
  });
  try {
    const conn = await Promise.race([connPromise, timer]);
    clearTimeout(timeoutId!);

    // Enable TCP Keep-Alive to prevent idle disconnections
    try {
      conn.setKeepAlive(true);
    } catch (_) {
      // setKeepAlive might not be available in all Deno versions
    }
    try {
      // Some Deno versions support setNoDelay for lower latency
      conn.setNoDelay(true);
    } catch (_) {
      // Ignore if not supported
    }

    return conn;
  } catch (e) {
    clearTimeout(timeoutId!);
    connPromise
      .then((c) => {
        try {
          c.close();
        } catch (_) {
          /* ignore */
        }
      })
      .catch(() => {});
    throw e;
  }
}

// ─── Helper: Check if error is a normal disconnect ───────────────────
function isNormalDisconnectError(error: unknown): boolean {
  if (error instanceof Error) {
    const err = error as Error & { code?: string; name?: string };
    return (
      err.code === "EINTR" ||
      err.name === "Interrupted" ||
      err.name === "AbortError" ||
      err.message?.includes("operation canceled") ||
      err.message?.includes("connection reset") ||
      err.message?.includes("broken pipe") ||
      err.message?.includes("aborted") ||
      err.message?.includes("closed") ||
      err.message?.includes("Connection refused")
    );
  }
  if (typeof error === "string") {
    return (
      error.includes("aborted") ||
      error.includes("reset") ||
      error.includes("canceled") ||
      error.includes("closed")
    );
  }
  return false;
}

// ─── Retryable Connection Error Check ────────────────────────────────
function isRetryableError(error: unknown): boolean {
  if (error instanceof Error) {
    const msg = error.message.toLowerCase();
    return (
      msg.includes("timed out") ||
      msg.includes("connection refused") ||
      msg.includes("network unreachable") ||
      msg.includes("host unreachable") ||
      msg.includes("connection reset") ||
      msg.includes("econnreset") ||
      msg.includes("econnrefused") ||
      msg.includes("etimedout") ||
      msg.includes("enetunreach") ||
      msg.includes("ehostunreach")
    );
  }
  return false;
}

// ─── Address Validation ──────────────────────────────────────────────
function isValidAddress(address: string): boolean {
  const privateRanges = [
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^192\.168\./,
    /^0\./,
    /^169\.254\./,
    /^::1$/,
    /^fc00:/i,
    /^fd00:/i,
    /^fe80:/i,
    /^localhost$/i,
  ];

  for (const regex of privateRanges) {
    if (regex.test(address)) {
      return false;
    }
  }
  return true;
}

// ─── WebSocket Ping/Pong Heartbeat ───────────────────────────────────
function startWebSocketHeartbeat(
  ws: WebSocket,
  log: (info: string, event?: string) => void
): number {
  let missedPongs = 0;
  const maxMissedPongs = 3;
  let waitingForPong = false;

  const pongHandler = () => {
    missedPongs = 0;
    waitingForPong = false;
  };

  // Listen for pong (in standard WebSocket, pong is handled internally,
  // but we track via message events or a custom approach)
  // For Deno's WebSocket, ping/pong is handled at protocol level
  // We'll use a simpler approach: just send pings and track connection state

  const intervalId = setInterval(() => {
    if (ws.readyState !== WS_READY_STATE_OPEN) {
      clearInterval(intervalId);
      activePingIntervals.delete(intervalId);
      return;
    }

    if (waitingForPong) {
      missedPongs++;
      if (missedPongs >= maxMissedPongs) {
        log(`WebSocket heartbeat: ${missedPongs} missed pongs, closing connection`);
        clearInterval(intervalId);
        activePingIntervals.delete(intervalId);
        safeCloseWebSocket(ws);
        return;
      }
    }

    try {
      // Send a ping frame — Deno's WebSocket doesn't expose .ping() directly
      // but the protocol handles ping/pong automatically.
      // We'll send a tiny binary message as application-level heartbeat
      // that the client can ignore, or just rely on TCP keepalive + WS protocol pings.
      // Actually, let's just check readyState and bufferedAmount
      if (ws.bufferedAmount > 5 * 1024 * 1024) {
        log(`WebSocket heartbeat: high buffered amount (${ws.bufferedAmount}), potential stall`);
      }
      waitingForPong = false; // Reset since we can't truly do app-level ping
      missedPongs = 0;
    } catch (e) {
      log(`WebSocket heartbeat error: ${(e as Error).message}`);
      clearInterval(intervalId);
      activePingIntervals.delete(intervalId);
    }
  }, WS_PING_INTERVAL);

  activePingIntervals.add(intervalId);
  return intervalId;
}

// ─── Main Server ─────────────────────────────────────────────────────
Deno.serve(async (request: Request) => {
  const url = new URL(request.url);

  // ── WebSocket upgrade ──
  const upgrade = request.headers.get("upgrade") || "";
  if (upgrade.toLowerCase() === "websocket") {
    if (url.pathname !== wsPath) {
      return new Response("Not Found", { status: 404 });
    }
    return await vlessOverWSHandler(request);
  }

  // ── HTTPS enforcement for sensitive routes ──
  if (
    REQUIRE_HTTPS &&
    (url.pathname === "/config" || url.pathname === "/sub")
  ) {
    const httpsRedirect = requireHTTPS(request);
    if (httpsRedirect) return httpsRedirect;
  }

  // ── Health (minimal info, no auth needed) ──
  if (url.pathname === "/health") {
    return secureResponse(
      JSON.stringify(
        {
          status: "ok",
          timestamp: new Date().toISOString(),
          activeConnections: activeConnections.size,
          activeWebSockets: activeWebSockets.size,
          dnsCacheSize: dnsCache.size,
          uptime: performance.now(),
        },
        null,
        2
      ),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        },
      }
    );
  }

  // ── /sub endpoint ──
  if (url.pathname === "/sub") {
    const authResponse = requireTokenOrAuth(request);
    if (authResponse) return authResponse;

    const hostName = url.hostname;
    const port = url.port || (url.protocol === "https:" ? 443 : 80);
    const allLinks = userIDs
      .map((uid, index) => {
        const tag = credit
          ? `${credit}-${index + 1}`
          : `${hostName}-${index + 1}`;
        return `vless://${uid}@${hostName}:${port}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=${encodeURIComponent(wsPath + "?ed=2048")}#${tag}`;
      })
      .join("\n");
    const base64Content = btoa(allLinks);
    return secureResponse(base64Content, {
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Profile-Update-Interval": "12",
        "Subscription-Userinfo":
          "upload=0; download=0; total=10737418240; expire=0",
        "Cache-Control": "no-store",
      },
    });
  }

  // ── /config endpoint ──
  if (url.pathname === "/config") {
    const authResponse = requireAuth(request);
    if (authResponse) return authResponse;

    const hostName = url.hostname;
    const port = url.port || (url.protocol === "https:" ? 443 : 80);
    let userSections = "";

    userIDs.forEach((uid, index) => {
      const rawTag = credit
        ? `${credit}-${index + 1}`
        : `${hostName}-${index + 1}`;

      const vlessLink = `vless://${uid}@${hostName}:${port}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=${encodeURIComponent(wsPath + "?ed=2048")}#${rawTag}`;

      const clashConfig = `
- type: vless
  name: ${rawTag}
  server: ${hostName}
  port: ${port}
  uuid: ${uid}
  network: ws
  tls: true
  udp: false
  sni: ${hostName}
  client-fingerprint: chrome
  ws-opts:
    path: "${wsPath}?ed=2048"
    headers:
      host: ${hostName}`;

      userSections += `
        <div class="${index > 0 ? "user-section" : ""}">
            <span class="user-label">User ${index + 1}</span>
            <div class="config-box">
                <div class="config-header">
                    <span class="config-title">VLESS URI (V2RayNG / v2rayN)</span>
                    <button class="copy-btn" onclick="copyToClipboard('vless-uri-${index}', this)">Copy</button>
                </div>
                <pre id="vless-uri-${index}">${escapeHtml(vlessLink)}</pre>
            </div>
            <div class="config-box">
                <div class="config-header">
                    <span class="config-title">Clash Meta YAML</span>
                    <button class="copy-btn" onclick="copyToClipboard('clash-config-${index}', this)">Copy</button>
                </div>
                <pre id="clash-config-${index}">${escapeHtml(clashConfig.trim())}</pre>
            </div>
        </div>
      `;
    });

    const safeHostForSub = escapeHtml(url.hostname);
    const subUrlDisplay = subToken
      ? `https://${safeHostForSub}/sub?token=${escapeHtml(subToken)}`
      : `https://${safeHostForSub}/sub`;

    const content = `
        <h1>Server Configuration</h1>
        <p>Import these settings into your V2Ray or Clash client.</p>
        ${userSections}
        <div class="config-box" style="margin-top: 30px;">
            <div class="config-header">
                <span class="config-title">Subscription URL</span>
                <button class="copy-btn" onclick="copyToClipboard('sub-url', this)">Copy</button>
            </div>
            <pre id="sub-url">${subUrlDisplay}</pre>
        </div>
        <div class="footer">
            <a href="/">Back to Home</a>
        </div>
    `;
    return secureResponse(getHtml("VLESS Config", content), {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  }

  // ── Home page ──
  if (url.pathname === "/") {
    const content = `
        <h1>NovaByte Cloud</h1>
        <p>We're crafting a next-generation cloud platform.<br>Something amazing is on the way.</p>
        
        <div class="countdown" id="countdown">
            <div class="countdown-item">
                <div class="countdown-number" id="days">00</div>
                <div class="countdown-label">Days</div>
            </div>
            <div class="countdown-item">
                <div class="countdown-number" id="hours">00</div>
                <div class="countdown-label">Hours</div>
            </div>
            <div class="countdown-item">
                <div class="countdown-number" id="minutes">00</div>
                <div class="countdown-label">Minutes</div>
            </div>
            <div class="countdown-item">
                <div class="countdown-number" id="seconds">00</div>
                <div class="countdown-label">Seconds</div>
            </div>
        </div>

        <div class="progress-bar">
            <div class="progress-fill"></div>
        </div>

        <div class="feature-grid">
            <div class="feature-item">
                <div class="feature-icon">⚡</div>
                <div class="feature-name">Lightning Fast</div>
            </div>
            <div class="feature-item">
                <div class="feature-icon">🔒</div>
                <div class="feature-name">Secure</div>
            </div>
            <div class="feature-item">
                <div class="feature-icon">🌍</div>
                <div class="feature-name">Global CDN</div>
            </div>
        </div>

        <div class="footer">
            <p>&copy; 2026 NovaByte Cloud Inc. All rights reserved.</p>
        </div>

        <script>
            const launchDate = new Date();
            launchDate.setDate(launchDate.getDate() + 90);
            
            function updateCountdown() {
                const now = new Date();
                const diff = launchDate - now;
                if (diff <= 0) return;
                const d = Math.floor(diff / (1000 * 60 * 60 * 24));
                const h = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                const m = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
                const s = Math.floor((diff % (1000 * 60)) / 1000);
                document.getElementById('days').textContent = String(d).padStart(2, '0');
                document.getElementById('hours').textContent = String(h).padStart(2, '0');
                document.getElementById('minutes').textContent = String(m).padStart(2, '0');
                document.getElementById('seconds').textContent = String(s).padStart(2, '0');
            }
            updateCountdown();
            setInterval(updateCountdown, 1000);
        </script>
    `;
    return secureResponse(getHtml("NovaByte Cloud - Coming Soon", content), {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  // ── 404 ──
  return secureResponse(
    getHtml(
      "404",
      '<h1>404 Not Found</h1><p>The path you requested does not exist.</p><a href="/" class="btn">Go Home</a>'
    ),
    {
      status: 404,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    }
  );
});

// ─── VLESS over WebSocket Handler ────────────────────────────────────
async function vlessOverWSHandler(request: Request) {
  const { socket, response } = Deno.upgradeWebSocket(request, {
    // Increase idle timeout for stability
    idleTimeout: 120, // seconds — keep connection alive longer
  });

  let address = "";
  let portWithRandomLog = "";
  let heartbeatIntervalId: number | undefined;
  const log = (info: string, event = "") => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event);
  };

  const earlyDataHeader =
    request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(
    socket,
    earlyDataHeader,
    log
  );

  const remoteSocketWrapper: { value: Deno.TcpConn | null } = {
    value: null,
  };
  let udpStreamWrite: ((chunk: Uint8Array) => void) | null = null;
  let isDns = false;

  const cleanupAll = () => {
    // Clean up heartbeat
    if (heartbeatIntervalId !== undefined) {
      clearInterval(heartbeatIntervalId);
      activePingIntervals.delete(heartbeatIntervalId);
      heartbeatIntervalId = undefined;
    }
    // Clean up remote TCP
    safeCloseRemote(remoteSocketWrapper.value);
    remoteSocketWrapper.value = null;
    // Untrack WebSocket
    untrackWebSocket(socket);
  };

  // Track this WebSocket
  trackWebSocket(socket);

  socket.addEventListener("open", () => {
    log("WebSocket opened");
    // Start heartbeat monitoring
    heartbeatIntervalId = startWebSocketHeartbeat(socket, log);
  });

  socket.addEventListener("close", (event) => {
    log(`WebSocket closed by client (code=${event.code}, reason=${event.reason})`);
    cleanupAll();
  });

  socket.addEventListener("error", (e) => {
    log("WebSocket error", String(e));
    cleanupAll();
  });

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWrapper.value) {
            const writeSuccess = await safeWriteToTCP(
              remoteSocketWrapper.value,
              new Uint8Array(chunk),
              log
            );
            if (!writeSuccess) {
              controller.error("TCP write failed");
            }
            return;
          }

          const {
            hasError,
            message,
            portRemote = 443,
            addressRemote = "",
            rawDataIndex,
            vlessVersion = new Uint8Array([0, 0]),
            isUDP,
          } = processVlessHeader(chunk, userIDs);

          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} `;

          if (hasError) {
            throw new Error(message);
          }

          if (!isValidAddress(addressRemote)) {
            throw new Error(
              `Connection to private/reserved address blocked: ${addressRemote}`
            );
          }

          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
            } else {
              throw new Error(
                "UDP proxy only enabled for DNS which is port 53"
              );
            }
          }

          const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex!);

          if (isDns) {
            log("DNS query via UDP");
            const { write } = await handleUDPOutBound(
              socket,
              vlessResponseHeader,
              log
            );
            udpStreamWrite = write;
            udpStreamWrite(rawClientData);
            return;
          }

          handleTCPOutBound(
            remoteSocketWrapper,
            addressRemote,
            portRemote,
            rawClientData,
            socket,
            vlessResponseHeader,
            log
          );
        },
        close() {
          log(`readableWebSocketStream is closed`);
          cleanupAll();
        },
        abort(reason) {
          log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
          cleanupAll();
        },
      })
    )
    .catch((err) => {
      if (isNormalDisconnectError(err)) {
        log("WebSocket stream ended (client disconnected)");
      } else {
        log("readableWebSocketStream pipeTo error", String(err));
      }
      cleanupAll();
      safeCloseWebSocket(socket);
    });

  return response;
}

// ─── Safe Close Remote TCP ───────────────────────────────────────────
function safeCloseRemote(conn: Deno.TcpConn | null): void {
  if (conn) {
    untrackConnection(conn);
    try {
      conn.close();
    } catch (_) {
      /* ignore */
    }
  }
}

// ─── TCP Outbound Handler (with retry + backoff) ─────────────────────
async function handleTCPOutBound(
  remoteSocket: { value: Deno.TcpConn | null },
  addressRemote: string,
  portRemote: number,
  rawClientData: Uint8Array,
  webSocket: WebSocket,
  vlessResponseHeader: Uint8Array,
  log: (info: string, event?: string) => void
) {
  async function connectAndWrite(
    address: string,
    port: number
  ): Promise<Deno.TcpConn> {
    const tcpSocket = await connectWithTimeout(
      address,
      port,
      CONNECTION_TIMEOUT
    );
    remoteSocket.value = tcpSocket;
    trackConnection(tcpSocket);
    log(`connected to ${address}:${port}`);
    const writeSuccess = await safeWriteToTCP(tcpSocket, new Uint8Array(rawClientData), log);
    if (!writeSuccess) {
      throw new Error(`Failed to write initial data to ${address}:${port}`);
    }
    return tcpSocket;
  }

  async function tryConnectWithRetry(
    address: string,
    port: number
  ): Promise<Deno.TcpConn> {
    return retryWithBackoff(
      () => connectAndWrite(address, port),
      MAX_RETRY_ATTEMPTS,
      RETRY_BASE_DELAY,
      log
    );
  }

  async function retryWithProxyIP() {
    const fallbackIP = getFixedProxyIP();
    if (!fallbackIP) {
      log("No proxy IP available for retry");
      safeCloseWebSocket(webSocket);
      return;
    }
    if (!isValidAddress(fallbackIP)) {
      log(`Proxy IP ${fallbackIP} is a private address, blocking`);
      safeCloseWebSocket(webSocket);
      return;
    }
    log(`Retrying with fixed proxy IP: ${fallbackIP}`);
    try {
      const tcpSocket = await tryConnectWithRetry(fallbackIP, portRemote);
      remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
    } catch (e) {
      log(`All retry attempts with proxy IP failed: ${(e as Error).message}`);
      safeCloseWebSocket(webSocket);
    }
  }

  try {
    const tcpSocket = await tryConnectWithRetry(addressRemote, portRemote);
    remoteSocketToWS(
      tcpSocket,
      webSocket,
      vlessResponseHeader,
      retryWithProxyIP,
      log
    );
  } catch (e) {
    log(
      `All direct connection attempts failed: ${(e as Error).message}, attempting proxy IP fallback...`
    );
    await retryWithProxyIP();
  }
}

// ─── Readable WebSocket Stream ───────────────────────────────────────
function makeReadableWebSocketStream(
  webSocketServer: WebSocket,
  earlyDataHeader: string,
  log: (info: string, event?: string) => void
) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) return;
        const data = event.data;
        if (data instanceof ArrayBuffer) {
          controller.enqueue(data);
        } else if (data instanceof Blob) {
          data
            .arrayBuffer()
            .then((buf) => {
              if (!readableStreamCancel) controller.enqueue(buf);
            })
            .catch((err) => {
              log("Blob to ArrayBuffer error", String(err));
            });
        }
        // Ignore string messages (could be heartbeat responses)
      });

      webSocketServer.addEventListener("close", () => {
        if (readableStreamCancel) return;
        try {
          controller.close();
        } catch (_) {
          /* stream may already be closed */
        }
      });

      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        try {
          controller.error(err);
        } catch (_) {
          /* stream may already be errored */
        }
      });

      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    pull(_controller) {},
    cancel(reason) {
      if (readableStreamCancel) return;
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
  return stream;
}

// ─── VLESS Header Parser ─────────────────────────────────────────────
function processVlessHeader(
  vlessBuffer: ArrayBuffer,
  validUserIDs: string[]
) {
  if (vlessBuffer.byteLength < 24) {
    return { hasError: true, message: "invalid data" };
  }

  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  const incomingUUID = stringify(
    new Uint8Array(vlessBuffer.slice(1, 17))
  ).toLowerCase();

  let isValidUser = false;
  for (const id of validUserIDs) {
    if (constantTimeEqual(id, incomingUUID)) {
      isValidUser = true;
    }
  }

  if (!isValidUser) {
    return { hasError: true, message: "invalid user" };
  }

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];

  if (18 + optLength + 1 > vlessBuffer.byteLength) {
    return { hasError: true, message: "invalid header: optLength exceeds buffer" };
  }

  const command = new Uint8Array(
    vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
  )[0];
  let isUDP = false;

  if (command === 1) {
    // TCP
  } else if (command === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${command} is not supported, command 01-tcp, 02-udp, 03-mux`,
    };
  }

  const portIndex = 18 + optLength + 1;

  if (portIndex + 2 > vlessBuffer.byteLength) {
    return { hasError: true, message: "invalid header: buffer too short for port" };
  }

  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  const addressIndex = portIndex + 2;

  if (addressIndex + 1 > vlessBuffer.byteLength) {
    return {
      hasError: true,
      message: "invalid header: buffer too short for address type",
    };
  }

  const addressBuffer = new Uint8Array(
    vlessBuffer.slice(addressIndex, addressIndex + 1)
  );
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";

  switch (addressType) {
    case 1: {
      addressLength = 4;
      if (addressValueIndex + addressLength > vlessBuffer.byteLength) {
        return {
          hasError: true,
          message: "invalid header: buffer too short for IPv4 address",
        };
      }
      addressValue = new Uint8Array(
        vlessBuffer.slice(
          addressValueIndex,
          addressValueIndex + addressLength
        )
      ).join(".");
      break;
    }
    case 2: {
      if (addressValueIndex + 1 > vlessBuffer.byteLength) {
        return {
          hasError: true,
          message: "invalid header: buffer too short for domain length",
        };
      }
      addressLength = new Uint8Array(
        vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
      )[0];
      addressValueIndex += 1;
      if (addressLength === 0) {
        return { hasError: true, message: "invalid header: domain length is 0" };
      }
      if (addressValueIndex + addressLength > vlessBuffer.byteLength) {
        return {
          hasError: true,
          message: "invalid header: domain length exceeds buffer",
        };
      }
      addressValue = new TextDecoder().decode(
        vlessBuffer.slice(
          addressValueIndex,
          addressValueIndex + addressLength
        )
      );
      break;
    }
    case 3: {
      addressLength = 16;
      if (addressValueIndex + addressLength > vlessBuffer.byteLength) {
        return {
          hasError: true,
          message: "invalid header: buffer too short for IPv6 address",
        };
      }
      const dataView = new DataView(
        vlessBuffer.slice(
          addressValueIndex,
          addressValueIndex + addressLength
        )
      );
      const ipv6: string[] = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    }
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

// ─── Remote Socket to WebSocket (improved stability) ─────────────────
async function remoteSocketToWS(
  remoteSocket: Deno.TcpConn,
  webSocket: WebSocket,
  vlessResponseHeader: Uint8Array,
  retry: (() => Promise<void>) | null,
  log: (info: string, event?: string) => void
) {
  let hasIncomingData = false;
  let headerSent = false;

  const abortController = new AbortController();

  const onWsClose = () => {
    abortController.abort();
  };

  webSocket.addEventListener("close", onWsClose);
  webSocket.addEventListener("error", onWsClose);

  try {
    await remoteSocket.readable.pipeTo(
      new WritableStream({
        start() {},
        write(chunk, controller) {
          hasIncomingData = true;

          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket is closed");
            return;
          }

          try {
            if (!headerSent) {
              const combined = concatUint8Arrays(vlessResponseHeader, chunk);
              if (!safeWebSocketSend(webSocket, combined)) {
                controller.error("WebSocket send failed (backpressure or closed)");
                return;
              }
              headerSent = true;
            } else {
              if (!safeWebSocketSend(webSocket, chunk)) {
                controller.error("WebSocket send failed (backpressure or closed)");
                return;
              }
            }
          } catch (e) {
            controller.error(
              "WebSocket send failed: " + (e as Error).message
            );
          }
        },
        close() {
          log(
            `remoteConnection!.readable is closed with hasIncomingData is ${hasIncomingData}`
          );
        },
        abort(reason) {
          if (isNormalDisconnectError(reason)) {
            log("Remote read ended (client disconnected)");
          } else {
            console.error("remoteConnection!.readable abort", reason);
          }
        },
      }),
      { signal: abortController.signal }
    );
  } catch (error) {
    if (isNormalDisconnectError(error)) {
      log("Connection ended normally (client disconnected)");
    } else {
      console.error(
        "remoteSocketToWS has exception",
        (error as Error).stack || error
      );
    }
    safeCloseRemote(remoteSocket);
    safeCloseWebSocket(webSocket);
  } finally {
    try {
      webSocket.removeEventListener("close", onWsClose);
      webSocket.removeEventListener("error", onWsClose);
    } catch (_) {
      /* ignore */
    }
  }

  if (hasIncomingData === false && retry) {
    log(`retry — no incoming data from remote`);
    await retry();
  }
}

// ─── Base64 Decoder ──────────────────────────────────────────────────
function base64ToArrayBuffer(base64Str: string) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error: error };
  }
}

// ─── WebSocket Helpers ───────────────────────────────────────────────
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket: WebSocket) {
  try {
    if (
      socket.readyState === WS_READY_STATE_OPEN ||
      socket.readyState === WS_READY_STATE_CLOSING
    ) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

// ─── UUID Byte-to-Hex ────────────────────────────────────────────────
const byteToHex: string[] = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr: Uint8Array, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    "-" +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    "-" +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    "-" +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    "-" +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr: Uint8Array, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}

// ─── UDP Outbound (DNS only — with caching + fallback DoH) ──────────
async function handleUDPOutBound(
  webSocket: WebSocket,
  vlessResponseHeader: Uint8Array,
  log: (info: string) => void
) {
  let isVlessHeaderSent = false;

  const transformStream = new TransformStream({
    start(_controller) {},
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        if (index + 2 > chunk.byteLength) {
          console.error("UDP: not enough data for length header");
          break;
        }
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        if (
          udpPacketLength === 0 ||
          index + 2 + udpPacketLength > chunk.byteLength
        ) {
          console.error("UDP: invalid packet length or exceeds buffer");
          break;
        }
        const udpData = new Uint8Array(
          chunk.slice(index + 2, index + 2 + udpPacketLength)
        );
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
    flush(_controller) {},
  });

  // DNS query with DoH fallback providers
  async function queryDoH(dnsPayload: Uint8Array): Promise<ArrayBuffer> {
    // Create a cache key from the DNS query
    const cacheKey = btoa(String.fromCharCode(...dnsPayload.slice(0, Math.min(dnsPayload.length, 64))));
    const cached = getCachedDNS(cacheKey);
    if (cached) {
      log("DNS cache hit");
      return cached;
    }

    let lastError: Error | undefined;
    for (const provider of DOH_PROVIDERS) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), DOH_TIMEOUT);
        const resp = await fetch(provider, {
          method: "POST",
          headers: { "content-type": "application/dns-message" },
          body: dnsPayload,
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

        if (!resp.ok) {
          throw new Error(`DoH provider ${provider} returned ${resp.status}`);
        }

        const result = await resp.arrayBuffer();
        // Cache the result
        setCachedDNS(cacheKey, result);
        return result;
      } catch (e) {
        lastError = e as Error;
        log(`DoH provider ${provider} failed: ${lastError.message}`);
      }
    }
    throw lastError || new Error("All DoH providers failed");
  }

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          try {
            const dnsQueryResult = await queryDoH(chunk);
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([
              (udpSize >> 8) & 0xff,
              udpSize & 0xff,
            ]);
            if (webSocket.readyState === WS_READY_STATE_OPEN) {
              log(`doh success and dns message length is ${udpSize}`);
              const dnsResultArray = new Uint8Array(dnsQueryResult);
              if (isVlessHeaderSent) {
                safeWebSocketSend(
                  webSocket,
                  concatUint8Arrays(udpSizeBuffer, dnsResultArray)
                );
              } else {
                safeWebSocketSend(
                  webSocket,
                  concatUint8Arrays(
                    vlessResponseHeader,
                    udpSizeBuffer,
                    dnsResultArray
                  )
                );
                isVlessHeaderSent = true;
              }
            }
          } catch (e) {
            log(`DNS query failed: ${(e as Error).message}`);
          }
        },
      })
    )
    .catch((error) => {
      log("dns udp has error: " + error);
    });

  const writer = transformStream.writable.getWriter();
  return {
    write(chunk: Uint8Array) {
      writer.write(chunk);
    },
  };
}
