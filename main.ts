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
const TCP_KEEPALIVE_DELAY = 30; // seconds (used in setKeepAlive)
const WS_PING_INTERVAL = 25_000; // ms
const CONNECTION_TIMEOUT = 10_000; // ms — reduced from 15s for faster failover
const MAX_RETRY_ATTEMPTS = 2; // reduced from 3 for faster failover
const RETRY_BASE_DELAY = 500; // ms — reduced from 1000
const DNS_CACHE_TTL = 300_000; // ms
const DOH_TIMEOUT = 5000; // ms
const WS_BACKPRESSURE_HIGH = 4 * 1024 * 1024; // 4MB
const WS_BACKPRESSURE_CRITICAL = 16 * 1024 * 1024; // 16MB
const WS_BACKPRESSURE_WAIT = 50; // ms
const WS_BACKPRESSURE_MAX_RETRIES = 30;

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
  if (dnsCache.size > 1000) {
    const now = Date.now();
    for (const [k, v] of dnsCache) {
      if (now >= v.expiry) dnsCache.delete(k);
    }
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

// ─── HTML Escape ─────────────────────────────────────────────────────
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

// ─── Proxy IP Selection ─────────────────────────────────────────────
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

console.log(Deno.version);
console.log(`UUIDs in use: ${userIDs.map(maskUUID).join(", ")}`);
console.log(`WebSocket path: ${wsPath}`);
console.log(
  `Fixed Proxy IP: ${fixedProxyIP || "(none — direct connection)"}`
);

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
  for (const intervalId of activePingIntervals) {
    clearInterval(intervalId);
  }
  activePingIntervals.clear();
  for (const ws of activeWebSockets) {
    try {
      ws.close(1001, "Server shutting down");
    } catch (_) { /* ignore */ }
  }
  for (const conn of activeConnections) {
    try {
      conn.close();
    } catch (_) { /* ignore */ }
  }
  Deno.exit(0);
}

try {
  Deno.addSignalListener("SIGINT", () => gracefulShutdown("SIGINT"));
} catch (_) { /* ignore */ }
try {
  Deno.addSignalListener("SIGTERM", () => gracefulShutdown("SIGTERM"));
} catch (_) { /* ignore */ }

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
        const jitter = Math.random() * 0.3 + 0.85;
        const waitTime = Math.min(
          baseDelay * Math.pow(2, attempt - 1) * jitter,
          5000
        );
        log(
          `Attempt ${attempt}/${maxAttempts} failed: ${lastError.message}. Retrying in ${Math.round(waitTime)}ms...`
        );
        await delay(waitTime);
      }
    }
  }
  throw lastError;
}

// ─── Safe WebSocket Send with Async Backpressure Handling ─────────────
async function safeWebSocketSendAsync(
  ws: WebSocket,
  data: Uint8Array | ArrayBuffer
): Promise<boolean> {
  try {
    if (ws.readyState !== WS_READY_STATE_OPEN) {
      return false;
    }

    // Backpressure handling: wait if buffer is too large
    let retries = 0;
    while (
      ws.bufferedAmount > WS_BACKPRESSURE_HIGH &&
      retries < WS_BACKPRESSURE_MAX_RETRIES
    ) {
      await delay(WS_BACKPRESSURE_WAIT);
      retries++;
      if (ws.readyState !== WS_READY_STATE_OPEN) return false;
    }

    if (ws.bufferedAmount > WS_BACKPRESSURE_CRITICAL) {
      // Drop packet instead of closing connection
      return true;
    }

    ws.send(data);
    return true;
  } catch (_) {
    return false;
  }
}

function safeWebSocketSend(
  ws: WebSocket,
  data: Uint8Array | ArrayBuffer
): boolean {
  try {
    if (ws.readyState !== WS_READY_STATE_OPEN) return false;
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
        .config-box {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-top: 20px;
            text-align: left;
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
        }
        pre {
            margin: 0;
            white-space: pre-wrap;
            word-break: break-all;
            font-family: monospace;
            font-size: 0.85rem;
            color: #94a3b8;
        }
        .copy-btn {
            background: rgba(59, 130, 246, 0.1);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.2);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.8rem;
            cursor: pointer;
        }
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
                setTimeout(() => { btn.innerText = originalText; }, 2000);
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
    try {
      conn.setKeepAlive(true);
    } catch (_) { /* ignore */ }
    try {
      conn.setNoDelay(true);
    } catch (_) { /* ignore */ }
    return conn;
  } catch (e) {
    clearTimeout(timeoutId!);
    connPromise
      .then((c) => {
        try {
          c.close();
        } catch (_) { /* ignore */ }
      })
      .catch(() => {});
    throw e;
  }
}

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
    if (regex.test(address)) return false;
  }
  return true;
}

function startWebSocketHeartbeat(
  ws: WebSocket,
  log: (info: string, event?: string) => void
): number {
  const intervalId = setInterval(() => {
    if (ws.readyState !== WS_READY_STATE_OPEN) {
      clearInterval(intervalId);
      activePingIntervals.delete(intervalId);
      return;
    }
    if (ws.bufferedAmount > WS_BACKPRESSURE_HIGH) {
      log(
        `WebSocket heartbeat: high buffered amount (${ws.bufferedAmount}), possible slow network`
      );
    }
  }, WS_PING_INTERVAL);
  activePingIntervals.add(intervalId);
  return intervalId;
}

// ─── Main Server ─────────────────────────────────────────────────────
Deno.serve(async (request: Request) => {
  const url = new URL(request.url);

  const upgrade = request.headers.get("upgrade") || "";
  if (upgrade.toLowerCase() === "websocket") {
    if (url.pathname !== wsPath)
      return new Response("Not Found", { status: 404 });
    return await vlessOverWSHandler(request);
  }

  if (
    REQUIRE_HTTPS &&
    (url.pathname === "/config" || url.pathname === "/sub")
  ) {
    const httpsRedirect = requireHTTPS(request);
    if (httpsRedirect) return httpsRedirect;
  }

  if (url.pathname === "/health") {
    return secureResponse(
      JSON.stringify(
        {
          status: "ok",
          activeConnections: activeConnections.size,
          activeWebSockets: activeWebSockets.size,
        },
        null,
        2
      ),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  }

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
    return secureResponse(btoa(allLinks), {
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }

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
      userSections += `
        <div class="user-section">
            <span class="user-label">User ${index + 1}</span>
            <div class="config-box">
                <div class="config-header">
                    <span class="config-title">VLESS URI</span>
                    <button class="copy-btn" onclick="copyToClipboard('vless-uri-${index}', this)">Copy</button>
                </div>
                <pre id="vless-uri-${index}">${escapeHtml(vlessLink)}</pre>
            </div>
        </div>`;
    });

    const content = `<h1>Server Configuration</h1>${userSections}`;
    return secureResponse(getHtml("VLESS Config", content), {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  if (url.pathname === "/") {
    return secureResponse(
      getHtml(
        "NovaByte Cloud",
        "<h1>NovaByte Cloud</h1><p>Running Smoothly</p>"
      ),
      {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      }
    );
  }

  return secureResponse(getHtml("404", "<h1>404 Not Found</h1>"), {
    status: 404,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
});

// ─── VLESS over WebSocket Handler ────────────────────────────────────
async function vlessOverWSHandler(request: Request) {
  const { socket, response } = Deno.upgradeWebSocket(request, {
    idleTimeout: 120,
  });
  let address = "";
  let portWithRandomLog = "";
  let heartbeatIntervalId: number | undefined;
  let cleanedUp = false;

  const log = (info: string, _event = "") => {
    // Uncomment for debugging:
    // console.log(`[${address}:${portWithRandomLog}] ${info}`, _event);
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
    if (cleanedUp) return;
    cleanedUp = true;
    if (heartbeatIntervalId !== undefined) {
      clearInterval(heartbeatIntervalId);
      activePingIntervals.delete(heartbeatIntervalId);
      heartbeatIntervalId = undefined;
    }
    safeCloseRemote(remoteSocketWrapper.value);
    remoteSocketWrapper.value = null;
    untrackWebSocket(socket);
  };

  trackWebSocket(socket);

  socket.addEventListener("open", () => {
    heartbeatIntervalId = startWebSocketHeartbeat(socket, log);
  });
  socket.addEventListener("close", cleanupAll);
  socket.addEventListener("error", cleanupAll);

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDns && udpStreamWrite) return udpStreamWrite(chunk);
          if (remoteSocketWrapper.value) {
            // FIX #1: Direct write instead of repeated getWriter/releaseLock
            try {
              const writer = remoteSocketWrapper.value.writable.getWriter();
              try {
                await writer.write(new Uint8Array(chunk));
              } finally {
                writer.releaseLock();
              }
            } catch (e) {
              log(`TCP write failed: ${(e as Error).message}`);
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

          if (hasError) throw new Error(message);
          if (!isValidAddress(addressRemote))
            throw new Error(`Private address blocked`);
          if (isUDP && portRemote === 53) isDns = true;

          const vlessResponseHeader = new Uint8Array([
            vlessVersion[0],
            0,
          ]);
          const rawClientData = new Uint8Array(chunk.slice(rawDataIndex!));

          if (isDns) {
            const { write } = await handleUDPOutBound(
              socket,
              vlessResponseHeader,
              log
            );
            udpStreamWrite = write;
            udpStreamWrite(rawClientData);
            return;
          }

          // FIX #2: TCP outbound with proxy fallback
          await handleTCPOutBound(
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
          cleanupAll();
        },
        abort() {
          cleanupAll();
        },
      })
    )
    .catch((_err) => {
      cleanupAll();
      safeCloseWebSocket(socket);
    });

  return response;
}

function safeCloseRemote(conn: Deno.TcpConn | null): void {
  if (conn) {
    untrackConnection(conn);
    try {
      conn.close();
    } catch (_) { /* ignore */ }
  }
}

// ─── TCP Outbound with Proxy IP Fallback ─────────────────────────────
// FIX #3: Added proxy IP fallback - if direct connection fails, try via proxy
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

    // Write initial data directly
    const writer = tcpSocket.writable.getWriter();
    try {
      await writer.write(rawClientData);
    } finally {
      writer.releaseLock();
    }
    return tcpSocket;
  }

  // Helper to start streaming from remote to WS
  function startRemoteToWS(tcpSocket: Deno.TcpConn): void {
    remoteSocketToWS(
      tcpSocket,
      webSocket,
      vlessResponseHeader,
      log
    );
  }

  try {
    // Attempt 1: Direct connection to the target
    const tcpSocket = await retryWithBackoff(
      () => connectAndWrite(addressRemote, portRemote),
      MAX_RETRY_ATTEMPTS,
      RETRY_BASE_DELAY,
      log
    );
    startRemoteToWS(tcpSocket);
  } catch (directError) {
    log(
      `Direct connection to ${addressRemote}:${portRemote} failed: ${(directError as Error).message}`
    );

    // Attempt 2: Try via proxy IP if configured
    const proxyIP = getFixedProxyIP();
    if (proxyIP && proxyIP !== addressRemote) {
      log(`Falling back to proxy IP: ${proxyIP}`);
      try {
        // Clean up the failed connection attempt
        safeCloseRemote(remoteSocket.value);
        remoteSocket.value = null;

        const tcpSocket = await retryWithBackoff(
          () => connectAndWrite(proxyIP, portRemote),
          MAX_RETRY_ATTEMPTS,
          RETRY_BASE_DELAY,
          log
        );
        startRemoteToWS(tcpSocket);
      } catch (proxyError) {
        log(
          `Proxy connection via ${proxyIP}:${portRemote} also failed: ${(proxyError as Error).message}`
        );
        safeCloseRemote(remoteSocket.value);
        remoteSocket.value = null;
        safeCloseWebSocket(webSocket);
      }
    } else {
      safeCloseRemote(remoteSocket.value);
      remoteSocket.value = null;
      safeCloseWebSocket(webSocket);
    }
  }
}

function makeReadableWebSocketStream(
  webSocketServer: WebSocket,
  earlyDataHeader: string,
  log: (info: string) => void
) {
  let readableStreamCancel = false;
  return new ReadableStream({
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
            .catch(() => {});
        }
      });
      webSocketServer.addEventListener("close", () => {
        if (readableStreamCancel) return;
        try {
          controller.close();
        } catch (_) { /* ignore */ }
      });
      webSocketServer.addEventListener("error", (err) => {
        try {
          controller.error(err);
        } catch (_) { /* ignore */ }
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    cancel(_reason) {
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
}

function processVlessHeader(
  vlessBuffer: ArrayBuffer,
  validUserIDs: string[]
) {
  if (vlessBuffer.byteLength < 24)
    return { hasError: true, message: "invalid data" };
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  const incomingUUID = stringify(
    new Uint8Array(vlessBuffer.slice(1, 17))
  ).toLowerCase();

  let isValidUser = false;
  for (const id of validUserIDs) {
    if (constantTimeEqual(id, incomingUUID)) isValidUser = true;
  }
  if (!isValidUser) return { hasError: true, message: "invalid user" };

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(
    vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
  )[0];
  const isUDP = command === 2;
  const portIndex = 18 + optLength + 1;
  const portRemote = new DataView(
    vlessBuffer.slice(portIndex, portIndex + 2)
  ).getUint16(0);
  const addressIndex = portIndex + 2;
  const addressType = new Uint8Array(
    vlessBuffer.slice(addressIndex, addressIndex + 1)
  )[0];
  let addressLength = 0,
    addressValueIndex = addressIndex + 1,
    addressValue = "";

  if (addressType === 1) {
    addressLength = 4;
    addressValue = new Uint8Array(
      vlessBuffer.slice(
        addressValueIndex,
        addressValueIndex + addressLength
      )
    ).join(".");
  } else if (addressType === 2) {
    addressLength = new Uint8Array(
      vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
    )[0];
    addressValueIndex += 1;
    addressValue = new TextDecoder().decode(
      vlessBuffer.slice(
        addressValueIndex,
        addressValueIndex + addressLength
      )
    );
  } else if (addressType === 3) {
    addressLength = 16;
    const dataView = new DataView(
      vlessBuffer.slice(
        addressValueIndex,
        addressValueIndex + addressLength
      )
    );
    const ipv6: string[] = [];
    for (let i = 0; i < 8; i++)
      ipv6.push(dataView.getUint16(i * 2).toString(16));
    addressValue = ipv6.join(":");
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

// ─── Remote Socket to WebSocket ──────────────────────────────────────
// FIX #4: Improved pipe with proper error handling and no retry-close confusion
async function remoteSocketToWS(
  remoteSocket: Deno.TcpConn,
  webSocket: WebSocket,
  vlessResponseHeader: Uint8Array,
  log: (info: string) => void
) {
  let headerSent = false;
  const abortController = new AbortController();

  const onWsClose = () => {
    try {
      abortController.abort();
    } catch (_) { /* ignore */ }
  };
  webSocket.addEventListener("close", onWsClose);
  webSocket.addEventListener("error", onWsClose);

  try {
    await remoteSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket is closed");
            return;
          }
          if (!headerSent) {
            const combined = concatUint8Arrays(
              vlessResponseHeader,
              chunk
            );
            const success = await safeWebSocketSendAsync(
              webSocket,
              combined
            );
            if (!success) {
              controller.error("WS send failed");
              return;
            }
            headerSent = true;
          } else {
            const success = await safeWebSocketSendAsync(
              webSocket,
              chunk
            );
            if (!success) {
              controller.error("WS send failed");
              return;
            }
          }
        },
      }),
      { signal: abortController.signal }
    );
  } catch (error) {
    if (!isNormalDisconnectError(error)) {
      log(`remoteSocketToWS error: ${(error as Error).message}`);
    }
  } finally {
    try {
      webSocket.removeEventListener("close", onWsClose);
    } catch (_) { /* ignore */ }
    try {
      webSocket.removeEventListener("error", onWsClose);
    } catch (_) { /* ignore */ }
    // FIX #5: Do NOT close the websocket here — let the client side manage its lifecycle.
    // Only close the remote TCP if it's still open.
    safeCloseRemote(remoteSocket);
  }
}

function base64ToArrayBuffer(base64Str: string) {
  if (!base64Str) return { error: null };
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    return {
      earlyData: Uint8Array.from(atob(base64Str), (c) =>
        c.charCodeAt(0)
      ).buffer,
      error: null,
    };
  } catch (error) {
    return { error: error };
  }
}

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
  } catch (_) { /* ignore */ }
}

const byteToHex: string[] = [];
for (let i = 0; i < 256; ++i)
  byteToHex.push((i + 256).toString(16).slice(1));

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
  return unsafeStringify(arr, offset);
}

async function handleUDPOutBound(
  webSocket: WebSocket,
  vlessResponseHeader: Uint8Array,
  log: (info: string) => void
) {
  let isVlessHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        if (index + 2 > chunk.byteLength) break;
        const udpPacketLength = new DataView(
          chunk.slice(index, index + 2)
        ).getUint16(0);
        if (
          udpPacketLength === 0 ||
          index + 2 + udpPacketLength > chunk.byteLength
        )
          break;
        controller.enqueue(
          new Uint8Array(
            chunk.slice(index + 2, index + 2 + udpPacketLength)
          )
        );
        index = index + 2 + udpPacketLength;
      }
    },
  });

  async function queryDoH(dnsPayload: Uint8Array): Promise<ArrayBuffer> {
    const cacheKey = btoa(
      String.fromCharCode(
        ...dnsPayload.slice(0, Math.min(dnsPayload.length, 64))
      )
    );
    const cached = getCachedDNS(cacheKey);
    if (cached) return cached;
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
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const result = await resp.arrayBuffer();
        setCachedDNS(cacheKey, result);
        return result;
      } catch (e) {
        lastError = e as Error;
      }
    }
    throw lastError || new Error("DoH failed");
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
            log(`DNS query error: ${(e as Error).message}`);
          }
        },
      })
    )
    .catch(() => {});
  const writer = transformStream.writable.getWriter();
  return {
    write(chunk: Uint8Array) {
      writer.write(chunk);
    },
  };
}
