const https = require("https");
const crypto = require("crypto");

// ─── SERVER-SIDE SECRETS (never sent to browser) ─────────────────────────────
const SECRET_CODE = "5EH9HGBN8I9UEWRN-0w-99R0-er-gr9-br";
const FIREBASE_URL = "https://new-fixed-default-rtdb.firebaseio.com";
const SESSION_KEY = "X9zKpQ2mLvTr7nYw";
// ─────────────────────────────────────────────────────────────────────────────

// ── Firebase helper ───────────────────────────────────────────────────────────
function firebase(method, path, data) {
  return new Promise((resolve, reject) => {
    const payload = data !== undefined ? JSON.stringify(data) : null;
    const url = new URL(FIREBASE_URL + path + ".json");
    const opts = {
      hostname: url.hostname,
      path: url.pathname + url.search,
      method,
      headers: {
        "Content-Type": "application/json",
        ...(payload ? { "Content-Length": Buffer.byteLength(payload) } : {}),
      },
    };
    const req = https.request(opts, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        let parsed;
        try { parsed = JSON.parse(body); } catch { parsed = body; }

        // Firebase returns non-2xx status codes (401 for rule violations,
        // 400 for bad data, etc.) along with an { error: "..." } body.
        // Previously this was never checked, so a denied write/delete
        // resolved normally and got reported to the client as a success.
        if (res.statusCode < 200 || res.statusCode >= 300) {
          const message =
            parsed && typeof parsed === "object" && parsed.error
              ? parsed.error
              : `Firebase request failed with status ${res.statusCode}`;
          return reject(new Error(message));
        }
        resolve(parsed);
      });
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// ── Token helpers (HMAC-signed, stored in localStorage, sent as Bearer) ───────
function makeToken() {
  const ts = Date.now().toString();
  const sig = crypto.createHmac("sha256", SESSION_KEY).update(ts).digest("hex");
  return `${ts}.${sig}`;
}

function verifyToken(token) {
  if (!token) return false;
  const [ts, sig] = token.split(".");
  if (!ts || !sig) return false;
  const expected = crypto.createHmac("sha256", SESSION_KEY).update(ts).digest("hex");
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  } catch { return false; }
  if (Date.now() - parseInt(ts) > 86400000 * 30) return false;
  return true;
}

// ── CORS / response helpers ───────────────────────────────────────────────────
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json",
};

function json(statusCode, body, extraHeaders = {}) {
  return { statusCode, headers: { ...CORS, ...extraHeaders }, body: JSON.stringify(body) };
}

function getToken(event) {
  const auth = event.headers.authorization || "";
  return auth.startsWith("Bearer ") ? auth.slice(7) : null;
}

// ── Main handler ──────────────────────────────────────────────────────────────
exports.handler = async (event) => {
  const method = event.httpMethod;
  const path   = event.path.replace(/^\/\.netlify\/functions\/api/, "").replace(/^\/api/, "") || "/";
  const authed = verifyToken(getToken(event));

  if (method === "OPTIONS") return { statusCode: 204, headers: CORS, body: "" };

  // ══ POST /auth ══════════════════════════════════════════════════════════
  if (method === "POST" && path === "/auth") {
    let body;
    try { body = JSON.parse(event.body || "{}"); } catch { body = {}; }
    if (body.code !== SECRET_CODE) return json(401, { success: false, message: "Invalid code" });
    return json(200, { success: true, token: makeToken() });
  }

  // ══ GET /session ════════════════════════════════════════════════════════
  if (method === "GET" && path === "/session") {
    return json(200, { authenticated: authed });
  }

  // ══ GET /portfolio (public) ══════════════════════════════════════════════
  if (method === "GET" && path === "/portfolio") {
    try {
      const data = await firebase("GET", "/portfolio");
      const items =
        data && typeof data === "object"
          ? Object.entries(data)
              .map(([id, val]) => ({ id, ...val }))
              .sort((a, b) => (a.order || 0) - (b.order || 0))
          : [];
      return json(200, { items });
    } catch (err) {
      return json(500, { error: err.message || "Database error" });
    }
  }

  // ── Auth-required routes ─────────────────────────────────────────────────
  if (!authed) return json(401, { error: "Unauthorized" });

  // ══ POST /portfolio ══════════════════════════════════════════════════════
  if (method === "POST" && path === "/portfolio") {
    let body;
    try { body = JSON.parse(event.body || "{}"); } catch { body = {}; }
    const item = { ...body, publishedAt: Date.now() };
    delete item.id;
    try {
      const result = await firebase("POST", "/portfolio", item);
      if (!result || !result.name) {
        return json(500, { error: "Firebase did not return a new item id" });
      }
      return json(200, { success: true, id: result.name });
    } catch (err) {
      return json(500, { error: err.message || "Database error" });
    }
  }

  // ══ PUT /portfolio/:id ═══════════════════════════════════════════════════
  if (method === "PUT" && path.startsWith("/portfolio/")) {
    const id = path.replace("/portfolio/", "");
    let body;
    try { body = JSON.parse(event.body || "{}"); } catch { body = {}; }
    try {
      await firebase("PATCH", `/portfolio/${id}`, body);
      return json(200, { success: true });
    } catch (err) {
      return json(500, { error: err.message || "Database error" });
    }
  }

  // ══ DELETE /portfolio/:id ════════════════════════════════════════════════
  if (method === "DELETE" && path.startsWith("/portfolio/")) {
    const id = path.replace("/portfolio/", "");
    try {
      await firebase("DELETE", `/portfolio/${id}`);
      return json(200, { success: true });
    } catch (err) {
      return json(500, { error: err.message || "Database error" });
    }
  }

  return json(404, { error: "Not found" });
};
