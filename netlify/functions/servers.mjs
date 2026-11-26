
const COOKIE = "vyora_admin_session";
const SESSION_SECONDS = 8 * 60 * 60;
const encoder = new TextEncoder();

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...headers
    }
  });

const base64url = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

const fromBase64url = (value) => {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
};

const getKey = (secret) =>
  crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

const createSession = async (secret) => {
  const payload = base64url(
    encoder.encode(JSON.stringify({
      exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS
    }))
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    await getKey(secret),
    encoder.encode(payload)
  );

  return `${payload}.${base64url(signature)}`;
};

// Returns null when valid, otherwise a safe diagnostic reason.
const verifySession = async (token, secret) => {
  try {
    const parts = token.split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return "malformed_cookie";
    }

    const [payload, signature] = parts;

    const valid = await crypto.subtle.verify(
      "HMAC",
      await getKey(secret),
      fromBase64url(signature),
      encoder.encode(payload)
    );

    if (!valid) return "invalid_signature";

    const data = JSON.parse(
      new TextDecoder().decode(fromBase64url(payload))
    );

    if (typeof data.exp !== "number") return "invalid_payload";
    if (data.exp <= Math.floor(Date.now() / 1000)) return "session_expired";

    return null;
  } catch {
    return "verification_error";
  }
};

const getToken = (request) =>
  (request.headers.get("Cookie") || "")
    .split(";")
    .map(v => v.trim())
    .find(v => v.startsWith(`${COOKIE}=`))
    ?.slice(COOKIE.length + 1) || null;

const safeEqual = (a, b) => {
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  if (x.length !== y.length) return false;

  let result = 0;
  for (let i = 0; i < x.length; i++) result |= x[i] ^ y[i];
  return result === 0;
};

const authorize = async (request, secret) => {
  const token = getToken(request);
  if (!token) return "cookie_missing";
  return await verifySession(token, secret);
};

export default async (request) => {
  const url = new URL(request.url);
  const method = request.method;

  const password = process.env.VYORA_PANEL_PASSWORD;
  const sessionSecret = process.env.VYORA_SESSION_SECRET;
  const apiKey = process.env.VYORA_ADMIN_KEY;

  if (!password || !sessionSecret || !apiKey) {
    return json({ error: "Server configuration missing" }, 500);
  }

  if (!["GET", "POST", "DELETE"].includes(method)) {
    return json({ error: "Method not allowed" }, 405);
  }

  if (method === "POST") {
    const raw = await request.text();

    if (raw.length > 10000) {
      return json({ error: "Payload too large" }, 413);
    }

    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      return json({ error: "Invalid JSON" }, 400);
    }

    if (body.action === "login") {
      if (!safeEqual(String(body.password || ""), password)) {
        return json({ error: "Invalid credentials" }, 401);
      }

      const token = await createSession(sessionSecret);

      return json(
        { success: true },
        200,
        {
          "Set-Cookie":
            `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/.netlify/functions/servers; Max-Age=${SESSION_SECONDS}`
        }
      );
    }

    if (body.action === "logout") {
      return json(
        { success: true },
        200,
        {
          "Set-Cookie":
            `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/.netlify/functions/servers; Max-Age=0`
        }
      );
    }

    const reason = await authorize(request, sessionSecret);
    if (reason) {
      return json({ error: "Unauthorized", reason }, 401);
    }

    delete body.action;
    return proxyRequest(method, url, body, apiKey);
  }

  const reason = await authorize(request, sessionSecret);
  if (reason) {
    return json({ error: "Unauthorized", reason }, 401);
  }

  return proxyRequest(method, url, null, apiKey);
};

async function proxyRequest(method, url, body, apiKey) {
  const apiUrl = new URL(
    "https://vyora-api.artyzuxi.workers.dev/admin/servers"
  );

  if (method === "DELETE") {
    apiUrl.search = url.search;
  }

  try {
    const response = await fetch(apiUrl, {
      method,
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        ...(body ? { "Content-Type": "application/json" } : {})
      },
      ...(body ? { body: JSON.stringify(body) } : {})
    });

    return new Response(await response.text(), {
      status: response.status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
      }
    });
  } catch {
    return json({ error: "API connection failed" }, 502);
  }
}
