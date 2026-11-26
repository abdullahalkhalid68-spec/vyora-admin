
export default async (request) => {
  const json = (data, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json" }
    });

  const url = new URL(request.url);
  const method = request.method;

  const adminPassword = process.env.VYORA_PANEL_PASSWORD;
  const apiKey = process.env.VYORA_ADMIN_KEY;

  if (!adminPassword || !apiKey) {
    return json({ error: "Server configuration missing" }, 500);
  }

  if (!["GET", "POST", "DELETE"].includes(method)) {
    return json({ error: "Method not allowed" }, 405);
  }

  const auth = request.headers.get("Authorization");

  if (auth !== `Bearer ${adminPassword}`) {
    return json({ error: "Unauthorized" }, 401);
  }

  const apiUrl = new URL(
    "https://vyora-api.artyzuxi.workers.dev/admin/servers"
  );

  if (method === "DELETE") {
    apiUrl.search = url.search;
  }

  let body;

  if (method === "POST") {
    const text = await request.text();

    if (text.length > 10000) {
      return json({ error: "Payload too large" }, 413);
    }

    try {
      body = JSON.parse(text);
    } catch {
      return json({ error: "Invalid JSON" }, 400);
    }
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

    const result = await response.text();

    return new Response(result, {
      status: response.status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
      }
    });
  } catch {
    return json({ error: "API connection failed" }, 502);
  }
};
