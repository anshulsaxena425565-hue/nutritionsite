export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  const rawPath = Array.isArray(req.query.path) ? req.query.path : [req.query.path].filter(Boolean);
  const path = "/" + rawPath.map(part => encodeURIComponent(String(part))).join("/");
  const target = new URL(path, "https://prachi-nutrition-api.prachisayani-api.workers.dev");
  for (const [key, value] of Object.entries(req.query || {})) {
    if (key === "path" || value == null) continue;
    for (const v of Array.isArray(value) ? value : [value]) target.searchParams.append(key, String(v));
  }
  const headers = { Accept: "application/json" };
  if (req.headers["content-type"]) headers["Content-Type"] = req.headers["content-type"];
  if (req.headers.cookie) headers.Cookie = req.headers.cookie;
  if (req.headers["x-bootstrap-secret"]) headers["X-Bootstrap-Secret"] = req.headers["x-bootstrap-secret"];
  let body;
  if (!["GET", "HEAD"].includes(req.method)) body = typeof req.body === "string" ? req.body : JSON.stringify(req.body ?? {});
  try {
    const upstream = await fetch(target, { method: req.method, headers, body, signal: AbortSignal.timeout(15000) });
    const text = await upstream.text();
    const setCookie = upstream.headers.get("set-cookie");
    if (setCookie) res.setHeader("Set-Cookie", setCookie);
    res.status(upstream.status);
    res.setHeader("Content-Type", upstream.headers.get("content-type") || "application/json; charset=utf-8");
    return res.send(text);
  } catch {
    return res.status(503).json({ success: false, message: "Practice service temporarily unavailable." });
  }
}
