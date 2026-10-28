export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  // Prefer the actual request URL; Vercel's catch-all query shape can vary.
  const requestUrl = new URL(req.url || "/", "https://local.invalid");
  const prefix = "/api/platform";
  let suffix = requestUrl.pathname.startsWith(prefix) ? requestUrl.pathname.slice(prefix.length) : "";
  if (!suffix || suffix === "/") {
    const raw = req.query?.path;
    const parts = Array.isArray(raw) ? raw : raw ? [raw] : [];
    suffix = parts.length ? "/" + parts.map(v => encodeURIComponent(String(v))).join("/") : "";
  }
  if (!suffix || suffix === "/") return res.status(404).json({success:false,message:"API route not found."});
  const target = new URL("https://prachi-nutrition-api.prachisayani-api.workers.dev" + suffix);
  for (const [key, value] of requestUrl.searchParams.entries()) target.searchParams.append(key, value);
  for (const [key, value] of Object.entries(req.query || {})) {
    if (key === "path" || value == null || requestUrl.searchParams.has(key)) continue;
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
