export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ success: false, message: "Method not allowed." });
  }

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch {
      return res.status(400).json({ success: false, message: "Invalid form submission." });
    }
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return res.status(400).json({ success: false, message: "Invalid form submission." });
  }

  const clean = (value, max = 1000) =>
    String(value ?? "").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, " ").trim().slice(0, max);

  const email = clean(body.email || body.Email || body.jEmail, 254);
  const name = clean(body.name || body.Name || body.jName, 120);
  if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, message: "Please enter a valid name and email address." });
  }

  try {
    const response = await fetch("https://prachi-nutrition-api.prachisayani-api.workers.dev/api/enquiry", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000)
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.success !== true) {
      return res.status(response.status >= 400 && response.status < 600 ? response.status : 502).json({
        success: false,
        message: data.message || "We could not save your enquiry right now. Please try again or email prachisayani14@gmail.com."
      });
    }

    return res.status(200).json({
      success: true,
      message: "Thank you. Your enquiry has been received.",
      reference: data.reference
    });
  } catch (error) {
    // Deliberately avoid logging enquiry contents or personal data.
    return res.status(503).json({
      success: false,
      message: "The enquiry service is temporarily unavailable. Please try again or email prachisayani14@gmail.com."
    });
  }
}
