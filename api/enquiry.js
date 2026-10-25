export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ success: false, message: "Method not allowed." });
  }

  if (!process.env.RESEND_API_KEY) {
    return res.status(503).json({
      success: false,
      message: "Email service is not configured yet. Please email prachisayani14@gmail.com directly."
    });
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
    String(value ?? "").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "").trim().slice(0, max);

  const fields = Object.entries(body)
    .filter(([key]) => !key.startsWith("_") && key !== "website")
    .map(([key, value]) => [clean(key, 80), clean(value, 2000)])
    .filter(([key, value]) => key && value);

  const email = clean(body.email || body.Email || body.jEmail, 254);
  const name = clean(body.name || body.Name || body.jName, 120);

  if (!name || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, message: "Please enter a valid name and email address." });
  }

  const subject = clean(body._subject || body.subject || "New website enquiry", 140);
  const escapeHtml = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  const rows = fields.map(([key, value]) =>
    '<tr><th align="left" style="padding:8px;border-bottom:1px solid #eee;vertical-align:top">' +
    escapeHtml(key) + '</th><td style="padding:8px;border-bottom:1px solid #eee;white-space:pre-wrap">' +
    escapeHtml(value) + '</td></tr>'
  ).join("");

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + process.env.RESEND_API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: process.env.RESEND_FROM_EMAIL || "Prachi Website <diet@prachisayani.online>",
        to: ["prachisayani14@gmail.com"],
        reply_to: email,
        subject,
        html: '<div style="font-family:Arial,sans-serif;color:#21352b"><h2>New website enquiry</h2><p>A visitor submitted the website form.</p><table style="border-collapse:collapse;width:100%;max-width:700px">' + rows + '</table></div>',
        text: "New website enquiry\\n\\n" + fields.map(([key, value]) => key + ": " + value).join("\\n")
      })
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      console.error("Resend API error:", response.status, data?.message || data?.name || "unknown error");
      return res.status(502).json({
        success: false,
        message: response.status === 401 || response.status === 403
          ? "Email service rejected its API key. Check RESEND_API_KEY in Vercel."
          : "Email service could not send the enquiry. Check the Resend sender/domain configuration and try again."
      });
    }

    return res.status(200).json({ success: true, message: "Enquiry sent.", id: data.id });
  } catch (error) {
    console.error("Enquiry email request failed:", error?.message || "unknown error");
    return res.status(502).json({ success: false, message: "Could not reach the email service. Please try again shortly." });
  }
}
