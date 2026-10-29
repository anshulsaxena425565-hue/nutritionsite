import proxy from "../lib/platform-proxy.js";

const ROUTES = new Set([
  "practices/public", "auth/register", "auth/login", "auth/me", "auth/logout",
  "dietitians/directory", "dietitian/patients", "dietitian/plans",
  "dietitian/conversations", "dietitian/messages", "dietitian/appointments",
  "client/diet-plans", "dietitian/profile", "dietitian/requests",
  "admin/practices", "admin/dietitians", "admin/applicants", "admin/applicants/approve",
  "practice/members", "practice/invitations", "practice/invitations/accept",
  "admin/dietitians/verification"
]);

export default function handler(req, res) {
  const path = Array.isArray(req.query?.path) ? req.query.path.join("/") : String(req.query?.path || "");
  const endpoint = path.replace(/^\\/+|\\/+$/g, "");
  const allowed = endpoint && (ROUTES.has(endpoint) ||
    /^dietitian\\/requests\\/[a-f0-9-]+\\/decision$/.test(endpoint) ||
    /^admin\\/practices\\/[a-f0-9-]+\\/status$/.test(endpoint) ||
    /^admin\\/dietitians\\/[a-f0-9-]+\\/verification$/.test(endpoint));
  if (!allowed) return res.status(404).json({success:false,message:"API route not found.",path:"/"+endpoint});
  return proxy(req, res, "/"+endpoint);
}
