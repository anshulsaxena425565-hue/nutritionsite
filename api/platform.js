import proxy from "../lib/platform-proxy.js";

const ROUTES = new Set([
  "practices/public", "auth/register", "auth/login", "auth/me", "auth/logout",
  "dietitians/directory", "dietitian/patients", "dietitian/plans",
  "dietitian/conversations", "dietitian/messages", "dietitian/appointments",
  "client/diet-plans", "dietitian/profile", "dietitian/requests",
  "admin/practices", "admin/dietitians", "admin/applicants", "admin/applicants/approve", "admin/users",
  "billing/plans", "billing/status", "billing/checkout", "admin/billing/overview", "admin/billing/plans", "admin/billing/subscriptions",
  "practice/members", "practice/invitations", "practice/invitations/accept",

]);

export default function handler(req, res) {
  const path = Array.isArray(req.query?.path) ? req.query.path.join("/") : String(req.query?.path || "");
  const endpoint = path.split("/").filter(Boolean).join("/");
  const allowed = endpoint && (ROUTES.has(endpoint) ||
    new RegExp("^dietitian/requests/[a-f0-9-]+/decision$").test(endpoint) ||
    new RegExp("^admin/practices/[a-f0-9-]+/status$").test(endpoint) ||
    new RegExp("^admin/users/[a-f0-9-]+$").test(endpoint) ||
    new RegExp("^admin/users/[a-f0-9-]+/status$").test(endpoint));
  if (!allowed) return res.status(404).json({success:false,message:"API route not found.",path:"/"+endpoint});
  return proxy(req, res, "/"+endpoint);
}
