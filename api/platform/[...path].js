import proxy from "../../lib/platform-proxy.js";

const ROUTES = new Set([
  "practices/public",
  "dietitians/directory",
  "dietitian/profile",
  "dietitian/requests",
  "admin/dietitians",
  "admin/applicants",
  "admin/applicants/approve",
  "practice/members",
  "practice/invitations/accept",
  "admin/dietitians/verification"
]);

export default function handler(req, res) {
  const path = Array.isArray(req.query?.path) ? req.query.path.join("/") : String(req.query?.path || "");
  const endpoint = path.replace(/^\/+|\/+$/g, "");
  const allowed = endpoint && (
    ROUTES.has(endpoint) ||
    /^dietitian\/requests\/[a-f0-9-]+\/decision$/.test(endpoint) ||
    /^admin\/practices\/[a-f0-9-]+\/status$/.test(endpoint) ||
    /^admin\/dietitians\/[a-f0-9-]+\/verification$/.test(endpoint)
  );
  if (!allowed) return res.status(404).json({success:false,message:"API route not found.",path:"/"+endpoint});
  return proxy(req, res, "/"+endpoint);
}
