import proxy from "../../../lib/platform-proxy.js";

export default function handler(req, res) {
  if (req.method !== "POST" && req.method !== "GET") {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).json({ success: false, message: "Method not allowed." });
  }
  return proxy(req, res, "/dietitian/profile");
}
