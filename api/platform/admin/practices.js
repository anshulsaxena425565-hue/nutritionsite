import proxy from "../../../lib/platform-proxy.js";
export default function handler(req,res) {
  if(req.method==="GET") return proxy(req,res,"/admin/practices"); if(req.method==="POST") return proxy(req,res,"/admin/practices"); return res.status(405).json({success:false,message:"Method not allowed."});
}
