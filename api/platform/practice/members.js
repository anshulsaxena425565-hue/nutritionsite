import proxy from "../../../lib/platform-proxy.js";
export default function handler(req,res) {
  if(req.method!=="GET") {res.setHeader("Allow","GET"); return res.status(405).json({success:false,message:"Method not allowed."});} return proxy(req,res,"/practice/members");
}
