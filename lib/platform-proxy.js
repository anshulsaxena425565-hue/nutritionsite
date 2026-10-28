export default async function proxy(req,res,endpoint) {
  res.setHeader("Cache-Control","no-store");
  res.setHeader("X-Content-Type-Options","nosniff");
  const target=new URL("https://prachi-nutrition-api.prachisayani-api.workers.dev"+endpoint);
  const source=new URL(req.url||"/","https://local.invalid");
  for(const [k,v] of source.searchParams.entries()) target.searchParams.append(k,v);
  const headers={Accept:"application/json"};
  if(req.headers["content-type"]) headers["Content-Type"]=req.headers["content-type"];
  if(req.headers.cookie) headers.Cookie=req.headers.cookie;
  if(req.headers["x-bootstrap-secret"]) headers["X-Bootstrap-Secret"]=req.headers["x-bootstrap-secret"];
  let body;
  if(!["GET","HEAD"].includes(req.method)) body=typeof req.body==="string"?req.body:JSON.stringify(req.body??{});
  try {
    const upstream=await fetch(target,{method:req.method,headers,body,signal:AbortSignal.timeout(15000)});
    const text=await upstream.text();
    const setCookie=upstream.headers.get("set-cookie"); if(setCookie)res.setHeader("Set-Cookie",setCookie);
    res.status(upstream.status);res.setHeader("Content-Type",upstream.headers.get("content-type")||"application/json; charset=utf-8");
    return res.send(text);
  } catch { return res.status(503).json({success:false,message:"Practice service temporarily unavailable."}); }
}
