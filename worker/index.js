const ORIGIN_ALLOWLIST = new Set(["https://prachisayani.online", "https://www.prachisayani.online"]);
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...headers } });
const id = () => crypto.randomUUID();
const hex = (b) => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const hash = async (s) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
const randomToken = (n = 32) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return [...b].map(x => x.toString(16).padStart(2, "0")).join(""); };
const clean = (v, n = 200) => String(v ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, n);
const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 254;
const now = () => new Date().toISOString();
function cors(request) {
  const origin = request.headers.get("Origin") || "";
  const h = { "Vary": "Origin", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Credentials": "true" };
  if (ORIGIN_ALLOWLIST.has(origin)) h["Access-Control-Allow-Origin"] = origin;
  return h;
}
function cookie(name, value, maxAge) { return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`; }
async function body(request) { const len = Number(request.headers.get("Content-Length") || 0); if (len > 16000) throw new Error("too_large"); const text = await request.text(); if (text.length > 16000) throw new Error("too_large"); return JSON.parse(text || "{}"); }
async function sendOtp(env, to, code) {
  if (!env.RESEND_API_KEY || !env.MAIL_FROM) throw new Error("email_not_configured");
  const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject: "Your secure sign-in code", text: `Your sign-in code is ${code}. It expires in 10 minutes. If you did not request this, you can ignore this email.`, html: `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px"><h2>Sign in securely</h2><p>Your one-time code is:</p><p style="font-size:32px;font-weight:700;letter-spacing:8px">${code}</p><p>This code expires in 10 minutes. Never share it with anyone.</p></div>` }) });
  if (!r.ok) throw new Error("email_send_failed");
}
async function getSession(request, env) {
  const raw = (request.headers.get("Cookie") || "").split(";").map(s => s.trim()).find(s => s.startsWith("pn_session="))?.slice("pn_session=".length);
  if (!raw) return null;
  const row = await env.DB.prepare("SELECT s.id AS session_id,s.user_id,s.expires_at,u.email,u.display_name,u.status FROM auth_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.status='active'").bind(await hash(raw), now()).first();
  if (!row) return null;
  const admin = await env.DB.prepare("SELECT status FROM platform_admins WHERE user_id=?").bind(row.user_id).first();
  const memberships = await env.DB.prepare("SELECT m.practice_id,m.role,m.status,p.name AS practice_name,p.slug AS practice_slug,p.status AS practice_status FROM practice_memberships m JOIN practices p ON p.id=m.practice_id WHERE m.user_id=? AND m.status='active' AND p.status='active' ORDER BY p.name").bind(row.user_id).all();
  return { ...row, is_platform_admin: admin?.status === "active", memberships: memberships.results || [] };
}
async function audit(env, actor, practiceId, action, resourceType, resourceId = null, metadata = {}) {
  await env.DB.prepare("INSERT INTO audit_logs(id,practice_id,actor_user_id,action,resource_type,resource_id,metadata_json) VALUES(?,?,?,?,?,?,?)").bind(id(), practiceId, actor, action, resourceType, resourceId, JSON.stringify(metadata)).run();
}
export default {
 async fetch(request, env) {
  const headers = cors(request);
  const origin = request.headers.get("Origin");
  if (origin && !ORIGIN_ALLOWLIST.has(origin)) return json({ success:false, message:"Origin not allowed." },403);
  if (request.method === "OPTIONS") return new Response(null,{status:204,headers});
  const url = new URL(request.url), path = url.pathname;
  try {
   if (path === "/health" && request.method === "GET") return json({ok:true,service:"prachi-nutrition-api",database:!!env.DB,authConfigured:!!(env.RESEND_API_KEY && env.MAIL_FROM),bootstrapConfigured:!!env.BOOTSTRAP_SECRET},200,headers);
   if (path === "/api/enquiry" && request.method === "POST") {
    const b = await body(request);
    if (clean(b.website,200)) return json({success:true,message:"Thank you. Your enquiry has been received."},200,headers);
    const name=clean(b.name||b.Name||b.jName,120), email=clean(b.email||b.Email||b.jEmail,254);
    if(!name||!emailOk(email)) return json({success:false,message:"Please enter a valid name and email address."},400,headers);
    const ref=id();
    await env.DB.prepare("INSERT INTO enquiries(id,name,email,phone,service,preferred_contact,goal,preferred_start,message,status,source) VALUES(?,?,?,?,?,?,?,?,?,'new',?)").bind(ref,name,email,clean(b.phone||b.jPhone,40),clean(b.service||b.service_name||b.journeyServiceName,160),clean(b.preferred_contact||b.jFormat,40),clean(b.goal||b.jGoal,1000),clean(b.preferred_start||b.jTimeline,120),clean(b.message||b.jContext,3000),"website").run();
    return json({success:true,message:"Thank you. Your enquiry has been received.",reference:ref},200,headers);
   }
   if (path === "/auth/request-code" && request.method === "POST") {
    const b=await body(request), email=clean(b.email,254).toLowerCase();
    if(!emailOk(email)) return json({success:false,message:"Enter a valid email address."},400,headers);
    const recent=await env.DB.prepare("SELECT created_at FROM auth_challenges WHERE email=? AND purpose='login' ORDER BY created_at DESC LIMIT 1").bind(email).first();
    if(recent && Date.now()-Date.parse(recent.created_at)<60000) return json({success:true,message:"If this email is eligible, a sign-in code will arrive shortly."},200,headers);
    // Do not disclose whether an account exists.
    const user=await env.DB.prepare("SELECT id,status FROM app_users WHERE email=? COLLATE NOCASE").bind(email).first();
    if(user && user.status==="active") {
      if(!env.RESEND_API_KEY||!env.MAIL_FROM) return json({success:false,message:"Secure sign-in email is not configured on the server yet."},503,headers);
      const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,"0"), challengeId=id(), salt=randomToken(16);
      await env.DB.prepare("INSERT INTO auth_challenges(id,email,purpose,code_hash,attempts,expires_at) VALUES(?,?, 'login', ?,0,?)").bind(challengeId,email,await hash(salt+":"+code),new Date(Date.now()+10*60*1000).toISOString()).run();
      try { await sendOtp(env,email,code); } catch { await env.DB.prepare("DELETE FROM auth_challenges WHERE id=?").bind(challengeId).run(); return json({success:false,message:"Could not send the sign-in email. Please try again later."},503,headers); }
      // Store salt with the hash to avoid storing the code itself.
      await env.DB.prepare("UPDATE auth_challenges SET code_hash=? WHERE id=?").bind(salt+":"+await hash(salt+":"+code),challengeId).run();
    }
    return json({success:true,message:"If this email is eligible, a sign-in code will arrive shortly."},200,headers);
   }
   if (path === "/auth/verify-code" && request.method === "POST") {
    const b=await body(request), email=clean(b.email,254).toLowerCase(), code=clean(b.code,6);
    if(!emailOk(email)||!/^\d{6}$/.test(code)) return json({success:false,message:"Invalid or expired code."},400,headers);
    const challenge=await env.DB.prepare("SELECT * FROM auth_challenges WHERE email=? AND purpose='login' AND consumed_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 1").bind(email,now()).first();
    if(!challenge||challenge.attempts>=5) return json({success:false,message:"Invalid or expired code."},400,headers);
    const [salt,stored]=challenge.code_hash.split(":");
    const valid=stored===await hash(salt+":"+code);
    if(!valid){await env.DB.prepare("UPDATE auth_challenges SET attempts=attempts+1 WHERE id=?").bind(challenge.id).run();return json({success:false,message:"Invalid or expired code."},400,headers);}
    const user=await env.DB.prepare("SELECT id FROM app_users WHERE email=? COLLATE NOCASE AND status='active'").bind(email).first();
    if(!user) return json({success:false,message:"Invalid or expired code."},400,headers);
    await env.DB.prepare("UPDATE auth_challenges SET consumed_at=? WHERE id=? AND consumed_at IS NULL").bind(now(),challenge.id).run();
    const raw=randomToken(32), expires=new Date(Date.now()+7*24*60*60*1000).toISOString();
    await env.DB.prepare("INSERT INTO auth_sessions(id,user_id,token_hash,expires_at,last_seen_at) VALUES(?,?,?,?,?)").bind(id(),user.id,await hash(raw),expires,now()).run();
    return json({success:true,message:"Signed in."},200,{...headers,"Set-Cookie":cookie("pn_session",raw,7*24*60*60)});
   }
   if (path === "/auth/logout" && request.method === "POST") {
    const raw=(request.headers.get("Cookie")||"").split(";").map(s=>s.trim()).find(s=>s.startsWith("pn_session="))?.slice(11);
    if(raw) await env.DB.prepare("UPDATE auth_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL").bind(now(),await hash(raw)).run();
    return json({success:true},200,{...headers,"Set-Cookie":cookie("pn_session","",0)});
   }
   if (path === "/auth/me" && request.method === "GET") {
    const s=await getSession(request,env); if(!s)return json({success:false,message:"Not signed in."},401,headers);
    return json({success:true,user:{id:s.user_id,email:s.email,display_name:s.display_name,is_platform_admin:s.is_platform_admin,memberships:s.memberships}},200,headers);
   }
   if (path === "/admin/bootstrap" && request.method === "POST") {
    if(!env.BOOTSTRAP_SECRET) return json({success:false,message:"Bootstrap is disabled until a server secret is configured."},503,headers);
    const b=await body(request), supplied=request.headers.get("X-Bootstrap-Secret")||b.bootstrap_secret||"";
    if(supplied.length<32 || supplied!==env.BOOTSTRAP_SECRET) return json({success:false,message:"Not authorized."},403,headers);
    const email=clean(b.email,254).toLowerCase(), displayName=clean(b.display_name,120);
    if(!emailOk(email)||!displayName) return json({success:false,message:"Valid email and display name required."},400,headers);
    const existingAdmin=await env.DB.prepare("SELECT user_id FROM platform_admins LIMIT 1").first();
    if(existingAdmin) return json({success:false,message:"Bootstrap has already been used."},409,headers);
    const user=await env.DB.prepare("SELECT id FROM app_users WHERE email=? COLLATE NOCASE").bind(email).first();
    const uid=user?.id||id();
    if(!user) await env.DB.prepare("INSERT INTO app_users(id,email,display_name,status) VALUES(?,?,?,'active')").bind(uid,email,displayName).run();
    await env.DB.prepare("INSERT INTO platform_admins(user_id,status) VALUES(?,'active')").bind(uid).run();
    await audit(env,uid,null,"platform_admin.bootstrap","user",uid);
    return json({success:true,message:"Super Admin allowlisted. Sign in using email code."},201,headers);
   }
   const session=await getSession(request,env);
   if(path.startsWith("/admin/")) {
    if(!session?.is_platform_admin) return json({success:false,message:"Platform administrator access required."},session?403:401,headers);
    if(path==="/admin/practices"&&request.method==="GET") {
      const rows=await env.DB.prepare("SELECT p.id,p.name,p.slug,p.status,p.timezone,p.currency,p.created_at,u.email AS owner_email FROM practices p LEFT JOIN app_users u ON u.id=p.owner_user_id ORDER BY p.created_at DESC LIMIT 200").all();
      return json({success:true,practices:rows.results||[]},200,headers);
    }
    if(path==="/admin/practices"&&request.method==="POST") {
      const b=await body(request),name=clean(b.name,120),slug=clean(b.slug,70).toLowerCase().replace(/[^a-z0-9-]/g,"-").replace(/-+/g,"-").replace(/^-|-$/g,"");
      if(name.length<2||slug.length<2) return json({success:false,message:"Practice name and valid slug required."},400,headers);
      const pid=id();
      try { await env.DB.prepare("INSERT INTO practices(id,name,slug,status) VALUES(?,?,?,'pending')").bind(pid,name,slug).run(); await env.DB.prepare("INSERT INTO practice_settings(practice_id) VALUES(?)").bind(pid).run(); await audit(env,session.user_id,pid,"practice.created","practice",pid); }
      catch { return json({success:false,message:"Could not create practice; the slug may already be in use."},409,headers); }
      return json({success:true,practice:{id:pid,name,slug,status:"pending"}},201,headers);
    }
    const match=path.match(/^\/admin\/practices\/([a-f0-9-]+)\/status$/);
    if(match&&request.method==="POST") {
      const b=await body(request),status=clean(b.status,20);
      if(!["active","suspended","closed","pending"].includes(status))return json({success:false,message:"Invalid practice status."},400,headers);
      const result=await env.DB.prepare("UPDATE practices SET status=?,updated_at=? WHERE id=?").bind(status,now(),match[1]).run();
      if(!result.meta?.changes)return json({success:false,message:"Practice not found."},404,headers);
      await audit(env,session.user_id,match[1],"practice.status_changed","practice",match[1],{status});
      return json({success:true},200,headers);
    }
   }
   if(path==="/practice/invitations"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),practiceId=clean(b.practice_id,80),email=clean(b.email,254).toLowerCase(),role=clean(b.role,20);
    const membership=session.memberships.find(m=>m.practice_id===practiceId&&["owner","admin"].includes(m.role));
    if(!membership)return json({success:false,message:"Practice owner/admin access required."},403,headers);
    if(!emailOk(email)||!["admin","dietitian","assistant","client"].includes(role))return json({success:false,message:"Valid email and permitted role required."},400,headers);
    const token=randomToken(32),inviteId=id(),expires=new Date(Date.now()+7*24*60*60*1000).toISOString();
    await env.DB.prepare("INSERT INTO practice_invitations(id,practice_id,email,role,invited_by_user_id,token_hash,expires_at) VALUES(?,?,?,?,?,?,?)").bind(inviteId,practiceId,email,role,session.user_id,await hash(token),expires).run();
    if(env.RESEND_API_KEY&&env.MAIL_FROM) {
      const acceptUrl="https://prachisayani.online/portal.html#invite="+encodeURIComponent(token);
      try { const r=await fetch("https://api.resend.com/emails",{method:"POST",headers:{Authorization:"Bearer "+env.RESEND_API_KEY,"Content-Type":"application/json"},body:JSON.stringify({from:env.MAIL_FROM,to:[email],subject:"Invitation to a nutrition practice",text:"You have been invited to join "+membership.practice_name+". Open this link to accept: "+acceptUrl,html:"<p>You have been invited to join <strong>"+membership.practice_name+"</strong>.</p><p><a href=\""+acceptUrl+"\">Accept invitation</a></p><p>This link expires in 7 days.</p>"})});if(!r.ok)throw new Error("send"); } catch { return json({success:false,message:"Invitation saved but email delivery failed; configure the Worker email secret before retrying."},503,headers); }
    } else return json({success:false,message:"Invitation saved but email delivery is not configured on the Worker."},503,headers);
    await audit(env,session.user_id,practiceId,"practice.invitation_sent","invitation",inviteId,{email,role});
    return json({success:true,message:"Invitation sent."},201,headers);
   }
   if(path==="/practice/invitations/accept"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),token=clean(b.token,128);
    if(token.length<32)return json({success:false,message:"Invalid or expired invitation."},400,headers);
    const invite=await env.DB.prepare("SELECT * FROM practice_invitations WHERE token_hash=? AND status='pending' AND expires_at>?").bind(await hash(token),now()).first();
    if(!invite||invite.email.toLowerCase()!==session.email.toLowerCase())return json({success:false,message:"Invalid or expired invitation."},400,headers);
    await env.DB.prepare("INSERT INTO practice_memberships(id,practice_id,user_id,role,status) VALUES(?,?,?,?, 'active') ON CONFLICT(practice_id,user_id) DO UPDATE SET role=excluded.role,status='active'").bind(id(),invite.practice_id,session.user_id,invite.role).run();
    if(invite.role==="dietitian") await env.DB.prepare("INSERT OR IGNORE INTO dietitian_profiles(id,practice_id,user_id) VALUES(?,?,?)").bind(id(),invite.practice_id,session.user_id).run();
    if(invite.role==="client") await env.DB.prepare("INSERT OR IGNORE INTO client_profiles(id,practice_id,user_id) VALUES(?,?,?)").bind(id(),invite.practice_id,session.user_id).run();
    await env.DB.prepare("UPDATE practice_invitations SET status='accepted',accepted_at=? WHERE id=?").bind(now(),invite.id).run();
    await audit(env,session.user_id,invite.practice_id,"practice.invitation_accepted","invitation",invite.id);
    return json({success:true,message:"Invitation accepted."},200,headers);
   }
   if(path==="/practice/members"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const practiceId=clean(url.searchParams.get("practice_id"),80);
    const membership=session.memberships.find(m=>m.practice_id===practiceId&&["owner","admin","dietitian"].includes(m.role));
    if(!membership)return json({success:false,message:"Practice membership required."},403,headers);
    const rows=await env.DB.prepare("SELECT u.id,u.email,u.display_name,m.role,m.status,m.created_at FROM practice_memberships m JOIN app_users u ON u.id=m.user_id WHERE m.practice_id=? AND m.status='active' ORDER BY m.created_at DESC LIMIT 200").bind(practiceId).all();
    return json({success:true,members:rows.results||[]},200,headers);
   }
   return json({success:false,message:"Not found."},404,headers);
  } catch (e) {
   if(e?.message==="too_large") return json({success:false,message:"Request too large."},413,headers);
   if(e instanceof SyntaxError) return json({success:false,message:"Invalid JSON."},400,headers);
   return json({success:false,message:"The service encountered an error. Please try again later."},500,headers);
  }
 }
};
