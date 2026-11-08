const ORIGIN_ALLOWLIST = new Set(["https://prachisayani.online", "https://www.prachisayani.online", "https://anshulsaxena425565-hue.github.io"]);
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()", "Cross-Origin-Opener-Policy": "same-origin", "Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", ...headers } });
const id = () => crypto.randomUUID();
const hex = (b) => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const hash = async (s) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
const randomToken = (n = 32) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return [...b].map(x => x.toString(16).padStart(2, "0")).join(""); };
const clean = (v, n = 200) => String(v ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, n);
const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 254;
const now = () => new Date().toISOString();
function cors(request) {
  const origin = request.headers.get("Origin") || "";
  const h = { "Vary": "Origin", "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, X-PN-CSRF", "Access-Control-Allow-Credentials": "true", "Access-Control-Max-Age": "600" };
  if (ORIGIN_ALLOWLIST.has(origin)) h["Access-Control-Allow-Origin"] = origin;
  return h;
}
const SESSION_TTL_SECONDS = 12 * 60 * 60;
const SESSION_TTL_MS = SESSION_TTL_SECONDS * 1000;
function cookie(name, value, maxAge) { return name+"="+value+"; Path=/; HttpOnly; Secure; SameSite=None; Max-Age="+maxAge; }
function createSessionCookie(raw) { return cookie("pn_session", raw, SESSION_TTL_SECONDS); }
function clearSessionCookie() { return cookie("pn_session", "", 0); }
function readSessionCookie(request) { return (request.headers.get("Cookie") || "").split(";").map(s => s.trim()).find(s => s.startsWith("pn_session="))?.slice("pn_session=".length) || ""; }
async function consumeRateLimit(env, scope, value, maxHits, windowMs) {
  if (!env.RATE_LIMIT_SECRET || String(env.RATE_LIMIT_SECRET).length < 32) throw new Error("rate_limit_not_configured");
  const windowStart = Math.floor(Date.now() / windowMs) * windowMs;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.RATE_LIMIT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const digest = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(scope+":"+value+":"+windowStart));
  const bucket = hex(digest);
  const row = await env.DB.prepare("INSERT INTO auth_rate_limits(bucket_key,window_start,expires_at,hits) VALUES(?,?,?,1) ON CONFLICT(bucket_key) DO UPDATE SET hits=hits+1 RETURNING hits").bind(bucket, windowStart, windowStart + windowMs).first();
  return Number(row?.hits || 0) > maxHits;
}
async function isAuthRateLimited(env, request, scope, identity, ipLimit, identityLimit, windowMs) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipLimited = await consumeRateLimit(env, scope+":ip", ip, ipLimit, windowMs);
  const identityLimited = identity ? await consumeRateLimit(env, scope+":identity", identity, identityLimit, windowMs) : false;
  return ipLimited || identityLimited;
}
async function body(request)async function body(request) { const len = Number(request.headers.get("Content-Length") || 0); if (len > 1600000) throw new Error("too_large"); const text = await request.text(); if (new TextEncoder().encode(text).byteLength > 1600000) throw new Error("too_large"); return JSON.parse(text || "{}"); }
async function sendOtp(env, to, code) {
  if (!env.RESEND_API_KEY || !env.MAIL_FROM) throw new Error("email_not_configured");
  const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject: "Your secure sign-in code", text: `Your sign-in code is ${code}. It expires in 10 minutes. If you did not request this, you can ignore this email.`, html: `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px"><h2>Sign in securely</h2><p>Your one-time code is:</p><p style="font-size:32px;font-weight:700;letter-spacing:8px">${code}</p><p>This code expires in 10 minutes. Never share it with anyone.</p></div>` }) });
  if (!r.ok) throw new Error("email_send_failed");
}
const PASSWORD_ITERATIONS = 600000;
async function derivePasswordBits(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256));
}
function constantTimeHexEqual(a, b) { if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false; let diff = 0; for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i); return diff === 0; }
async function passwordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derived = await derivePasswordBits(password, salt, PASSWORD_ITERATIONS);
  return "pbkdf2-sha256$"+PASSWORD_ITERATIONS+"$"+hex(salt)+"$"+derived;
}
async function passwordMatches(password, stored) {
  if (typeof stored !== "string") return { valid: false, needsUpgrade: false };
  if (stored.startsWith("pbkdf2-sha256$")) {
    const [algorithm, iterationsText, saltHex, expected] = stored.split("$");
    const iterations = Number(iterationsText);
    if (algorithm !== "pbkdf2-sha256" || !Number.isInteger(iterations) || iterations < 600000 || iterations > 2000000 || !/^[a-f0-9]{32}$/.test(saltHex || "") || !/^[a-f0-9]{64}$/.test(expected || "")) return { valid: false, needsUpgrade: false };
    const salt = Uint8Array.from(saltHex.match(/.{2}/g).map(x => parseInt(x, 16)));
    return { valid: constantTimeHexEqual(expected, await derivePasswordBits(password, salt, iterations)), needsUpgrade: false };
  }
  if (!stored.includes(":")) return { valid: false, needsUpgrade: false };
  const [saltHex, expected] = stored.split(":");
  if (!/^[a-f0-9]{32}$/.test(saltHex || "") || !/^[a-f0-9]{64}$/.test(expected || "")) return { valid: false, needsUpgrade: false };
  const salt = Uint8Array.from(saltHex.match(/.{2}/g).map(x => parseInt(x, 16)));
  return { valid: constantTimeHexEqual(expected, await derivePasswordBits(password, salt, 100000)), needsUpgrade: true };
}
function validPassword(p){return typeof p==="string" && p.length>=10 && p.length<=128 && /[A-Za-z]/.test(p) && /[0-9]/.test(p);}
async function establishSession(env,userId){
  const raw=randomToken(32), expires=new Date(Date.now()+SESSION_TTL_MS).toISOString();
  await env.DB.prepare("INSERT INTO auth_sessions(id,user_id,token_hash,expires_at,last_seen_at) VALUES(?,?,?,?,?)").bind(id(),userId,await hash(raw),expires,now()).run();
  return { token: raw, setCookie: createSessionCookie(raw) };
}
async function getSession(request, env) {
  const raw = readSessionCookie(request);
  if (!raw) return null;
async function getSession(request, env) {
  const bearer = request.headers.get("Authorization") || "";
  const raw = bearer.startsWith("Bearer ") ? bearer.slice(7).trim() : (request.headers.get("Cookie") || "").split(";").map(s => s.trim()).find(s => s.startsWith("pn_session="))?.slice("pn_session=".length);
  if (!raw) return null;
  const row = await env.DB.prepare("SELECT s.id AS session_id,s.user_id,s.expires_at,u.email,u.display_name,u.status,u.account_type FROM auth_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.status='active'").bind(await hash(raw), now()).first();
  if (!row) return null;
  const admin = await env.DB.prepare("SELECT status FROM platform_admins WHERE user_id=?").bind(row.user_id).first();
  const memberships = await env.DB.prepare("SELECT m.practice_id,m.role,m.status,p.name AS practice_name,p.slug AS practice_slug,p.status AS practice_status FROM practice_memberships m JOIN practices p ON p.id=m.practice_id WHERE m.user_id=? AND m.status='active' AND p.status='active' ORDER BY p.name").bind(row.user_id).all();
  return { ...row, is_platform_admin: admin?.status === "active", memberships: memberships.results || [] };
}
async function audit(env, actor, practiceId, action, resourceType, resourceId = null, metadata = {}) {
  await env.DB.prepare("INSERT INTO audit_logs(id,practice_id,actor_user_id,action,resource_type,resource_id,metadata_json) VALUES(?,?,?,?,?,?,?)").bind(id(), practiceId, actor, action, resourceType, resourceId, JSON.stringify(metadata)).run();
}
const PLAN_FEATURE_PATHS = {
  "/dietitian/plans": "diet_planning",
  "/dietitian/patients": "patient_management",
  "/dietitian/requests": "patient_management",
  "/dietitian/conversations": "client_communication",
  "/dietitian/messages": "client_communication",
  "/dietitian/appointments": "appointments",
  "/practice/invitations": "team_collaboration",
  "/practice/members": "team_collaboration"
};
const PLAN_FEATURE_KEYS = ["patient_management","diet_planning","client_communication","appointments","team_collaboration","advanced_analytics","data_export","advanced_tools","client_feedback"];
export default {
 async fetch(request, env) {
  const headers = cors(request);
  const origin = request.headers.get("Origin");
  if (origin && !ORIGIN_ALLOWLIST.has(origin)) return json({ success:false, message:"Origin not allowed." },403);
  if (request.method === "OPTIONS") return new Response(null,{status:204,headers});
  if (!["GET","HEAD"].includes(request.method) && (!origin || !ORIGIN_ALLOWLIST.has(origin) || request.headers.get("X-PN-CSRF") !== "1")) return json({ success:false, message:"Request origin verification failed." },403,headers);
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
   if (path === "/auth/register" && request.method === "POST") {
    const b=await body(request),name=clean(b.full_name,120),email=clean(b.email,254).toLowerCase(),phone=clean(b.mobile,24).replace(/[\\s()+.-]/g,""),password=b.password,accountType=b.account_type==="dietitian"?"dietitian":"client";
    if(!env.RATE_LIMIT_SECRET) return json({success:false,message:"Authentication protection is not configured. Please contact support."},503,headers);
    if(await isAuthRateLimited(env,request,"register",email,5,3,60*60*1000)) return json({success:false,message:"Too many account attempts. Please try again later."},429,{...headers,"Retry-After":"3600"});
    if(name.length<2||!emailOk(email)||!/^[0-9]{7,15}$/.test(phone)||!validPassword(password))
      return json({success:false,message:"Enter your name, a valid email, mobile number and a password of at least 10 characters containing letters and numbers."},400,headers);
    const existing=await env.DB.prepare("SELECT id FROM app_users WHERE email=? COLLATE NOCASE OR phone=? LIMIT 1").bind(email,phone).first();
    if(existing)return json({success:false,message:"An account already exists for that email or mobile. Sign in instead, or use account recovery."},409,headers);
    const userId=id(),stored=await passwordHash(password);
    await env.DB.prepare("INSERT INTO app_users(id,email,display_name,phone,password_hash,status,account_type) VALUES(?,?,?,?,?,'active',?)").bind(userId,email,name,phone,stored,accountType).run();
    const established=await establishSession(env,userId);
    await audit(env,userId,null,"auth.register","user",userId);
    return json({success:true,message:"Account created.",user:{id:userId,email,display_name:name,account_type:accountType}},201,{...headers,"Set-Cookie":established.setCookie});
   }
   if (path === "/auth/login" && request.method === "POST") {
    const b=await body(request),identifier=clean(b.identifier,254).toLowerCase(),password=b.password;
    if(!identifier||typeof password!=="string"||password.length>128)return json({success:false,message:"Enter your email/mobile and password."},400,headers);
    if(!env.RATE_LIMIT_SECRET) return json({success:false,message:"Authentication protection is not configured. Please contact support."},503,headers);
    if(await isAuthRateLimited(env,request,"login",identifier,30,8,15*60*1000)) return json({success:false,message:"Too many sign-in attempts. Please wait before trying again."},429,{...headers,"Retry-After":"900"});
    const user=await env.DB.prepare("SELECT id,email,display_name,status,password_hash,account_type FROM app_users WHERE (email=? COLLATE NOCASE OR phone=?) LIMIT 1").bind(identifier,identifier.replace(/[\\s()+.-]/g,"")).first();
    const passwordCheck = user && user.status==="active" ? await passwordMatches(password,user.password_hash) : {valid:false,needsUpgrade:false};
    if(!passwordCheck.valid)return json({success:false,message:"Email/mobile or password is incorrect."},401,headers);
    if(passwordCheck.needsUpgrade) await env.DB.prepare("UPDATE app_users SET password_hash=? WHERE id=?").bind(await passwordHash(password),user.id).run();
    const established=await establishSession(env,user.id);
    return json({success:true,message:"Signed in.",user:{id:user.id,email:user.email,display_name:user.display_name,account_type:user.account_type||"client"}},200,{...headers,"Set-Cookie":established.setCookie});
   }
   if (path === "/auth/request-code" && request.method === "POST") {
    const b=await body(request), email=clean(b.email,254).toLowerCase();
    if(!emailOk(email)) return json({success:false,message:"Enter a valid email address."},400,headers);
    if(!env.RATE_LIMIT_SECRET) return json({success:false,message:"Authentication protection is not configured. Please contact support."},503,headers);
    if(await isAuthRateLimited(env,request,"otp-request",email,5,3,60*60*1000)) return json({success:true,message:"If this email is eligible, a sign-in code will arrive shortly."},200,headers);
    const recent=await env.DB.prepare("SELECT created_at FROM auth_challenges WHERE email=? AND purpose='login' ORDER BY created_at DESC LIMIT 1").bind(email).first();
    if(recent && Date.now()-Date.parse(recent.created_at)<60000) return json({success:true,message:"If this email is eligible, a sign-in code will arrive shortly."},200,headers);
    const user=await env.DB.prepare("SELECT id,status FROM app_users WHERE email=? COLLATE NOCASE").bind(email).first();
    if(user && user.status==="active") {
      if(!env.RESEND_API_KEY||!env.MAIL_FROM) return json({success:false,message:"Secure sign-in email is not configured on the server yet."},503,headers);
      const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,"0"), challengeId=id(), salt=randomToken(16);
      await env.DB.prepare("INSERT INTO auth_challenges(id,email,purpose,code_hash,attempts,expires_at) VALUES(?,?, 'login', ?,0,?)").bind(challengeId,email,await hash(salt+":"+code),new Date(Date.now()+10*60*1000).toISOString()).run();
      try { await sendOtp(env,email,code); } catch { await env.DB.prepare("DELETE FROM auth_challenges WHERE id=?").bind(challengeId).run(); return json({success:false,message:"Could not send the sign-in email. Please try again later."},503,headers); }
      await env.DB.prepare("UPDATE auth_challenges SET code_hash=? WHERE id=?").bind(salt+":"+await hash(salt+":"+code),challengeId).run();
    }
    return json({success:true,message:"If this email is eligible, a sign-in code will arrive shortly."},200,headers);
   }
   if (path === "/auth/verify-code" && request.method === "POST") {
    const b=await body(request), email=clean(b.email,254).toLowerCase(), code=clean(b.code,6);
    if(!emailOk(email)||!/^\\d{6}$/.test(code)) return json({success:false,message:"Invalid or expired code."},400,headers);
    if(!env.RATE_LIMIT_SECRET) return json({success:false,message:"Authentication protection is not configured. Please contact support."},503,headers);
    if(await isAuthRateLimited(env,request,"otp-verify",email,20,5,15*60*1000)) return json({success:false,message:"Invalid or expired code."},429,{...headers,"Retry-After":"900"});
    const challenge=await env.DB.prepare("SELECT * FROM auth_challenges WHERE email=? AND purpose='login' AND consumed_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 1").bind(email,now()).first();
    if(!challenge||challenge.attempts>=5) return json({success:false,message:"Invalid or expired code."},400,headers);
    const [salt,stored]=challenge.code_hash.split(":");
    const valid=stored===await hash(salt+":"+code);
    if(!valid){await env.DB.prepare("UPDATE auth_challenges SET attempts=attempts+1 WHERE id=? AND attempts<5").bind(challenge.id).run();return json({success:false,message:"Invalid or expired code."},400,headers);}
    const user=await env.DB.prepare("SELECT id FROM app_users WHERE email=? COLLATE NOCASE AND status='active'").bind(email).first();
    if(!user) return json({success:false,message:"Invalid or expired code."},400,headers);
    const consumed=await env.DB.prepare("UPDATE auth_challenges SET consumed_at=? WHERE id=? AND consumed_at IS NULL AND expires_at>? AND attempts<5").bind(now(),challenge.id,now()).run();
    if(!consumed.meta?.changes) return json({success:false,message:"Invalid or expired code."},400,headers);
    const established=await establishSession(env,user.id);
    return json({success:true,message:"Signed in."},200,{...headers,"Set-Cookie":established.setCookie});
   }
   if (path === "/auth/logout" && request.method === "POST") {
    const raw=readSessionCookie(request);
    if(raw) await env.DB.prepare("UPDATE auth_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL").bind(now(),await hash(raw)).run();
    return json({success:true},200,{...headers,"Set-Cookie":clearSessionCookie()});
   }
   if (path === "/auth/me" && request.method === "GET") {
    const s=await getSession(request,env); if(!s)return json({success:false,message:"Not signed in."},401,headers);
    return json({success:true,user:{id:s.user_id,email:s.email,display_name:s.display_name,account_type:s.account_type||"client",is_platform_admin:s.is_platform_admin,memberships:s.memberships}},200,headers);
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
   if(path==="/theme"&&request.method==="GET"){await env.DB.prepare("CREATE TABLE IF NOT EXISTS platform_branding_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_by TEXT)").run();const row=await env.DB.prepare("SELECT setting_value FROM platform_branding_settings WHERE setting_key='primary_color'").first();return json({success:true,theme:{primary_color:row?.setting_value||"#5A52D5"}},200,headers)}
   const session=await getSession(request,env);
   // Entitlement switches are enforced server-side for mapped dietitian API features.
   // Keep the platform administrator exempt so they can always support and inspect accounts.
   const requiredPlanFeature=PLAN_FEATURE_PATHS[path]||(path.startsWith("/dietitian/requests/")?"patient_management":path.startsWith("/dietitian/patients/")?"patient_management":path==="/dietitian/patient-measurements"?"patient_management":path.startsWith("/practice/invitations/")?"team_collaboration":null);
   if(session?.account_type==="dietitian"&&!session.is_platform_admin&&requiredPlanFeature){
    const access=await env.DB.prepare("SELECT s.status,s.trial_ends_at,s.current_period_end,p.entitlements_json FROM dietitian_subscriptions s JOIN subscription_plans p ON p.id=s.plan_id WHERE s.user_id=?").bind(session.user_id).first();
    if(access&&["trialing","active","comped"].includes(access.status)){
     const end=access.status==="trialing"?access.trial_ends_at:access.current_period_end;
     const stillValid=!end||Date.parse(end)>Date.now();
     const entitlements=(()=>{try{return JSON.parse(access.entitlements_json||"{}")}catch{return {}}})();
     if(stillValid&&entitlements[requiredPlanFeature]===false)return json({success:false,message:"This feature is not included in your current plan. Ask your administrator to enable it or upgrade your plan.",feature:requiredPlanFeature},403,headers);
    }
   }
   // Authenticated dashboards read the role-specific global module switches here.
   // The Superadmin editor uses /admin/module-controls; client/dietitian navigation uses this route.
   if(path==="/module-controls"&&request.method==="GET"){
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const rows=await env.DB.prepare("SELECT user_type,module_key,enabled FROM platform_module_controls").all();
    const allSettings={};
    for(const row of rows.results||[]){allSettings[row.user_type]??={};allSettings[row.user_type][row.module_key]={enabled:!!row.enabled};}
    const userType=session.account_type==="dietitian"?(session.memberships||[]).some(m=>m.role==="dietitian"&&m.status==="active")?"dietitian":"dietitian_applicant":"client";
    return json({success:true,user_type:userType,settings:allSettings},200,headers);
   }
   if(path==="/billing/plans"&&request.method==="GET") {
    const rows=await env.DB.prepare("SELECT id,slug,name,description,price_minor,prices_minor_json,patient_limit,is_unlimited,trial_days,features_json,entitlements_json,is_active,is_featured,sort_order FROM subscription_plans WHERE is_active=1 ORDER BY sort_order,name").all();
    return json({success:true,plans:(rows.results||[]).map(p=>({...p,prices_minor:JSON.parse(p.prices_minor_json||"{}"),features:JSON.parse(p.features_json||"[]"),entitlements:JSON.parse(p.entitlements_json||"{}"),is_active:!!p.is_active,is_unlimited:!!p.is_unlimited,is_featured:!!p.is_featured}))},200,headers);
   }
   if(path==="/billing/status"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="dietitian")return json({success:false,message:"Subscriptions are only available for dietitian accounts."},403,headers);
    let sub=await env.DB.prepare("SELECT s.*,p.slug AS plan_slug,p.name AS plan_name,p.patient_limit,p.is_unlimited,p.price_minor,p.entitlements_json FROM dietitian_subscriptions s JOIN subscription_plans p ON p.id=s.plan_id WHERE s.user_id=?").bind(session.user_id).first();
    if(!sub){const basic=await env.DB.prepare("SELECT id,trial_days FROM subscription_plans WHERE slug='basic' AND is_active=1").first();if(basic){const start=now(),end=new Date(Date.now()+Number(basic.trial_days||14)*86400000).toISOString();await env.DB.prepare("INSERT OR IGNORE INTO dietitian_subscriptions(id,user_id,plan_id,status,trial_ends_at,current_period_start,current_period_end) VALUES(?,?,?,'trialing',?,?,?)").bind(id(),session.user_id,basic.id,end,start,end).run();sub=await env.DB.prepare("SELECT s.*,p.slug AS plan_slug,p.name AS plan_name,p.patient_limit,p.is_unlimited,p.price_minor,p.entitlements_json FROM dietitian_subscriptions s JOIN subscription_plans p ON p.id=s.plan_id WHERE s.user_id=?").bind(session.user_id).first();}}
    if(sub&&["trialing","active","comped"].includes(sub.status)&&((sub.status==="trialing"&&sub.trial_ends_at&&Date.parse(sub.trial_ends_at)<=Date.now())||(sub.current_period_end&&Date.parse(sub.current_period_end)<=Date.now()))){await env.DB.prepare("UPDATE dietitian_subscriptions SET status='expired',updated_at=? WHERE id=?").bind(now(),sub.id).run();sub.status="expired";}
    const count=await env.DB.prepare("SELECT COUNT(DISTINCT user_id) AS n FROM (SELECT client_user_id AS user_id FROM dietitian_requests WHERE dietitian_user_id=? AND status='accepted' UNION SELECT user_id FROM client_profiles WHERE assigned_dietitian_user_id=?)").bind(session.user_id,session.user_id).first();
    return json({success:true,subscription:sub?{...sub,is_unlimited:!!sub.is_unlimited,entitlements:(()=>{try{return JSON.parse(sub.entitlements_json||"{}")}catch{return {}}})(),locked:!["trialing","active","comped"].includes(sub.status)}:null,patient_count:Number(count?.n||0),locked:!sub||!["trialing","active","comped"].includes(sub.status)},200,headers);
   }
   if(path==="/billing/checkout"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="dietitian")return json({success:false,message:"Only dietitian accounts can subscribe."},403,headers);
    const b=await body(request),slug=clean(b.plan_slug,50),plan=await env.DB.prepare("SELECT id,slug,name FROM subscription_plans WHERE slug=? AND is_active=1").bind(slug).first();
    if(!plan)return json({success:false,message:"This plan is unavailable. Refresh the plan catalogue."},404,headers);
    await audit(env,session.user_id,null,"billing.checkout_unavailable","subscription_plan",plan.id,{slug:plan.slug});
    return json({success:false,message:"Online payments are not enabled yet. No payment was taken and your subscription was not changed."},501,headers);
   }

   if(path==="/dietitian/tool-controls"&&request.method==="GET"){
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const member=await env.DB.prepare("SELECT 1 AS ok FROM practice_memberships WHERE user_id=? AND role='dietitian' AND status='active' LIMIT 1").bind(session.user_id).first();
    if(!member&&!session.is_platform_admin)return json({success:false,message:"Dietitian access required."},403,headers);
    const rows=await env.DB.prepare("SELECT tool_key,enabled FROM platform_tool_controls").all();
    return json({success:true,settings:Object.fromEntries((rows.results||[]).map(r=>[r.tool_key,!!r.enabled]))},200,headers);
   }
   if(path.startsWith("/admin/")) {
    if(!session?.is_platform_admin) return json({success:false,message:"Platform administrator access required."},session?403:401,headers);
 

   if(path==="/admin/theme"&&request.method==="POST"){const b=await body(request),color=String(b.primary_color||"").toUpperCase();if(!/^#[0-9A-F]{6}$/.test(color))return json({success:false,message:"Enter a valid six-digit HEX colour."},400,headers);await env.DB.prepare("CREATE TABLE IF NOT EXISTS platform_branding_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_by TEXT)").run();await env.DB.prepare("INSERT INTO platform_branding_settings(setting_key,setting_value,updated_at,updated_by) VALUES('primary_color',?,CURRENT_TIMESTAMP,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by").bind(color,session.user_id).run();await audit(env,session.user_id,null,"platform.branding.updated","branding","primary_color",{primary_color:color});return json({success:true,message:"Brand theme updated.",theme:{primary_color:color}},200,headers)}
   if(path==="/admin/module-controls"&&request.method==="GET"){
    const moduleInfo={
     overview:["Overview","Core dashboard landing page."],
     find_dietitian:["Find a dietitian","Discover and select a dietitian."],
     consultation_requests:["Consultation requests","Manage consultation requests."],
     nutrition_care:["My Nutrition Care","Patient nutrition care and plans."],
     feedback_ratings:["Feedback & Ratings","Patient feedback and ratings."],
     chat:["Chats","Patient conversations and replies."],
     notifications:["Notifications","Important account and care updates."],
     profile_settings:["Profile & Settings","Personal account settings."],
     help_support:["Help & Support","Support and assistance."],
     my_practice:["My practice","Practice workspace and details."],
     team_invitations:["Team & invitations","Manage practice team access."],
     dietitian_dashboard:["Dietitian Dashboard","Practice performance and analytics."],
     patient_management:["Patient Management","Manage patients and clinical records."],
     diet_plans:["Diet Plans","Create and manage patient diet plans."],
     plan_billing:["Plan & billing","Manage dietitian subscription."],
     more_tools:["More Tools","Clinical and nutrition tools."],
     dietitian_profile:["Dietitian profile","Professional profile and directory details."],
     invoices:["Invoices","Create and manage patient invoices."]
    };
    const roleKeys={
     client:["overview","find_dietitian","consultation_requests","nutrition_care","feedback_ratings","notifications","profile_settings","help_support","invoices"],
     dietitian:["overview","chat","notifications","my_practice","team_invitations","dietitian_dashboard","patient_management","diet_plans","plan_billing","more_tools","dietitian_profile","invoices"],
     dietitian_applicant:["overview","more_tools"]
    };
    const catalog=Object.fromEntries(Object.entries(roleKeys).map(([role,keys])=>[role,keys.map(key=>({key,label:moduleInfo[key][0],description:moduleInfo[key][1]}))]));
    const rows=await env.DB.prepare("SELECT user_type,module_key,enabled FROM platform_module_controls").all();
    const settings={};
    for(const row of rows.results||[]){settings[row.user_type]??={};settings[row.user_type][row.module_key]={enabled:!!row.enabled};}
    return json({success:true,catalog,settings},200,headers);
   }
   if(path==="/admin/module-controls"&&request.method==="POST"){
    const b=await body(request),role=clean(b.user_type,32),items=Array.isArray(b.modules)?b.modules:[];
    const allowed={client:["overview","find_dietitian","consultation_requests","nutrition_care","feedback_ratings","notifications","profile_settings","help_support","invoices"],dietitian:["overview","chat","notifications","my_practice","team_invitations","dietitian_dashboard","patient_management","diet_plans","plan_billing","more_tools","dietitian_profile","invoices"],dietitian_applicant:["overview","more_tools"]};
    if(!allowed[role])return json({success:false,message:"Invalid dashboard role."},400,headers);
    if(items.length>20||items.some(x=>!allowed[role].includes(x.key)||typeof x.enabled!=="boolean"))return json({success:false,message:"Invalid module settings."},400,headers);
    const statements=items.map(x=>env.DB.prepare("INSERT INTO platform_module_controls(user_type,module_key,enabled,updated_at,updated_by) VALUES(?,?,?,CURRENT_TIMESTAMP,?) ON CONFLICT(user_type,module_key) DO UPDATE SET enabled=excluded.enabled,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by").bind(role,x.key,x.enabled?1:0,session.user_id));
    if(statements.length)await env.DB.batch(statements);
    return json({success:true,message:"Dashboard module permissions saved.",count:items.length},200,headers);
   }
   if(path==="/admin/diet-plans"&&request.method==="GET"){
    const rows=await env.DB.prepare("SELECT dp.id,dp.practice_id,dp.client_user_id,dp.dietitian_user_id,dp.title,dp.status,dp.current_version,dp.created_at,dp.updated_at,p.name AS practice_name,cu.display_name AS patient_name,cu.email AS patient_email,du.display_name AS dietitian_name,du.email AS dietitian_email,v.plan_json,v.notes,v.version_number,v.published_at FROM diet_plans dp JOIN practices p ON p.id=dp.practice_id LEFT JOIN app_users cu ON cu.id=dp.client_user_id LEFT JOIN app_users du ON du.id=dp.dietitian_user_id LEFT JOIN diet_plan_versions v ON v.plan_id=dp.id AND v.version_number=dp.current_version ORDER BY dp.updated_at DESC LIMIT 500").all();
    const plans=(rows.results||[]).map(row=>{let plan={};try{plan=JSON.parse(row.plan_json||"{}");}catch{}return {...row,plan,notes:row.notes||"",version_number:row.version_number||row.current_version};});
    return json({success:true,plans},200,headers);
   }
   if(path==="/admin/tool-controls"&&request.method==="GET"){
    const rows=await env.DB.prepare("SELECT tool_key,enabled,updated_at FROM platform_tool_controls ORDER BY tool_key").all();
    return json({success:true,tools:[{"key":"bmi","label":"BMI Calculator","category":"Anthropometry"},{"key":"carbs","label":"Carb Counting","category":"Diabetes care"},{"key":"food","label":"Food Nutrition Explorer","category":"Food reference"},{"key":"fodmap","label":"FODMAP Food Guide","category":"Gut health"},{"key":"energy","label":"Energy Needs Estimator","category":"Assessment"},{"key":"water","label":"Fluid Needs Quick Check","category":"Hydration"},{"key":"waist","label":"Waist-to-Height Ratio","category":"Risk screening"},{"key":"macro","label":"Macro Split Calculator","category":"Meal planning"},{"key":"rda","label":"RDA & Nutrient Reference","category":"Indian requirements"},{"key":"recipe","label":"Indian Recipe Analyzer","category":"Recipe analysis"},{"key":"compare","label":"Compare Foods","category":"Food comparison"},{"key":"exchange","label":"Exchange & Macro Planner","category":"Diet planning"},{"key":"adequacy","label":"Dietary Adequacy Analyzer","category":"Intake review"},{"key":"dietanalysis","label":"Diet Plan Nutrient Analysis","category":"Diet plan review"},{"key":"growth","label":"Growth & Weight Assessment","category":"Growth"},{"key":"references","label":"Clinical Reference Library","category":"Evidence library"},{"key":"interactions","label":"Drug–Nutrient Interactions","category":"Medication safety"},{"key":"enteral","label":"Enteral Nutrition Calculator","category":"Clinical support"},{"key":"malnutrition","label":"Malnutrition Screening Assistant","category":"Screening"},{"key":"monitoring","label":"Clinical Monitoring Dashboard","category":"Follow-up"},{"key":"glycemic","label":"Glycemic Index & Load","category":"Glucose response"},{"key":"label","label":"Nutrition Label Decoder","category":"Food label"},{"key":"renal","label":"Sodium · Potassium · Phosphorus","category":"Renal nutrition"},{"key":"pediatric","label":"Paediatric Fluids & BMR","category":"Paediatrics"},{"key":"fatprofile","label":"Fatty Acid Profile","category":"Lipids"},{"key":"supplement","label":"Supplement Label Calculator","category":"Supplement review"},{"key":"recall","label":"24-Hour Recall Journal","category":"Dietary assessment"},{"key":"drug","label":"Drug–Nutrient Interactions","category":"Medication safety"}],settings:Object.fromEntries((rows.results||[]).map(r=>[r.tool_key,!!r.enabled]))},200,headers);
   }
   if(path==="/admin/tool-controls"&&request.method==="POST"){
    const b=await body(request),items=Array.isArray(b.tools)?b.tools:[];
    if(items.length>28)return json({success:false,message:"Too many tool settings."},400,headers);
    const allowed=new Set(["bmi","carbs","food","fodmap","energy","water","waist","macro","rda","recipe","compare","exchange","adequacy","dietanalysis","growth","references","interactions","enteral","malnutrition","monitoring","glycemic","label","renal","pediatric","fatprofile","supplement","recall","drug"]);
    for(const item of items){
     const key=clean(item.key,60);
     if(!allowed.has(key)||typeof item.enabled!=="boolean")return json({success:false,message:"Invalid tool setting."},400,headers);
    }
    for(const item of items){
     await env.DB.prepare("INSERT INTO platform_tool_controls(tool_key,enabled,updated_at,updated_by) VALUES(?,?,?,?) ON CONFLICT(tool_key) DO UPDATE SET enabled=excluded.enabled,updated_at=excluded.updated_at,updated_by=excluded.updated_by").bind(item.key,item.enabled?1:0,now(),session.user_id).run();
    }
    await audit(env,session.user_id,null,"platform.tool_controls_updated","platform_tool_controls",null,{count:items.length});
    return json({success:true,message:"Dietitian tool visibility settings saved.",count:items.length},200,headers);
   }
   if(path==="/admin/billing/overview"&&request.method==="GET") {
    const plans=await env.DB.prepare("SELECT id,slug,name,description,price_minor,prices_minor_json,patient_limit,is_unlimited,trial_days,features_json,entitlements_json,is_active,is_featured,sort_order,created_at,updated_at FROM subscription_plans ORDER BY sort_order,name").all();
    const subscriptions=await env.DB.prepare("SELECT s.id,s.user_id,u.display_name,u.email,s.status,s.trial_ends_at,s.current_period_start,s.current_period_end,s.admin_override,s.override_reason,p.slug AS plan_slug,p.name AS plan_name FROM dietitian_subscriptions s JOIN app_users u ON u.id=s.user_id JOIN subscription_plans p ON p.id=s.plan_id ORDER BY s.updated_at DESC LIMIT 500").all();
    const stats=await env.DB.prepare("SELECT (SELECT COUNT(*) FROM app_users WHERE account_type='dietitian' AND status='active') AS dietitians,(SELECT COUNT(*) FROM dietitian_subscriptions WHERE status='trialing' AND (trial_ends_at IS NULL OR trial_ends_at>?)) AS trialing,(SELECT COUNT(*) FROM dietitian_subscriptions WHERE status IN ('active','comped')) AS active,(SELECT COUNT(*) FROM dietitian_subscriptions WHERE status IN ('expired','suspended','cancelled') OR (status='trialing' AND trial_ends_at<=?)) AS expired").bind(now(),now()).first();
    return json({success:true,plans:(plans.results||[]).map(p=>({...p,prices_minor:JSON.parse(p.prices_minor_json||"{}"),features:JSON.parse(p.features_json||"[]"),entitlements:JSON.parse(p.entitlements_json||"{}"),is_active:!!p.is_active,is_unlimited:!!p.is_unlimited,is_featured:!!p.is_featured})),subscriptions:subscriptions.results||[],stats:stats||{}},200,headers);
   }
   if(path==="/admin/billing/plans"&&request.method==="POST") {
    const b=await body(request),action=clean(b.action||"save",20),reason=clean(b.reason||"Plan catalogue updated by Superadmin",500);
    if(action==="delete"){
     const planId=clean(b.id,80),slug=clean(b.slug,50),plan=planId?await env.DB.prepare("SELECT id,slug,name FROM subscription_plans WHERE id=?").bind(planId).first():await env.DB.prepare("SELECT id,slug,name FROM subscription_plans WHERE slug=?").bind(slug).first();
     if(!plan)return json({success:false,message:"Plan not found."},404,headers);
     const count=await env.DB.prepare("SELECT COUNT(*) AS n FROM dietitian_subscriptions WHERE plan_id=?").bind(plan.id).first();
     if(Number(count?.n||0)>0){await env.DB.prepare("UPDATE subscription_plans SET is_active=0,updated_at=? WHERE id=?").bind(now(),plan.id).run();await audit(env,session.user_id,null,"billing.plan_archived","subscription_plan",plan.id,{slug:plan.slug,reason,subscriptions:Number(count.n)});return json({success:true,message:"Subscription history exists, so this plan was safely unpublished and archived."},200,headers);}
     await env.DB.prepare("DELETE FROM subscription_plans WHERE id=?").bind(plan.id).run();await audit(env,session.user_id,null,"billing.plan_deleted","subscription_plan",plan.id,{slug:plan.slug,reason});return json({success:true,message:"Plan deleted from the catalogue."},200,headers);
    }
    if(action!=="save"||!Array.isArray(b.plans)||b.plans.length>100)return json({success:false,message:"Send a valid catalogue of up to 100 plans."},400,headers);
    const seen=new Set();
    for(let i=0;i<b.plans.length;i++){
     const p=b.plans[i]||{},pid=clean(p.id,80)||id(),slug=clean(p.slug,50).toLowerCase(),name=clean(p.name,80),description=clean(p.description,240);
     if(!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug))return json({success:false,message:"Plan slugs must use lowercase letters, numbers and hyphens."},400,headers);
     if(name.length<2)return json({success:false,message:"Every plan needs a name of at least 2 characters."},400,headers);
     if(seen.has(slug))return json({success:false,message:"Duplicate plan slug: "+slug+"."},400,headers);seen.add(slug);
     const conflict=await env.DB.prepare("SELECT id FROM subscription_plans WHERE slug=? AND id<>?").bind(slug,pid).first();if(conflict)return json({success:false,message:"The slug “"+slug+"” is already used by another plan."},409,headers);
     const price=Math.max(0,Math.min(1000000000,Math.round(Number(p.price_minor??0))));if(!Number.isFinite(price))return json({success:false,message:"Enter a valid price for "+name+"."},400,headers);
     const pr=p.prices_minor&&typeof p.prices_minor==="object"?p.prices_minor:{monthly:price},prices={monthly:price,quarterly:Math.max(0,Math.min(3000000000,Math.round(Number(pr.quarterly||0)))),half_yearly:Math.max(0,Math.min(6000000000,Math.round(Number(pr.half_yearly||0)))),yearly:Math.max(0,Math.min(12000000000,Math.round(Number(pr.yearly||0))))};
     const limit=Math.max(1,Math.min(1000000,Math.round(Number(p.patient_limit||1)))),trial=Math.max(0,Math.min(365,Math.round(Number(p.trial_days??14)))),features=Array.isArray(p.features)?p.features.map(x=>clean(x,180)).filter(Boolean).slice(0,80):[];
     const rawEntitlements=p.entitlements&&typeof p.entitlements==="object"?p.entitlements:{},entitlements=Object.fromEntries(PLAN_FEATURE_KEYS.map(key=>[key,rawEntitlements[key]!==false]));
     await env.DB.prepare("INSERT INTO subscription_plans(id,slug,name,description,price_minor,prices_minor_json,patient_limit,is_unlimited,trial_days,features_json,entitlements_json,is_active,is_featured,sort_order,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET slug=excluded.slug,name=excluded.name,description=excluded.description,price_minor=excluded.price_minor,prices_minor_json=excluded.prices_minor_json,patient_limit=excluded.patient_limit,is_unlimited=excluded.is_unlimited,trial_days=excluded.trial_days,features_json=excluded.features_json,entitlements_json=excluded.entitlements_json,is_active=excluded.is_active,is_featured=excluded.is_featured,sort_order=excluded.sort_order,updated_at=excluded.updated_at").bind(pid,slug,name,description,price,JSON.stringify(prices),limit,p.is_unlimited===true?1:0,trial,JSON.stringify(features),JSON.stringify(entitlements),p.is_active===false?0:1,p.is_featured===true?1:0,Math.max(0,Math.min(9999,Math.round(Number(p.sort_order||i+1)))),now()).run();
    }
    await audit(env,session.user_id,null,"billing.plan_catalogue_saved","subscription_plan",null,{count:b.plans.length,reason});
    return json({success:true,message:"Plan catalogue saved. Published plans are available to new selections.",count:b.plans.length},200,headers);
   }
   if(path==="/admin/billing/subscriptions"&&request.method==="POST") {
    const b=await body(request),email=clean(b.email,254).toLowerCase(),slug=clean(b.plan_slug,50),status=clean(b.status,20),days=Math.max(1,Math.min(3660,Math.round(Number(b.days||30)))),reason=clean(b.reason,500);
    if(!emailOk(email)||!reason)return json({success:false,message:"Enter a valid dietitian email and an audit reason."},400,headers);
    if(!["active","comped","trialing","suspended","cancelled","expired"].includes(status))return json({success:false,message:"Choose a valid subscription status."},400,headers);
    const user=await env.DB.prepare("SELECT id,email,display_name,account_type,status FROM app_users WHERE email=? COLLATE NOCASE").bind(email).first();
    if(!user||user.account_type!=="dietitian"||user.status!=="active")return json({success:false,message:"An active dietitian account with that email was not found. Patient accounts cannot be subscribed."},404,headers);
    const plan=await env.DB.prepare("SELECT id,slug,name FROM subscription_plans WHERE slug=?").bind(slug).first();if(!plan)return json({success:false,message:"Choose an existing plan."},400,headers);
    const start=now(),end=new Date(Date.now()+days*86400000).toISOString(),trialEnd=status==="trialing"?end:null,override=["comped","suspended","cancelled","expired"].includes(status)?1:0;
    await env.DB.prepare("INSERT INTO dietitian_subscriptions(id,user_id,plan_id,status,trial_ends_at,current_period_start,current_period_end,admin_override,override_reason,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET plan_id=excluded.plan_id,status=excluded.status,trial_ends_at=excluded.trial_ends_at,current_period_start=excluded.current_period_start,current_period_end=excluded.current_period_end,admin_override=excluded.admin_override,override_reason=excluded.override_reason,updated_at=excluded.updated_at").bind(id(),user.id,plan.id,status,trialEnd,start,end,override,reason,now()).run();
    const sub=await env.DB.prepare("SELECT id FROM dietitian_subscriptions WHERE user_id=?").bind(user.id).first();await audit(env,session.user_id,null,"billing.subscription_admin_changed","dietitian_subscription",sub?.id,{email:user.email,plan_slug:slug,status,days,reason});
    return json({success:true,message:"Subscription updated for "+user.display_name+"."},200,headers);
   }
   if(path==="/admin/users"&&request.method==="GET") {
      const q=clean(url.searchParams.get("q"),120).toLowerCase(),type=clean(url.searchParams.get("type"),20),status=clean(url.searchParams.get("status"),20);
      const rows=await env.DB.prepare("SELECT u.id AS user_id,u.display_name,u.email,u.phone,u.account_type,u.status,u.created_at,(SELECT COUNT(*) FROM practice_memberships m WHERE m.user_id=u.id AND m.status='active') AS active_memberships,(SELECT GROUP_CONCAT(DISTINCT p.name) FROM practice_memberships m JOIN practices p ON p.id=m.practice_id WHERE m.user_id=u.id) AS practices,(SELECT COUNT(*) FROM dietitian_requests r WHERE r.client_user_id=u.id OR r.dietitian_user_id=u.id) AS consultation_count,(SELECT COUNT(*) FROM diet_plans dp WHERE dp.client_user_id=u.id OR dp.dietitian_user_id=u.id) AS diet_plan_count FROM app_users u WHERE (?='' OR lower(u.display_name) LIKE '%'||?||'%' OR lower(u.email) LIKE '%'||?||'%' OR u.phone LIKE '%'||?||'%') AND (?='' OR u.account_type=?) AND (?='' OR u.status=?) ORDER BY u.created_at DESC LIMIT 500").bind(q,q,q,q,type,type,status,status).all();
      return json({success:true,users:rows.results||[]},200,headers);
   }
   const adminUserStatus=path.match(/^\/admin\/users\/([a-f0-9-]+)\/status$/);
   if(adminUserStatus&&request.method==="POST") {
      const targetId=adminUserStatus[1],b=await body(request),status=clean(b.status,20);
      if(!["active","suspended"].includes(status))return json({success:false,message:"Choose active or suspended."},400,headers);
      if(targetId===session.user_id)return json({success:false,message:"You cannot suspend your own superadmin account."},400,headers);
      const target=await env.DB.prepare("SELECT id,account_type,status FROM app_users WHERE id=?").bind(targetId).first();
      if(!target)return json({success:false,message:"User not found."},404,headers);
      if(await env.DB.prepare("SELECT 1 AS ok FROM platform_admins WHERE user_id=? AND status='active'").bind(targetId).first())return json({success:false,message:"Superadmin accounts cannot be changed from User Management."},403,headers);
      await env.DB.prepare("UPDATE app_users SET status=? WHERE id=?").bind(status,targetId).run();
      await audit(env,session.user_id,null,"admin.user_status_changed","user",targetId,{status,previous_status:target.status});
      return json({success:true,message:"User "+status+".",status},200,headers);
   }
   const adminUserDetail=path.match(/^\/admin\/users\/([a-f0-9-]+)$/);
   if(adminUserDetail&&request.method==="GET") {
      const targetId=adminUserDetail[1],target=await env.DB.prepare("SELECT id AS user_id,display_name,email,phone,account_type,status,created_at FROM app_users WHERE id=?").bind(targetId).first();
      if(!target)return json({success:false,message:"User not found."},404,headers);
      const [memberships,profile,requests,plans,appointments,conversations]=await Promise.all([
        env.DB.prepare("SELECT m.practice_id,m.role,m.status AS membership_status,p.name AS practice_name,p.status AS practice_status FROM practice_memberships m JOIN practices p ON p.id=m.practice_id WHERE m.user_id=? ORDER BY p.name").bind(targetId).all(),
        env.DB.prepare("SELECT dp.practice_id,p.name AS practice_name,dp.credentials,dp.registration_number,dp.bio,dp.verification_status,dd.specialties_json,dd.languages_json,dd.consultation_modes_json,dd.experience_years,dd.fee_minor,dd.accepting_clients FROM dietitian_profiles dp JOIN practices p ON p.id=dp.practice_id LEFT JOIN dietitian_directory dd ON dd.user_id=dp.user_id AND dd.practice_id=dp.practice_id WHERE dp.user_id=?").bind(targetId).all(),
        env.DB.prepare("SELECT r.id,r.practice_id,p.name AS practice_name,r.client_user_id,cu.display_name AS client_name,r.dietitian_user_id,du.display_name AS dietitian_name,r.message,r.status,r.created_at FROM dietitian_requests r JOIN practices p ON p.id=r.practice_id LEFT JOIN app_users cu ON cu.id=r.client_user_id LEFT JOIN app_users du ON du.id=r.dietitian_user_id WHERE r.client_user_id=? OR r.dietitian_user_id=? ORDER BY r.created_at DESC LIMIT 200").bind(targetId,targetId).all(),
        env.DB.prepare("SELECT dp.id,dp.practice_id,p.name AS practice_name,dp.client_user_id,cu.display_name AS client_name,dp.dietitian_user_id,du.display_name AS dietitian_name,dp.title,dp.status,dp.current_version,dp.created_at,dp.updated_at,dv.plan_json,dv.notes,dv.published_at FROM diet_plans dp JOIN practices p ON p.id=dp.practice_id LEFT JOIN app_users cu ON cu.id=dp.client_user_id LEFT JOIN app_users du ON du.id=dp.dietitian_user_id LEFT JOIN diet_plan_versions dv ON dv.plan_id=dp.id AND dv.version_number=dp.current_version WHERE dp.client_user_id=? OR dp.dietitian_user_id=? ORDER BY dp.updated_at DESC LIMIT 200").bind(targetId,targetId).all(),
        env.DB.prepare("SELECT a.id,a.practice_id,p.name AS practice_name,a.client_user_id,cu.display_name AS client_name,a.dietitian_user_id,du.display_name AS dietitian_name,a.starts_at,a.ends_at,a.status,a.notes,a.created_at FROM appointments a JOIN practices p ON p.id=a.practice_id LEFT JOIN app_users cu ON cu.id=a.client_user_id LEFT JOIN app_users du ON du.id=a.dietitian_user_id WHERE a.client_user_id=? OR a.dietitian_user_id=? ORDER BY a.starts_at DESC LIMIT 200").bind(targetId,targetId).all(),
        env.DB.prepare("SELECT c.id,c.practice_id,p.name AS practice_name,c.client_user_id,cu.display_name AS client_name,c.dietitian_user_id,du.display_name AS dietitian_name,c.status,c.updated_at FROM conversations c JOIN practices p ON p.id=c.practice_id LEFT JOIN app_users cu ON cu.id=c.client_user_id LEFT JOIN app_users du ON du.id=c.dietitian_user_id WHERE c.client_user_id=? OR c.dietitian_user_id=? ORDER BY c.updated_at DESC LIMIT 100").bind(targetId,targetId).all()
      ]);
      const chats=[];
      for(const c of conversations.results||[]){const m=await env.DB.prepare("SELECT m.id,m.sender_user_id,u.display_name AS sender_name,m.body,m.created_at,m.read_at FROM messages m JOIN app_users u ON u.id=m.sender_user_id WHERE m.conversation_id=? ORDER BY m.created_at ASC LIMIT 500").bind(c.id).all();chats.push({...c,messages:m.results||[]});}
      await audit(env,session.user_id,null,"admin.user_detail_viewed","user",targetId,{included:"memberships,profile,requests,plans,appointments,conversations"});
      return json({success:true,user:target,memberships:memberships.results||[],dietitian_profiles:profile.results||[],requests:requests.results||[],plans:(plans.results||[]).map(p=>({...p,plan:(()=>{try{return JSON.parse(p.plan_json||"{}")}catch{return {}}})()})),appointments:appointments.results||[],conversations:chats},200,headers);
   }
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
   if(path==="/dietitian/invoices"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="dietitian"||session.is_platform_admin)return json({success:false,message:"Dietitian access required."},403,headers);
    const requestedPractice=clean(url.searchParams.get("practice_id"),80);
    const member=session.memberships.find(m=>m.role==="dietitian"&&m.status==="active"&&(!requestedPractice||m.practice_id===requestedPractice));
    if(!member)return json({success:false,message:"An active dietitian practice membership is required to view invoices."},403,headers);
    const rows=await env.DB.prepare("SELECT id,invoice_json,status,sent_at,created_at,updated_at FROM practice_invoices WHERE practice_id=? AND dietitian_user_id=? ORDER BY updated_at DESC LIMIT 500").bind(member.practice_id,session.user_id).all();
    const invoices=(rows.results||[]).map(row=>{try{return {...JSON.parse(row.invoice_json||"{}"),id:row.id,status:row.status,sent_at:row.sent_at||null,created_at:row.created_at,updated_at:row.updated_at}}catch{return null}}).filter(Boolean);
    return json({success:true,practice_id:member.practice_id,invoices},200,headers);
   }
   if(path==="/dietitian/invoices"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="dietitian"||session.is_platform_admin)return json({success:false,message:"Only a dietitian account can manage invoices."},403,headers);
    const b=await body(request),requestedPractice=clean(b.practice_id,80),invoice=b.invoice||{};
    const member=session.memberships.find(m=>m.role==="dietitian"&&m.status==="active"&&(!requestedPractice||m.practice_id===requestedPractice));
    if(!member)return json({success:false,message:"An active dietitian practice membership is required to save invoices."},403,headers);
    const invoiceId=clean(invoice.id,80)||id(),number=clean(invoice.number,80),patient=clean(invoice.patient_name,120),to=clean(invoice.patient_email,254).toLowerCase(),date=clean(invoice.date,20),due=clean(invoice.due_date,20),currency=clean(invoice.currency,8)||"INR";
    const items=Array.isArray(invoice.items)?invoice.items.slice(0,40).map(x=>({description:clean(x.description,180),quantity:Number(x.quantity),rate:Number(x.rate)})).filter(x=>x.description&&Number.isFinite(x.quantity)&&x.quantity>0&&Number.isFinite(x.rate)&&x.rate>=0):[];
    if(!number||!patient||!date||!items.length)return json({success:false,message:"Add an invoice number, patient name, invoice date and at least one valid line item."},400,headers);
    if(to&&!emailOk(to))return json({success:false,message:"Enter a valid patient email address or leave it blank."},400,headers);
    const subtotal=items.reduce((sum,x)=>sum+x.quantity*x.rate,0),taxPercent=Math.min(100,Math.max(0,Number(invoice.tax_percent)||0)),tax=subtotal*taxPercent/100,total=subtotal+tax;
    if(!Number.isFinite(total)||total<=0)return json({success:false,message:"Invoice total must be greater than zero."},400,headers);
    const existing=await env.DB.prepare("SELECT id,status,sent_at FROM practice_invoices WHERE id=? AND practice_id=? AND dietitian_user_id=?").bind(invoiceId,member.practice_id,session.user_id).first();
    if(!existing){
      const duplicate=await env.DB.prepare("SELECT id FROM practice_invoices WHERE practice_id=? AND invoice_number=?").bind(member.practice_id,number).first();
      if(duplicate)return json({success:false,message:"That invoice number is already in use in this practice. Choose a different number."},409,headers);
    }
    const selectedPatientId=clean(invoice.patient_user_id,80);
    let patientUser=null;
    if(selectedPatientId){
      patientUser=await env.DB.prepare("SELECT u.id,u.email,u.display_name,cp.preferred_name FROM client_profiles cp JOIN app_users u ON u.id=cp.user_id WHERE cp.user_id=? AND cp.practice_id=? AND (cp.assigned_dietitian_user_id=? OR EXISTS(SELECT 1 FROM dietitian_requests r WHERE r.practice_id=cp.practice_id AND r.client_user_id=cp.user_id AND r.dietitian_user_id=? AND r.status='accepted')) AND u.status='active'").bind(selectedPatientId,member.practice_id,session.user_id,session.user_id).first();
      if(!patientUser)return json({success:false,message:"Select a connected patient in your active practice, then try again."},403,headers);
    }else if(to){
      patientUser=await env.DB.prepare("SELECT id,email,display_name FROM app_users WHERE email=? COLLATE NOCASE").bind(to).first();
    }
    const finalEmail=patientUser?.email||to;
    if(finalEmail&&!emailOk(finalEmail))return json({success:false,message:"The selected patient's account does not have a valid email address."},400,headers);
    const payload={...invoice,id:invoiceId,patient_user_id:patientUser?.id||null,number,patient_name:patientUser?(clean(patientUser.preferred_name,120)||clean(patientUser.display_name,120)||patient):patient,patient_email:finalEmail,patient_address:clean(invoice.patient_address,500),date,due_date:due,currency,tax_percent:taxPercent,items,subtotal,tax,total,status:existing?.status||"Draft",sent_at:existing?.sent_at||null,created_at:existing?invoice.created_at||null:now(),brand:{brand_name:clean(invoice.brand?.brand_name,120),dietitian_name:clean(invoice.brand?.dietitian_name,120),email:clean(invoice.brand?.email,254),phone:clean(invoice.brand?.phone,40),address:clean(invoice.brand?.address,600),website:clean(invoice.brand?.website,200),logo:typeof invoice.brand?.logo==="string"&&invoice.brand.logo.length<=1200000?invoice.brand.logo:""}};
    const stamp=now(),jsonPayload=JSON.stringify(payload);
    if(existing){
      await env.DB.prepare("UPDATE practice_invoices SET patient_user_id=?,invoice_number=?,patient_name=?,patient_email=?,invoice_json=?,updated_at=? WHERE id=? AND practice_id=? AND dietitian_user_id=?").bind(patientUser?.id||null,number,patient,to,jsonPayload,stamp,invoiceId,member.practice_id,session.user_id).run();
    }else{
      await env.DB.prepare("INSERT INTO practice_invoices(id,practice_id,dietitian_user_id,patient_user_id,invoice_number,patient_name,patient_email,status,invoice_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'Draft',?,?,?)").bind(invoiceId,member.practice_id,session.user_id,patientUser?.id||null,number,patient,to,jsonPayload,stamp,stamp).run();
    }
    return json({success:true,invoice:{...payload,updated_at:stamp}},existing?200:201,headers);
   }
   if(path==="/client/invoices"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const rows=await env.DB.prepare("SELECT i.id,i.invoice_json,i.status,i.sent_at,i.created_at,i.updated_at FROM practice_invoices i WHERE (i.patient_user_id=? OR lower(i.patient_email)=(SELECT lower(email) FROM app_users WHERE id=?)) AND i.status IN ('Sent','Paid','Overdue','Cancelled') ORDER BY i.updated_at DESC LIMIT 200").bind(session.user_id,session.user_id).all();
    const invoices=(rows.results||[]).map(row=>{try{return {...JSON.parse(row.invoice_json||"{}"),id:row.id,status:row.status,sent_at:row.sent_at||null,created_at:row.created_at,updated_at:row.updated_at}}catch{return null}}).filter(Boolean);
    return json({success:true,invoices},200,headers);
   }
   if(path==="/dietitian/invoices/send"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in to send invoices."},401,headers);
    if(session.account_type!=="dietitian"||session.is_platform_admin)return json({success:false,message:"Only a dietitian account can send patient invoices."},403,headers);
    if(!env.RESEND_API_KEY||!env.MAIL_FROM)return json({success:false,message:"Invoice email delivery is not configured on the server. Ask the administrator to configure the mail service."},503,headers);
    const b=await body(request), invoice=b.invoice||{}, brand=invoice.brand||{};
    const to=clean(invoice.patient_email,254).toLowerCase(), number=clean(invoice.number,80), patient=clean(invoice.patient_name,120), date=clean(invoice.date,20), due=clean(invoice.due_date,20), currency=clean(invoice.currency,8)||"INR";
    const items=Array.isArray(invoice.items)?invoice.items.slice(0,40).map(x=>({description:clean(x.description,180),quantity:Number(x.quantity),rate:Number(x.rate)})).filter(x=>x.description&&Number.isFinite(x.quantity)&&x.quantity>0&&Number.isFinite(x.rate)&&x.rate>=0):[];
    if(!emailOk(to)||!number||!patient||!date||!items.length)return json({success:false,message:"Add a valid patient email, invoice number, invoice date and at least one valid line item."},400,headers);
    const subtotal=items.reduce((sum,x)=>sum+x.quantity*x.rate,0), taxPercent=Math.min(100,Math.max(0,Number(invoice.tax_percent)||0)), tax=subtotal*taxPercent/100, total=subtotal+tax;
    if(!Number.isFinite(total)||total<=0)return json({success:false,message:"Invoice total must be greater than zero."},400,headers);
    const savedInvoice=await env.DB.prepare("SELECT id FROM practice_invoices WHERE id=? AND dietitian_user_id=? AND patient_email=? COLLATE NOCASE").bind(clean(invoice.id,80),session.user_id,to).first();
    if(!savedInvoice)return json({success:false,message:"Save this invoice before emailing it, then try again."},404,headers);
    const esc=v=>String(v??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
    const symbol=currency==="INR"?"₹":currency+" ";
    const money=n=>symbol+Number(n||0).toLocaleString("en-IN",{minimumFractionDigits:2,maximumFractionDigits:2});
    const rows=items.map((x,i)=>'<tr><td style="padding:13px 10px;border-bottom:1px solid #edf0f7;color:#737b91">'+(i+1)+'</td><td style="padding:13px 10px;border-bottom:1px solid #edf0f7;font-weight:600">'+esc(x.description)+'</td><td style="padding:13px 10px;border-bottom:1px solid #edf0f7;text-align:right">'+x.quantity+'</td><td style="padding:13px 10px;border-bottom:1px solid #edf0f7;text-align:right">'+money(x.rate)+'</td><td style="padding:13px 10px;border-bottom:1px solid #edf0f7;text-align:right;font-weight:700">'+money(x.quantity*x.rate)+'</td></tr>').join("");
    const brandName=clean(brand.brand_name,120)||clean(brand.dietitian_name,120)||session.display_name||"Nutrition practice";
    const senderName=clean(brand.dietitian_name,120)||session.display_name||brandName;
    const payment=clean(invoice.payment_details,1000), notes=clean(invoice.notes,1500), address=clean(brand.address,600), contact=[clean(brand.email,254),clean(brand.phone,40),clean(brand.website,200)].filter(Boolean).join(" · ");
    const html='<!doctype html><html><body style="margin:0;background:#f4f5fb;font-family:Arial,Helvetica,sans-serif;color:#27304a"><div style="max-width:760px;margin:0 auto;padding:28px 14px"><div style="background:#fff;border:1px solid #e5e8f2;border-radius:20px;overflow:hidden"><div style="padding:30px 32px;background:linear-gradient(120deg,#f0efff,#fff5fa);border-bottom:1px solid #e8eaf4"><div style="font-size:12px;letter-spacing:2px;color:#6257d9;font-weight:800">INVOICE</div><h1 style="font-size:30px;margin:8px 0 4px;color:#252d65">'+esc(number)+'</h1><div style="color:#69718a">Issued '+esc(date)+(due?' · Due '+esc(due):'')+'</div></div><div style="padding:28px 32px"><div style="display:flex;flex-wrap:wrap;gap:28px;margin-bottom:28px"><div style="flex:1;min-width:210px"><div style="font-size:11px;letter-spacing:1px;color:#7c8499;font-weight:800;margin-bottom:8px">FROM</div><strong>'+esc(brandName)+'</strong><div style="margin-top:5px;white-space:pre-line;color:#69718a;font-size:13px">'+esc(senderName)+'<br>'+esc(address)+'<br>'+esc(contact)+'</div></div><div style="flex:1;min-width:180px"><div style="font-size:11px;letter-spacing:1px;color:#7c8499;font-weight:800;margin-bottom:8px">BILL TO</div><strong>'+esc(patient)+'</strong><div style="margin-top:5px;white-space:pre-line;color:#69718a;font-size:13px">'+esc(clean(invoice.patient_address,500))+'</div></div></div><div style="overflow-x:auto"><table style="border-collapse:collapse;width:100%;font-size:13px"><thead><tr style="background:#f7f8fc;text-align:left"><th style="padding:12px 10px">#</th><th style="padding:12px 10px">Service / description</th><th style="padding:12px 10px;text-align:right">Qty</th><th style="padding:12px 10px;text-align:right">Rate</th><th style="padding:12px 10px;text-align:right">Amount</th></tr></thead><tbody>'+rows+'</tbody></table></div><div style="margin:20px 0 0 auto;max-width:300px"><div style="display:flex;justify-content:space-between;padding:6px 0;color:#69718a"><span>Subtotal</span><strong>'+money(subtotal)+'</strong></div><div style="display:flex;justify-content:space-between;padding:6px 0;color:#69718a"><span>Tax ('+taxPercent.toFixed(2)+'%)</span><strong>'+money(tax)+'</strong></div><div style="display:flex;justify-content:space-between;margin-top:8px;padding:16px;border-radius:12px;background:#f0efff;color:#272765;font-size:18px"><strong>Total due</strong><strong>'+money(total)+'</strong></div></div>'+(payment?'<div style="margin-top:24px;padding:16px;border:1px solid #e5e8f2;border-radius:12px"><strong style="display:block;margin-bottom:7px">Payment instructions</strong><div style="white-space:pre-line;color:#59627b;font-size:13px">'+esc(payment)+'</div></div>':'')+(notes?'<div style="margin-top:18px"><strong>Notes / terms</strong><div style="margin-top:5px;white-space:pre-line;color:#59627b;font-size:13px">'+esc(notes)+'</div></div>':'')+'<p style="margin-top:28px;color:#69718a;font-size:13px">Thank you for choosing '+esc(brandName)+'. Please contact '+esc(senderName)+' if you have any questions about this invoice.</p><div style="margin-top:24px;padding-top:16px;border-top:1px solid #edf0f7;color:#9399aa;font-size:11px">This email contains your invoice details. You can print this email or choose “Save as PDF” from your browser to keep a copy.</div></div></div></div></body></html>';
    const textBody=[brandName,"INVOICE "+number,"Invoice date: "+date,due?"Due date: "+due:"","Bill to: "+patient,clean(invoice.patient_address,500),"",...items.map((x,i)=>(i+1)+". "+x.description+" — "+x.quantity+" × "+money(x.rate)+" = "+money(x.quantity*x.rate)),"","Subtotal: "+money(subtotal),"Tax ("+taxPercent+"%): "+money(tax),"TOTAL DUE: "+money(total),payment?"Payment instructions: "+payment:"",notes?"Notes: "+notes:"","From: "+senderName,contact].filter(Boolean).join("\n");
    try {
      const response=await fetch("https://api.resend.com/emails",{method:"POST",headers:{Authorization:"Bearer "+env.RESEND_API_KEY,"Content-Type":"application/json"},body:JSON.stringify({from:env.MAIL_FROM,to:[to],reply_to:emailOk(clean(brand.email,254))?clean(brand.email,254):undefined,subject:"Invoice "+number+" from "+brandName,html,text:textBody})});
      if(!response.ok){const detail=await response.text();console.error("Invoice email delivery failed",response.status,detail.slice(0,300));return json({success:false,message:"The invoice could not be emailed. Check the recipient address and mail service configuration, then try again."},502,headers);}
      const result=await response.json();
      const sentAt=now();
      await env.DB.prepare("UPDATE practice_invoices SET status='Sent',sent_at=?,updated_at=? WHERE id=? AND dietitian_user_id=? AND patient_email=? COLLATE NOCASE").bind(sentAt,sentAt,clean(invoice.id,80),session.user_id,to).run();
      await audit(env,session.user_id,null,"invoice.email_sent","invoice",number,{recipient:to,total,currency});
      return json({success:true,message:"Invoice email sent.",id:result.id||null,recipient:to,sent_at:sentAt},200,headers);
    } catch(e){console.error("Invoice email error",String(e));return json({success:false,message:"Invoice email could not be sent right now. Please try again."},502,headers);}
   }
   if(path==="/practice/invitations"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),practiceId=clean(b.practice_id,80),email=clean(b.email,254).toLowerCase(),role=clean(b.role,20);
    const membership=session.memberships.find(m=>m.practice_id===practiceId&&["owner","admin"].includes(m.role));
    if(!membership)return json({success:false,message:"Practice owner/admin access required."},403,headers);
    if(!emailOk(email)||!["admin","dietitian","assistant","client"].includes(role))return json({success:false,message:"Valid email and permitted role required."},400,headers);
    const existingInviteUser=await env.DB.prepare("SELECT id FROM app_users WHERE email=? COLLATE NOCASE").bind(email).first();
    if(!existingInviteUser) await env.DB.prepare("INSERT INTO app_users(id,email,display_name,status) VALUES(?,?,?,'active')").bind(id(),email,email.split("@")[0].slice(0,120)).run();
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
   if(path==="/practices/public"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const rows=await env.DB.prepare("SELECT id,name,slug,timezone,currency FROM practices WHERE status='active' ORDER BY name LIMIT 200").all();
    return json({success:true,practices:rows.results||[]},200,headers);
   }
   if(path==="/dietitians/directory"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const practiceId=clean(url.searchParams.get("practice_id"),80);
    const minExp=Math.max(0,Number(url.searchParams.get("min_experience")||0));
    const maxFee=Math.max(0,Number(url.searchParams.get("max_fee")||0));
    const specialty=clean(url.searchParams.get("specialty"),80).toLowerCase();
    const language=clean(url.searchParams.get("language"),60).toLowerCase();
    const mode=clean(url.searchParams.get("mode"),30).toLowerCase();
    const gender=clean(url.searchParams.get("gender"),30).toLowerCase();
    const order=clean(url.searchParams.get("sort"),20);
    const rows=await env.DB.prepare("SELECT u.id AS user_id,u.display_name,dp.credentials,dp.registration_number,dp.bio,dp.verification_status,dd.specialties_json,dd.languages_json,dd.consultation_modes_json,dd.gender,dd.fee_minor,dd.experience_years FROM dietitian_profiles dp JOIN app_users u ON u.id=dp.user_id JOIN practice_memberships m ON m.practice_id=dp.practice_id AND m.user_id=dp.user_id AND m.role='dietitian' AND m.status='active' JOIN dietitian_directory dd ON dd.practice_id=dp.practice_id AND dd.user_id=dp.user_id JOIN practices p ON p.id=dp.practice_id WHERE (?='' OR dp.practice_id=?) AND p.status='active' AND u.status='active' AND dp.verification_status='verified' AND dd.accepting_clients=1 AND dd.experience_years>=? AND (?=0 OR dd.fee_minor<=?) AND (?='' OR lower(dd.specialties_json) LIKE ?) AND (?='' OR lower(dd.languages_json) LIKE ?) AND (?='' OR lower(dd.consultation_modes_json) LIKE ?) AND (?='' OR lower(coalesce(dd.gender,''))=?)").bind(practiceId,practiceId,minExp,maxFee,maxFee,specialty,"%"+specialty+"%",language,"%"+language+"%",mode,"%"+mode+"%",gender,gender).all();
    const dietitians=(rows.results||[]).map(d=>({...d,specialties:JSON.parse(d.specialties_json||"[]"),languages:JSON.parse(d.languages_json||"[]"),consultation_modes:JSON.parse(d.consultation_modes_json||"[]")}));
    dietitians.sort((a,b)=>order==="fee_low"?a.fee_minor-b.fee_minor:order==="experience"?b.experience_years-a.experience_years:a.display_name.localeCompare(b.display_name));
    return json({success:true,dietitians},200,headers);
   }
   if(path==="/dietitian/profile"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const practiceId=clean(url.searchParams.get("practice_id"),80);
    const member=session.memberships.find(m=>m.practice_id===practiceId&&m.role==="dietitian"&&m.status==="active");
    if(!member&&!session.is_platform_admin)return json({success:false,message:"Active dietitian membership required."},403,headers);
    const row=await env.DB.prepare("SELECT p.name AS practice_name,u.display_name,u.email,u.phone,dp.credentials,dp.registration_number,dp.bio,dp.business_name,dp.profile_photo_data_url,dp.contact_email,dp.contact_phone,dp.practice_location,dp.headline,dp.session_minutes,dp.website,dd.specialties_json,dd.languages_json,dd.consultation_modes_json,dd.gender,dd.fee_minor,dd.experience_years,dd.accepting_clients FROM practices p JOIN app_users u ON u.id=? LEFT JOIN dietitian_profiles dp ON dp.practice_id=p.id AND dp.user_id=u.id LEFT JOIN dietitian_directory dd ON dd.practice_id=p.id AND dd.user_id=u.id WHERE p.id=?").bind(session.user_id,practiceId).first();
    if(!row)return json({success:false,message:"Practice profile not found."},404,headers);
    return json({success:true,profile:{practice_id:practiceId,business_name:row.business_name||row.practice_name||"",profile_photo_data_url:row.profile_photo_data_url||"",practice_location:row.practice_location||"",headline:row.headline||"",session_minutes:Number(row.session_minutes)||30,dietitian_name:row.display_name||"",email:row.contact_email||row.email||"",phone:row.contact_phone||row.phone||"",address:row.practice_location||"",website:row.website||"",credentials:row.credentials||"",registration_number:row.registration_number||"",bio:row.bio||"",specialties:JSON.parse(row.specialties_json||"[]"),languages:JSON.parse(row.languages_json||"[]"),consultation_modes:JSON.parse(row.consultation_modes_json||'["Online"]'),gender:row.gender||"",fee_rupees:Number(row.fee_minor||0)/100,experience_years:Number(row.experience_years||0),accepting_clients:row.accepting_clients!==0}},200,headers);
   }
   if(path==="/dietitian/profile"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),practiceId=clean(b.practice_id,80);
    const member=session.memberships.find(m=>m.practice_id===practiceId&&m.role==="dietitian"&&m.status==="active");
    if(!member&&!session.is_platform_admin)return json({success:false,message:"Dietitian membership required."},403,headers);
    const specialties=Array.isArray(b.specialties)?b.specialties.map(x=>clean(x,60)).filter(Boolean).slice(0,12):[];
    const languages=Array.isArray(b.languages)?b.languages.map(x=>clean(x,40)).filter(Boolean).slice(0,12):[];
    const modes=Array.isArray(b.consultation_modes)?b.consultation_modes.map(x=>clean(x,30)).filter(x=>["Online","In-person","Hybrid"].includes(x)).slice(0,3):["Online"];
    const fee=Math.max(0,Math.min(10000000,Math.round(Number(b.fee_rupees||0)*100)));
    const exp=Math.max(0,Math.min(70,Math.round(Number(b.experience_years||0))));
    const gender=clean(b.gender,30),bio=clean(b.bio,1200),credentials=clean(b.credentials,180),reg=clean(b.registration_number,100);
    await env.DB.prepare("INSERT INTO dietitian_profiles(id,practice_id,user_id,credentials,registration_number,bio,business_name,profile_photo_data_url,contact_email,contact_phone,practice_location,website,headline,session_minutes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(practice_id,user_id) DO UPDATE SET credentials=excluded.credentials,registration_number=excluded.registration_number,bio=excluded.bio,business_name=excluded.business_name,profile_photo_data_url=excluded.profile_photo_data_url,contact_email=excluded.contact_email,contact_phone=excluded.contact_phone,practice_location=excluded.practice_location,website=excluded.website,headline=excluded.headline,session_minutes=excluded.session_minutes").bind(id(),practiceId,session.user_id,credentials,reg,bio,clean(b.business_name,120),typeof b.profile_photo_data_url==="string"&&b.profile_photo_data_url.length<=600000?b.profile_photo_data_url:"",clean(b.email,254),clean(b.phone,40),clean(b.practice_location,180),clean(b.website,200),clean(b.headline,140),Math.min(90,Math.max(15,Number(b.session_minutes)||30))).run();
    await env.DB.prepare("INSERT INTO dietitian_directory(user_id,practice_id,specialties_json,languages_json,consultation_modes_json,gender,fee_minor,experience_years,accepting_clients,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id,practice_id) DO UPDATE SET specialties_json=excluded.specialties_json,languages_json=excluded.languages_json,consultation_modes_json=excluded.consultation_modes_json,gender=excluded.gender,fee_minor=excluded.fee_minor,experience_years=excluded.experience_years,accepting_clients=excluded.accepting_clients,updated_at=excluded.updated_at").bind(session.user_id,practiceId,JSON.stringify(specialties),JSON.stringify(languages),JSON.stringify(modes),gender,fee,exp,b.accepting_clients===false?0:1,now()).run();
    await audit(env,session.user_id,practiceId,"dietitian.profile_updated","dietitian_profile",session.user_id);
    return json({success:true,message:"Profile saved. It will appear in the client directory after Super Admin verification."},200,headers);
   }
   if(path==="/dietitian/requests"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const rows=await env.DB.prepare("SELECT r.id,r.practice_id,r.client_user_id,r.dietitian_user_id,r.message,r.status,r.created_at,p.name AS practice_name,c.display_name AS client_name,c.email AS client_email,d.display_name AS dietitian_name FROM dietitian_requests r JOIN practices p ON p.id=r.practice_id JOIN app_users c ON c.id=r.client_user_id JOIN app_users d ON d.id=r.dietitian_user_id WHERE r.client_user_id=? OR r.dietitian_user_id=? ORDER BY r.created_at DESC LIMIT 200").bind(session.user_id,session.user_id).all();
    return json({success:true,requests:rows.results||[]},200,headers);
   }
   if(path==="/dietitian/requests"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),practiceId=clean(b.practice_id,80),dietitianId=clean(b.dietitian_user_id,80),message=clean(b.message,1000);
    const practice=await env.DB.prepare("SELECT id FROM practices WHERE id=? AND status='active'").bind(practiceId).first();
    if(!practice)return json({success:false,message:"Active practice not found."},404,headers);
    const found=await env.DB.prepare("SELECT dp.user_id FROM dietitian_profiles dp JOIN dietitian_directory dd ON dd.user_id=dp.user_id AND dd.practice_id=dp.practice_id JOIN practices p ON p.id=dp.practice_id WHERE dp.practice_id=? AND dp.user_id=? AND dp.verification_status='verified' AND dd.accepting_clients=1 AND p.status='active'").bind(practiceId,dietitianId).first();
    if(!found)return json({success:false,message:"This dietitian is not available for selection."},404,headers);
    await env.DB.prepare("INSERT INTO practice_memberships(id,practice_id,user_id,role,status) VALUES(?,?,?,'client','active') ON CONFLICT(practice_id,user_id) DO NOTHING").bind(id(),practiceId,session.user_id).run();
    await env.DB.prepare("INSERT INTO client_profiles(id,practice_id,user_id) VALUES(?,?,?) ON CONFLICT(practice_id,user_id) DO NOTHING").bind(id(),practiceId,session.user_id).run();
    const requestId=id();
    await env.DB.prepare("INSERT INTO dietitian_requests(id,practice_id,client_user_id,dietitian_user_id,message) VALUES(?,?,?,?,?) ON CONFLICT(client_user_id,practice_id,dietitian_user_id) DO UPDATE SET message=excluded.message,status='pending',updated_at=?").bind(requestId,practiceId,session.user_id,dietitianId,message,now()).run();
    await audit(env,session.user_id,practiceId,"dietitian.requested","dietitian_request",requestId);
    return json({success:true,message:"Request sent to the dietitian."},201,headers);
   }
   const requestMatch=path.match(/^\/dietitian\/requests\/([a-f0-9-]+)\/decision$/);
   if(requestMatch&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),status=clean(b.status,20);
    if(!["accepted","declined"].includes(status))return json({success:false,message:"Invalid decision."},400,headers);
    const req=await env.DB.prepare("SELECT * FROM dietitian_requests WHERE id=?").bind(requestMatch[1]).first();
    if(!req||req.dietitian_user_id!==session.user_id)return json({success:false,message:"Request not found."},404,headers);
    const membership=session.memberships.find(m=>m.practice_id===req.practice_id&&m.role==="dietitian"&&m.status==="active");
    if(!membership&&!session.is_platform_admin)return json({success:false,message:"Dietitian access required."},403,headers);
    if(status==="accepted"){
      let sub=await env.DB.prepare("SELECT s.id,s.status,s.trial_ends_at,s.current_period_end,p.patient_limit,p.is_unlimited FROM dietitian_subscriptions s JOIN subscription_plans p ON p.id=s.plan_id WHERE s.user_id=?").bind(session.user_id).first();
      if(!sub){
       const basic=await env.DB.prepare("SELECT id,trial_days FROM subscription_plans WHERE slug='basic' AND is_active=1").first();
       if(basic){const start=now(),end=new Date(Date.now()+Number(basic.trial_days||14)*86400000).toISOString();await env.DB.prepare("INSERT OR IGNORE INTO dietitian_subscriptions(id,user_id,plan_id,status,trial_ends_at,current_period_start,current_period_end) VALUES(?,?,?,'trialing',?,?,?)").bind(id(),session.user_id,basic.id,end,start,end).run();sub=await env.DB.prepare("SELECT s.id,s.status,s.trial_ends_at,s.current_period_end,p.patient_limit,p.is_unlimited FROM dietitian_subscriptions s JOIN subscription_plans p ON p.id=s.plan_id WHERE s.user_id=?").bind(session.user_id).first();}
      }
      if(!sub)return json({success:false,message:"No active subscription or trial is available. Please contact Superadmin."},402,headers);
      if(["trialing","active","comped"].includes(sub.status)&&((sub.status==="trialing"&&sub.trial_ends_at&&Date.parse(sub.trial_ends_at)<=Date.now())||(sub.current_period_end&&Date.parse(sub.current_period_end)<=Date.now()))){await env.DB.prepare("UPDATE dietitian_subscriptions SET status='expired',updated_at=? WHERE id=?").bind(now(),sub.id).run();sub.status="expired";}
      if(!["trialing","active","comped"].includes(sub.status))return json({success:false,message:"Your plan does not currently allow new patient connections. Contact Superadmin or renew your subscription."},402,headers);
      const used=await env.DB.prepare("SELECT COUNT(DISTINCT user_id) AS n FROM (SELECT client_user_id AS user_id FROM dietitian_requests WHERE dietitian_user_id=? AND status='accepted' AND id<>? UNION SELECT user_id FROM client_profiles WHERE assigned_dietitian_user_id=? AND user_id<>?)").bind(session.user_id,req.id,session.user_id,req.client_user_id).first();
      if(!sub.is_unlimited&&Number(used?.n||0)>=Number(sub.patient_limit||1))return json({success:false,message:"This plan's patient limit has been reached. Upgrade the plan or adjust the subscription in Superadmin."},409,headers);
     }
     await env.DB.prepare("UPDATE dietitian_requests SET status=?,updated_at=? WHERE id=?").bind(status,now(),req.id).run();
    if(status==="accepted"){
      await env.DB.prepare("INSERT INTO client_profiles(id,practice_id,user_id,assigned_dietitian_user_id) VALUES(?,?,?,?) ON CONFLICT(practice_id,user_id) DO UPDATE SET assigned_dietitian_user_id=excluded.assigned_dietitian_user_id").bind(id(),req.practice_id,req.client_user_id,session.user_id).run();
      await env.DB.prepare("INSERT INTO conversations(id,practice_id,client_user_id,dietitian_user_id,status) VALUES(?,?,?,?,'open')").bind(id(),req.practice_id,req.client_user_id,session.user_id).run();
    }
    await audit(env,session.user_id,req.practice_id,"dietitian.request_"+status,"dietitian_request",req.id);
    return json({success:true,message:"Request "+status+"."},200,headers);
   }

   // Dietitian patient-management workspace
   if(path==="/dietitian/patients/invite"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="dietitian"||session.is_platform_admin)return json({success:false,message:"Dietitian access required."},403,headers);
    if(!env.RESEND_API_KEY||!env.MAIL_FROM)return json({success:false,message:"Patient invitation email is not configured. No account was created."},503,headers);
    const b=await body(request),practiceId=clean(b.practice_id,80),name=clean(b.full_name,120),email=clean(b.email,254).toLowerCase(),phone=clean(b.mobile,24).replace(/[\s()+.-]/g,"");
    const member=session.memberships.find(x=>x.practice_id===practiceId&&x.role==="dietitian"&&x.status==="active");
    if(!member)return json({success:false,message:"Active dietitian practice membership required."},403,headers);
    if(name.length<2||!emailOk(email)||!/^[0-9]{7,15}$/.test(phone))return json({success:false,message:"Enter a valid patient name, email and mobile number."},400,headers);
    const duplicate=await env.DB.prepare("SELECT id FROM app_users WHERE email=? COLLATE NOCASE OR phone=? LIMIT 1").bind(email,phone).first();
    if(duplicate)return json({success:false,message:"An account already exists for this email or mobile. No duplicate was created."},409,headers);
    const dob=clean(b.date_of_birth,10);
    if(dob&&!/^\d{4}-\d{2}-\d{2}$/.test(dob))return json({success:false,message:"Enter a valid date of birth."},400,headers);
    const token=randomToken(32),inviteId=id(),userId=id(),expires=new Date(Date.now()+7*24*60*60*1000).toISOString();
    const profile=b.profile&&typeof b.profile==="object"&&!Array.isArray(b.profile)?b.profile:{};
    const safeProfile={};
    for(const [k,v] of Object.entries(profile))if(typeof v==="string"||typeof v==="number"||typeof v==="boolean"||v===null)safeProfile[clean(k,80)]=typeof v==="string"?clean(v,1200):v;
    safeProfile.intake_source="dietitian_added";
    await env.DB.prepare("INSERT INTO app_users(id,email,display_name,phone,status,account_type) VALUES(?,?,?,?,'invited','client')").bind(userId,email,name,phone).run();
    await env.DB.prepare("INSERT INTO practice_memberships(id,practice_id,user_id,role,status) VALUES(?,?,?,'client','invited')").bind(id(),practiceId,userId).run();
    await env.DB.prepare("INSERT INTO client_profiles(id,practice_id,user_id,assigned_dietitian_user_id,date_of_birth,preferred_name,onboarding_status) VALUES(?,?,?,?,?,?, 'incomplete')").bind(id(),practiceId,userId,session.user_id,dob||null,clean(b.preferred_name,120)||name).run();
    // Create the private chat thread at the same time as the direct patient assignment.
    const existingChat=await env.DB.prepare("SELECT id FROM conversations WHERE practice_id=? AND client_user_id=? AND dietitian_user_id=? AND status='open' LIMIT 1").bind(practiceId,userId,session.user_id).first();
    if(!existingChat)await env.DB.prepare("INSERT INTO conversations(id,practice_id,client_user_id,dietitian_user_id,status) VALUES(?,?,?,?,'open')").bind(id(),practiceId,userId,session.user_id).run();
    await env.DB.prepare("INSERT INTO clinical_records(id,practice_id,client_user_id,dietitian_user_id,profile_json,patient_notes,status) VALUES(?,?,?,?,?,?,'draft')").bind(id(),practiceId,userId,session.user_id,JSON.stringify(safeProfile),clean(b.patient_notes,4000)).run();
    await env.DB.prepare("INSERT INTO practice_invitations(id,practice_id,email,role,invited_by_user_id,token_hash,expires_at) VALUES(?,?,?,'client',?,?,?)").bind(inviteId,practiceId,email,session.user_id,await hash(token),expires).run();
    const acceptUrl="https://prachisayani.online/portal.html#invite="+encodeURIComponent(token);
    try {
     const r=await fetch("https://api.resend.com/emails",{method:"POST",headers:{Authorization:"Bearer "+env.RESEND_API_KEY,"Content-Type":"application/json"},body:JSON.stringify({from:env.MAIL_FROM,to:[email],subject:"Activate your patient account",text:"Hello "+name+", "+session.display_name+" has invited you to "+member.practice_name+". Set your own password using this one-time link (expires in 7 days): "+acceptUrl,html:"<p>Hello "+name.replace(/[&<>"]/g,"")+". Your dietitian has invited you to their nutrition care workspace.</p><p><a href='"+acceptUrl+"'>Activate your patient account</a></p><p>This secure one-time link expires in 7 days.</p>"})});
     if(!r.ok)throw new Error("email_send_failed");
    } catch(e) {
     await env.DB.prepare("DELETE FROM clinical_records WHERE practice_id=? AND client_user_id=? AND dietitian_user_id=?").bind(practiceId,userId,session.user_id).run();
     await env.DB.prepare("DELETE FROM client_profiles WHERE practice_id=? AND user_id=?").bind(practiceId,userId).run();
     await env.DB.prepare("DELETE FROM practice_memberships WHERE practice_id=? AND user_id=?").bind(practiceId,userId).run();
     await env.DB.prepare("DELETE FROM practice_invitations WHERE id=?").bind(inviteId).run();
     await env.DB.prepare("DELETE FROM app_users WHERE id=?").bind(userId).run();
     return json({success:false,message:"Invitation email could not be delivered. No patient account was created; please try again."},502,headers);
    }
    await audit(env,session.user_id,practiceId,"patient.invited","patient",userId,{email});
    return json({success:true,message:"Secure patient invitation sent. Their account activates after they create their password.",patient_id:userId},201,headers);
   }
   if(path==="/dietitian/patients/activate"&&request.method==="POST") {
    const b=await body(request),token=clean(b.token,128),password=b.password;
    if(token.length<32||!validPassword(password)||password!==b.confirm_password)return json({success:false,message:"Enter matching passwords of at least 10 characters with letters and numbers."},400,headers);
    const invite=await env.DB.prepare("SELECT * FROM practice_invitations WHERE token_hash=? AND role='client' AND status='pending' AND expires_at>?").bind(await hash(token),now()).first();
    if(!invite)return json({success:false,message:"Invitation is invalid, expired or already used. Ask your dietitian to send a new one."},400,headers);
    const user=await env.DB.prepare("SELECT id,email,status FROM app_users WHERE email=? COLLATE NOCASE").bind(invite.email).first();
    if(!user||user.status!=="invited")return json({success:false,message:"Patient invitation is no longer available."},409,headers);
    const stamp=now(),stored=await passwordHash(password);
    await env.DB.prepare("UPDATE app_users SET password_hash=?,status='active',updated_at=? WHERE id=? AND status='invited'").bind(stored,stamp,user.id).run();
    await env.DB.prepare("UPDATE practice_memberships SET status='active' WHERE practice_id=? AND user_id=? AND role='client' AND status='invited'").bind(invite.practice_id,user.id).run();
    await env.DB.prepare("UPDATE practice_invitations SET status='accepted',accepted_at=? WHERE id=? AND status='pending'").bind(stamp,invite.id).run();
    await env.DB.prepare("UPDATE client_profiles SET onboarding_status='submitted' WHERE practice_id=? AND user_id=?").bind(invite.practice_id,user.id).run();
    const established=await establishSession(env,user.id,headers);
    await audit(env,user.id,invite.practice_id,"patient.account_activated","patient",user.id);
    return json({success:true,message:"Patient account activated.",session_token:established.token,user:{id:user.id,email:user.email,account_type:"client"}},200,established.headers);
   }
   if(path==="/dietitian/patients"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const practiceId=clean(url.searchParams.get("practice_id"),80);
    const member=session.memberships.find(m=>m.practice_id===practiceId&&m.role==="dietitian"&&m.status==="active");
    if(!member&&!session.is_platform_admin)return json({success:false,message:"Active dietitian membership required."},403,headers);
    const rows=await env.DB.prepare("SELECT cp.user_id AS client_user_id,cp.preferred_name,cp.date_of_birth,cp.onboarding_status,u.display_name,u.email,cp.practice_id,p.name AS practice_name,cp.created_at,(SELECT COUNT(*) FROM diet_plans dp WHERE dp.practice_id=cp.practice_id AND dp.client_user_id=cp.user_id AND dp.dietitian_user_id=? AND dp.status!='archived') AS plan_count,(SELECT MAX(a.starts_at) FROM appointments a WHERE a.practice_id=cp.practice_id AND a.client_user_id=cp.user_id AND a.dietitian_user_id=?) AS next_appointment FROM client_profiles cp JOIN app_users u ON u.id=cp.user_id JOIN practices p ON p.id=cp.practice_id WHERE cp.practice_id=? AND (cp.assigned_dietitian_user_id=? OR EXISTS(SELECT 1 FROM dietitian_requests r WHERE r.practice_id=cp.practice_id AND r.client_user_id=cp.user_id AND r.dietitian_user_id=? AND r.status='accepted')) AND u.status IN ('active','invited') ORDER BY u.display_name LIMIT 300").bind(session.user_id,session.user_id,practiceId,session.user_id,session.user_id).all();
    return json({success:true,patients:rows.results||[]},200,headers);
   }
   // Shared account-level measurements: the client tracker and connected care team
   // read and write the same records. Client identity is taken from the session.
   if(path==="/client/measurements"&&(request.method==="GET"||request.method==="POST")) {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="client")return json({success:false,message:"Client account required."},403,headers);
    if(request.method==="GET"){
     const rows=await env.DB.prepare("SELECT m.id,m.measurement_date AS date,m.weight_kg AS weight,m.height_cm AS height,m.bmi,m.recorded_by_role,m.note,m.created_at,u.display_name AS recorded_by_name FROM patient_measurements m LEFT JOIN app_users u ON u.id=m.recorded_by_user_id WHERE m.client_user_id=? ORDER BY m.measurement_date DESC,m.created_at DESC LIMIT 500").bind(session.user_id).all();
     return json({success:true,measurements:rows.results||[]},200,headers);
    }
    const b=await body(request),date=clean(b.date,10),weight=Number(b.weight),height=Number(b.height);
    if(!/^\d{4}-\d{2}-\d{2}$/.test(date)||!Number.isFinite(Date.parse(date+"T12:00:00Z"))||!(weight>0&&weight<500&&height>=50&&height<260))return json({success:false,message:"Enter a valid measurement date, weight and height."},400,headers);
    const measurementId=clean(b.id,80)||id(),bmi=Number((weight/((height/100)**2)).toFixed(1)),stamp=now();
    await env.DB.prepare("INSERT INTO patient_measurements(id,client_user_id,measurement_date,weight_kg,height_cm,bmi,recorded_by_user_id,recorded_by_role,note,created_at) VALUES(?,?,?,?,?,?,?,'client',?,?) ON CONFLICT(id) DO NOTHING").bind(measurementId,session.user_id,date,weight,height,bmi,session.user_id,clean(b.note,500),stamp).run();
    await audit(env,session.user_id,null,"patient_measurement.created","patient_measurement",measurementId,{measurement_date:date,source:"client"});
    return json({success:true,message:"Measurement saved securely.",measurement:{id:measurementId,date,weight,height,bmi,recorded_by_role:"client",created_at:stamp}},201,headers);
   }
   const clientMeasurementDelete=path.match(/^\/client\/measurements\/([a-zA-Z0-9_-]+)$/);
   if(clientMeasurementDelete&&request.method==="DELETE"){
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="client")return json({success:false,message:"Client account required."},403,headers);
    const existing=await env.DB.prepare("SELECT id FROM patient_measurements WHERE id=? AND client_user_id=? AND recorded_by_role='client'").bind(clientMeasurementDelete[1],session.user_id).first();
    if(!existing)return json({success:false,message:"Measurement not found or cannot be deleted by this account."},404,headers);
    await env.DB.prepare("DELETE FROM patient_measurements WHERE id=? AND client_user_id=? AND recorded_by_role='client'").bind(existing.id,session.user_id).run();
    await audit(env,session.user_id,null,"patient_measurement.deleted","patient_measurement",existing.id);
    return json({success:true,message:"Measurement deleted."},200,headers);
   }
   // Patient hydration log, stored server-side and scoped to the signed-in client.
   if(path==="/client/water"&&(request.method==="GET"||request.method==="POST")){
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="client")return json({success:false,message:"Client account required."},403,headers);
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS patient_water_logs (id TEXT PRIMARY KEY, client_user_id TEXT NOT NULL, log_date TEXT NOT NULL, amount_ml INTEGER NOT NULL CHECK(amount_ml>0 AND amount_ml<=3000), created_at TEXT NOT NULL)").run();
    const date=clean(url.searchParams.get("date"),10)||new Date().toISOString().slice(0,10);
    if(request.method==="GET"){
     const rows=await env.DB.prepare("SELECT id,log_date AS date,amount_ml,created_at FROM patient_water_logs WHERE client_user_id=? AND log_date=? ORDER BY created_at").bind(session.user_id,date).all();
     return json({success:true,entries:rows.results||[]},200,headers);
    }
    const b=await body(request),logDate=clean(b.date,10)||date,amount=Math.round(Number(b.amount_ml));
    if(!/^\d{4}-\d{2}-\d{2}$/.test(logDate)||!Number.isFinite(Date.parse(logDate+"T12:00:00Z"))||!(amount>0&&amount<=3000))return json({success:false,message:"Enter a valid date and water amount."},400,headers);
    const entryId=id(),stamp=now();
    await env.DB.prepare("INSERT INTO patient_water_logs(id,client_user_id,log_date,amount_ml,created_at) VALUES(?,?,?,?,?)").bind(entryId,session.user_id,logDate,amount,stamp).run();
    await audit(env,session.user_id,null,"patient_water_log.created","patient_water_log",entryId,{date:logDate,amount_ml:amount});
    return json({success:true,message:"Water intake saved.",entry:{id:entryId,date:logDate,amount_ml:amount,created_at:stamp}},201,headers);
   }
   const waterDelete=path.match(/^\/client\/water\/([a-f0-9-]+)$/);
   if(waterDelete&&request.method==="DELETE"){
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="client")return json({success:false,message:"Client account required."},403,headers);
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS patient_water_logs (id TEXT PRIMARY KEY, client_user_id TEXT NOT NULL, log_date TEXT NOT NULL, amount_ml INTEGER NOT NULL CHECK(amount_ml>0 AND amount_ml<=3000), created_at TEXT NOT NULL)").run();
    const result=await env.DB.prepare("DELETE FROM patient_water_logs WHERE id=? AND client_user_id=?").bind(waterDelete[1],session.user_id).run();
    if(!result.meta?.changes)return json({success:false,message:"Water entry not found."},404,headers);
    return json({success:true,message:"Water entry deleted."},200,headers);
   }
   // Patient-entered daily food diary, shared with the connected dietitian.
   if(path==="/client/food-diary"&&(request.method==="GET"||request.method==="POST")) {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="client")return json({success:false,message:"Client account required."},403,headers);
    if(request.method==="GET"){
     const date=clean(url.searchParams.get("date"),10);
     const rows=await env.DB.prepare("SELECT id,diary_date AS date,meal_slot,meal_time,food_description,quantity,note,created_at FROM patient_food_diary WHERE client_user_id=? AND (?='' OR diary_date=?) ORDER BY diary_date DESC,CASE meal_slot WHEN 'Early morning' THEN 1 WHEN 'Breakfast' THEN 2 WHEN 'Mid-morning' THEN 3 WHEN 'Lunch' THEN 4 WHEN 'Evening snack' THEN 5 WHEN 'Dinner' THEN 6 WHEN 'Bedtime' THEN 7 ELSE 8 END,meal_time,created_at LIMIT 1000").bind(session.user_id,date,date).all();
     return json({success:true,entries:rows.results||[]},200,headers);
    }
    const b=await body(request),date=clean(b.date,10),slot=clean(b.meal_slot,40),time=clean(b.meal_time,5),food=clean(b.food_description,1200),quantity=clean(b.quantity,160),note=clean(b.note,500);
    const slots=['Early morning','Breakfast','Mid-morning','Lunch','Evening snack','Dinner','Bedtime','Other'];
    if(!/^\d{4}-\d{2}-\d{2}$/.test(date)||!Number.isFinite(Date.parse(date+"T12:00:00Z"))||!slots.includes(slot)||!food)return json({success:false,message:"Enter a valid date, meal and food description."},400,headers);
    if(time&&!/^([01]\d|2[0-3]):[0-5]\d$/.test(time))return json({success:false,message:"Enter a valid meal time."},400,headers);
    const entryId=id(),stamp=now();
    await env.DB.prepare("INSERT INTO patient_food_diary(id,client_user_id,diary_date,meal_slot,meal_time,food_description,quantity,note,recorded_by_user_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(entryId,session.user_id,date,slot,time,food,quantity,note,session.user_id,stamp).run();
    await audit(env,session.user_id,null,"patient_food_diary.created","patient_food_diary",entryId,{date,meal_slot:slot});
    return json({success:true,message:"Food diary entry saved and shared with your dietitian.",entry:{id:entryId,date,meal_slot:slot,meal_time:time,food_description:food,quantity,note,created_at:stamp}},201,headers);
   }
   const foodDiaryDelete=path.match(/^\/client\/food-diary\/([a-f0-9-]+)$/);
   if(foodDiaryDelete&&request.method==="DELETE"){
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="client")return json({success:false,message:"Client account required."},403,headers);
    const existing=await env.DB.prepare("SELECT id FROM patient_food_diary WHERE id=? AND client_user_id=?").bind(foodDiaryDelete[1],session.user_id).first();
    if(!existing)return json({success:false,message:"Food diary entry not found."},404,headers);
    await env.DB.prepare("DELETE FROM patient_food_diary WHERE id=? AND client_user_id=?").bind(existing.id,session.user_id).run();
    return json({success:true,message:"Food diary entry deleted."},200,headers);
   }
   if(path==="/client/connection"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="client")return json({success:false,message:"Patient access required."},403,headers);
    const rows=await env.DB.prepare("SELECT cp.practice_id,cp.assigned_dietitian_user_id AS dietitian_user_id,du.display_name AS dietitian_name,du.email AS dietitian_email,p.name AS practice_name,dp.profile_photo_data_url AS dietitian_photo,'assigned' AS connection_type FROM client_profiles cp JOIN app_users du ON du.id=cp.assigned_dietitian_user_id LEFT JOIN practices p ON p.id=cp.practice_id LEFT JOIN dietitian_profiles dp ON dp.user_id=du.id WHERE cp.user_id=? AND cp.assigned_dietitian_user_id IS NOT NULL UNION SELECT r.practice_id,r.dietitian_user_id,du.display_name AS dietitian_name,du.email AS dietitian_email,p.name AS practice_name,dp.profile_photo_data_url AS dietitian_photo,'accepted' AS connection_type FROM dietitian_requests r JOIN app_users du ON du.id=r.dietitian_user_id LEFT JOIN practices p ON p.id=r.practice_id LEFT JOIN dietitian_profiles dp ON dp.user_id=du.id WHERE r.client_user_id=? AND r.status='accepted' ORDER BY practice_name,dietitian_name").bind(session.user_id,session.user_id).all();
    return json({success:true,connections:rows.results||[]},200,headers);
   }
   if(path==="/client/diet-plans"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const practiceId=clean(url.searchParams.get("practice_id"),80);
    // Clients can view only their own published plans. A client membership is not
    // required when a dietitian has connected the client through an accepted request.
    const rows=await env.DB.prepare("SELECT dp.id,dp.practice_id,dp.client_user_id,dp.dietitian_user_id,dp.title,dp.status,dp.current_version,dp.created_at,dp.updated_at,p.name AS practice_name,u.display_name AS dietitian_name FROM diet_plans dp JOIN practices p ON p.id=dp.practice_id LEFT JOIN app_users u ON u.id=dp.dietitian_user_id WHERE (?='' OR dp.practice_id=?) AND dp.client_user_id=? AND dp.status='published' AND p.status='active' ORDER BY dp.updated_at DESC LIMIT 100").bind(practiceId,practiceId,session.user_id).all();
    const plans=[];for(const p of rows.results||[]){const v=await env.DB.prepare("SELECT plan_json,notes,version_number,published_at FROM diet_plan_versions WHERE plan_id=? AND version_number=?").bind(p.id,p.current_version).first();plans.push({...p,plan:v?JSON.parse(v.plan_json||"{}"):{},notes:v?.notes||"",published_at:v?.published_at||null});}
    return json({success:true,plans},200,headers);
   }
   if(path==="/dietitian/plans"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const clientId=clean(url.searchParams.get("client_user_id"),80),practiceId=clean(url.searchParams.get("practice_id"),80);
    const member=session.memberships.find(m=>m.practice_id===practiceId&&m.role==="dietitian"&&m.status==="active");
    if(!member&&!session.is_platform_admin)return json({success:false,message:"Active dietitian membership required."},403,headers);
    const rows=await env.DB.prepare("SELECT id,practice_id,client_user_id,dietitian_user_id,title,status,current_version,created_at,updated_at FROM diet_plans WHERE practice_id=? AND dietitian_user_id=? AND (?='' OR client_user_id=?) ORDER BY updated_at DESC LIMIT 200").bind(practiceId,session.user_id,clientId,clientId).all();
    const plans=[];
    for(const p of rows.results||[]){const v=await env.DB.prepare("SELECT plan_json,notes,version_number FROM diet_plan_versions WHERE plan_id=? AND version_number=?").bind(p.id,p.current_version).first();plans.push({...p,plan:v?JSON.parse(v.plan_json||"{}"):{},notes:v?.notes||""});}
    return json({success:true,plans},200,headers);
   }
   if(path==="/dietitian/plans"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),practiceId=clean(b.practice_id,80),clientId=clean(b.client_user_id,80),title=clean(b.title,160)||"Nutrition care plan";
    const member=session.memberships.find(m=>m.practice_id===practiceId&&m.role==="dietitian"&&m.status==="active");
    if(!member&&!session.is_platform_admin)return json({success:false,message:"Active dietitian membership required."},403,headers);
    const connected=await env.DB.prepare("SELECT 1 AS ok FROM dietitian_requests WHERE practice_id=? AND client_user_id=? AND dietitian_user_id=? AND status='accepted' UNION SELECT 1 AS ok FROM client_profiles WHERE practice_id=? AND user_id=? AND assigned_dietitian_user_id=? LIMIT 1").bind(practiceId,clientId,session.user_id,practiceId,clientId,session.user_id).first();
    if(!connected)return json({success:false,message:"A client must accept/connect with you before you can create their plan."},403,headers);
    const planId=id(),plan=b.plan&&typeof b.plan==="object"?b.plan:{meals:[]},notes=clean(b.notes,3000),status=b.publish===true?"published":"draft";
    await env.DB.prepare("INSERT INTO diet_plans(id,practice_id,client_user_id,dietitian_user_id,title,status,current_version) VALUES(?,?,?,?,?,?,1)").bind(planId,practiceId,clientId,session.user_id,title,status).run();
    await env.DB.prepare("INSERT INTO diet_plan_versions(id,plan_id,version_number,plan_json,notes,published_at,created_by_user_id) VALUES(?,?,1,?,?,?,?)").bind(id(),planId,JSON.stringify(plan),notes,status==="published"?now():null,session.user_id).run();
    await audit(env,session.user_id,practiceId,"diet_plan.created","diet_plan",planId,{client_user_id:clientId,status});
    return json({success:true,plan_id:planId,message:status==="published"?"Diet chart published to the client.":"Diet chart saved as draft."},201,headers);
   }
   const planMatch=path.match(/^\/dietitian\/plans\/([a-f0-9-]+)$/);
   if(planMatch&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),existing=await env.DB.prepare("SELECT * FROM diet_plans WHERE id=?").bind(planMatch[1]).first();
    if(!existing)return json({success:false,message:"Diet chart not found."},404,headers);
    if(existing.dietitian_user_id!==session.user_id&&!session.is_platform_admin)return json({success:false,message:"Only the assigned dietitian can edit this chart."},403,headers);
    const member=session.memberships.find(m=>m.practice_id===existing.practice_id&&m.role==="dietitian"&&m.status==="active");
    if(!member&&!session.is_platform_admin)return json({success:false,message:"Active dietitian membership required."},403,headers);
    const version=existing.current_version+1,status=b.publish===true?"published":clean(b.status,20)==="archived"?"archived":"draft";
    await env.DB.prepare("INSERT INTO diet_plan_versions(id,plan_id,version_number,plan_json,notes,published_at,created_by_user_id) VALUES(?,?,?,?,?,?,?)").bind(id(),existing.id,version,JSON.stringify(b.plan&&typeof b.plan==="object"?b.plan:{}),clean(b.notes,3000),status==="published"?now():null,session.user_id).run();
    await env.DB.prepare("UPDATE diet_plans SET title=?,status=?,current_version=?,updated_at=? WHERE id=?").bind(clean(b.title,160)||existing.title,status,version,now(),existing.id).run();
    await audit(env,session.user_id,existing.practice_id,"diet_plan.updated","diet_plan",existing.id,{version,status});
    return json({success:true,message:status==="published"?"Diet chart published to the client.":"Diet chart updated.",version},200,headers);
   }
   if(path==="/dietitian/conversations"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const practiceId=clean(url.searchParams.get("practice_id"),80),clientId=clean(url.searchParams.get("client_user_id"),80);
    // Patient inbox: list every active connection assigned to this account, including patients added directly by their dietitian.
    if(session.account_type==="client"){
     const assigned=await env.DB.prepare("SELECT cp.practice_id,cp.assigned_dietitian_user_id FROM client_profiles cp JOIN practice_memberships pm ON pm.practice_id=cp.practice_id AND pm.user_id=cp.user_id WHERE cp.user_id=? AND pm.role='client' AND pm.status IN ('active','invited') AND cp.assigned_dietitian_user_id IS NOT NULL UNION SELECT r.practice_id,r.dietitian_user_id FROM dietitian_requests r WHERE r.client_user_id=? AND r.status='accepted'").bind(session.user_id,session.user_id).all();
     for(const link of assigned.results||[]){
      const existing=await env.DB.prepare("SELECT id FROM conversations WHERE practice_id=? AND client_user_id=? AND dietitian_user_id=? AND status='open' LIMIT 1").bind(link.practice_id,session.user_id,link.assigned_dietitian_user_id).first();
      if(!existing)await env.DB.prepare("INSERT INTO conversations(id,practice_id,client_user_id,dietitian_user_id,status) VALUES(?,?,?,?,'open')").bind(id(),link.practice_id,session.user_id,link.assigned_dietitian_user_id).run();
     }
     const rows=await env.DB.prepare("SELECT c.id,c.practice_id,c.client_user_id,c.dietitian_user_id,c.status,c.updated_at,cu.display_name AS client_name,du.display_name AS dietitian_name FROM conversations c JOIN app_users cu ON cu.id=c.client_user_id LEFT JOIN app_users du ON du.id=c.dietitian_user_id WHERE c.client_user_id=? AND c.status='open' ORDER BY c.updated_at DESC LIMIT 100").bind(session.user_id).all();
     return json({success:true,conversations:rows.results||[]},200,headers);
    }
    if(!practiceId)return json({success:false,message:"Practice is required."},400,headers);
    // Backfill a thread for each directly assigned patient so older connections work too.
    const assigned=await env.DB.prepare("SELECT user_id AS client_user_id,assigned_dietitian_user_id FROM client_profiles WHERE practice_id=? AND assigned_dietitian_user_id=?").bind(practiceId,session.user_id).all();
    for(const link of assigned.results||[]){
     const existing=await env.DB.prepare("SELECT id FROM conversations WHERE practice_id=? AND client_user_id=? AND dietitian_user_id=? AND status='open' LIMIT 1").bind(practiceId,link.client_user_id,session.user_id).first();
     if(!existing)await env.DB.prepare("INSERT INTO conversations(id,practice_id,client_user_id,dietitian_user_id,status) VALUES(?,?,?,?,'open')").bind(id(),practiceId,link.client_user_id,session.user_id).run();
    }
    const rows=await env.DB.prepare("SELECT c.id,c.practice_id,c.client_user_id,c.dietitian_user_id,c.status,c.updated_at,cu.display_name AS client_name,du.display_name AS dietitian_name FROM conversations c JOIN app_users cu ON cu.id=c.client_user_id LEFT JOIN app_users du ON du.id=c.dietitian_user_id WHERE c.practice_id=? AND (c.client_user_id=? OR c.dietitian_user_id=?) AND (?='' OR c.client_user_id=?) AND c.status='open' ORDER BY c.updated_at DESC LIMIT 100").bind(practiceId,session.user_id,session.user_id,clientId,clientId).all();
    return json({success:true,conversations:rows.results||[]},200,headers);
   }
   if(path==="/dietitian/messages"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const conversationId=clean(url.searchParams.get("conversation_id"),80);
    const convo=await env.DB.prepare("SELECT * FROM conversations WHERE id=? AND (client_user_id=? OR dietitian_user_id=?)").bind(conversationId,session.user_id,session.user_id).first();
    if(!convo)return json({success:false,message:"Conversation not found."},404,headers);
    const rows=await env.DB.prepare("SELECT m.id,m.sender_user_id,m.body,m.created_at,m.read_at,u.display_name AS sender_name FROM messages m JOIN app_users u ON u.id=m.sender_user_id WHERE m.conversation_id=? ORDER BY m.created_at ASC LIMIT 500").bind(conversationId).all();
    await env.DB.prepare("UPDATE messages SET read_at=? WHERE conversation_id=? AND sender_user_id<>? AND read_at IS NULL").bind(now(),conversationId,session.user_id).run();
    return json({success:true,messages:rows.results||[]},200,headers);
   }
   if(path==="/dietitian/messages"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),conversationId=clean(b.conversation_id,80),text=clean(b.body,4000);
    if(!text)return json({success:false,message:"Write a message first."},400,headers);
    const convo=await env.DB.prepare("SELECT * FROM conversations WHERE id=? AND status='open' AND (client_user_id=? OR dietitian_user_id=?)").bind(conversationId,session.user_id,session.user_id).first();
    if(!convo)return json({success:false,message:"Open conversation not found."},404,headers);
    const messageId=id();await env.DB.prepare("INSERT INTO messages(id,conversation_id,sender_user_id,body) VALUES(?,?,?,?)").bind(messageId,conversationId,session.user_id,text).run();
    await env.DB.prepare("UPDATE conversations SET updated_at=? WHERE id=?").bind(now(),conversationId).run();
    return json({success:true,message_id:messageId},201,headers);
   }

   // Dietitian access is restricted to a connected patient in the selected practice.
   if(path==="/dietitian/patient-measurements"&&(request.method==="GET"||request.method==="POST")){
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="dietitian"||session.is_platform_admin)return json({success:false,message:"Dietitian access required."},403,headers);
    const isWrite=request.method==="POST",b=isWrite?await body(request):null;
    const practiceId=clean(isWrite?b.practice_id:url.searchParams.get("practice_id"),80);
    const clientId=clean(isWrite?b.client_user_id:url.searchParams.get("client_user_id"),80);
    if(!practiceId||!clientId)return json({success:false,message:"Practice and patient are required."},400,headers);
    const member=session.memberships.find(m=>m.practice_id===practiceId&&m.role==="dietitian"&&m.status==="active");
    if(!member)return json({success:false,message:"Active dietitian practice membership required."},403,headers);
    const connected=await env.DB.prepare("SELECT 1 AS ok FROM dietitian_requests WHERE practice_id=? AND client_user_id=? AND dietitian_user_id=? AND status='accepted' UNION SELECT 1 AS ok FROM client_profiles WHERE practice_id=? AND user_id=? AND assigned_dietitian_user_id=? LIMIT 1").bind(practiceId,clientId,session.user_id,practiceId,clientId,session.user_id).first();
    if(!connected)return json({success:false,message:"Connected patient not found in this practice."},404,headers);
    if(!isWrite){
     const rows=await env.DB.prepare("SELECT m.id,m.measurement_date AS date,m.weight_kg AS weight,m.height_cm AS height,m.bmi,m.recorded_by_role,m.note,m.created_at,u.display_name AS recorded_by_name FROM patient_measurements m LEFT JOIN app_users u ON u.id=m.recorded_by_user_id WHERE m.client_user_id=? ORDER BY m.measurement_date DESC,m.created_at DESC LIMIT 500").bind(clientId).all();
     return json({success:true,measurements:rows.results||[]},200,headers);
    }
    const date=clean(b.date,10),weight=Number(b.weight),height=Number(b.height);
    if(!/^\d{4}-\d{2}-\d{2}$/.test(date)||!Number.isFinite(Date.parse(date+"T12:00:00Z"))||!(weight>0&&weight<500&&height>=50&&height<260))return json({success:false,message:"Enter a valid measurement date, weight and height."},400,headers);
    const measurementId=id(),bmi=Number((weight/((height/100)**2)).toFixed(1)),stamp=now();
    await env.DB.prepare("INSERT INTO patient_measurements(id,client_user_id,practice_id,measurement_date,weight_kg,height_cm,bmi,recorded_by_user_id,recorded_by_role,note,created_at) VALUES(?,?,?,?,?,?,?,?, 'dietitian',?,?)").bind(measurementId,clientId,practiceId,date,weight,height,bmi,session.user_id,clean(b.note,500),stamp).run();
    await audit(env,session.user_id,practiceId,"patient_measurement.created","patient_measurement",measurementId,{client_user_id:clientId,measurement_date:date,source:"dietitian"});
    return json({success:true,message:"Patient measurement saved to the shared record.",measurement:{id:measurementId,date,weight,height,bmi,recorded_by_role:"dietitian",recorded_by_name:session.display_name,created_at:stamp}},201,headers);
   }
   if(path==="/dietitian/patient-food-diary"&&request.method==="GET"){
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="dietitian"||session.is_platform_admin)return json({success:false,message:"Dietitian access required."},403,headers);
    const practiceId=clean(url.searchParams.get("practice_id"),80),clientId=clean(url.searchParams.get("client_user_id"),80),date=clean(url.searchParams.get("date"),10);
    if(!practiceId||!clientId)return json({success:false,message:"Practice and patient are required."},400,headers);
    const member=session.memberships.find(m=>m.practice_id===practiceId&&m.role==="dietitian"&&m.status==="active");
    if(!member)return json({success:false,message:"Active dietitian practice membership required."},403,headers);
    const connected=await env.DB.prepare("SELECT 1 AS ok FROM dietitian_requests WHERE practice_id=? AND client_user_id=? AND dietitian_user_id=? AND status='accepted' UNION SELECT 1 AS ok FROM client_profiles WHERE practice_id=? AND user_id=? AND assigned_dietitian_user_id=? LIMIT 1").bind(practiceId,clientId,session.user_id,practiceId,clientId,session.user_id).first();
    if(!connected)return json({success:false,message:"Connected patient not found in this practice."},404,headers);
    const rows=await env.DB.prepare("SELECT f.id,f.diary_date AS date,f.meal_slot,f.meal_time,f.food_description,f.quantity,f.note,f.created_at,u.display_name AS recorded_by_name FROM patient_food_diary f LEFT JOIN app_users u ON u.id=f.recorded_by_user_id WHERE f.client_user_id=? AND (?='' OR f.diary_date=?) ORDER BY f.diary_date DESC,CASE f.meal_slot WHEN 'Early morning' THEN 1 WHEN 'Breakfast' THEN 2 WHEN 'Mid-morning' THEN 3 WHEN 'Lunch' THEN 4 WHEN 'Evening snack' THEN 5 WHEN 'Dinner' THEN 6 WHEN 'Bedtime' THEN 7 ELSE 8 END,f.meal_time,f.created_at LIMIT 1000").bind(clientId,date,date).all();
    return json({success:true,entries:rows.results||[]},200,headers);
   }
   if(path==="/dietitian/patient-water"&&request.method==="GET"){
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="dietitian"||session.is_platform_admin)return json({success:false,message:"Dietitian access required."},403,headers);
    const practiceId=clean(url.searchParams.get("practice_id"),80),clientId=clean(url.searchParams.get("client_user_id"),80),date=clean(url.searchParams.get("date"),10);
    if(!practiceId||!clientId||!/^\d{4}-\d{2}-\d{2}$/.test(date)||!Number.isFinite(Date.parse(date+"T12:00:00Z")))return json({success:false,message:"Practice, patient and a valid diary date are required."},400,headers);
    const member=session.memberships.find(m=>m.practice_id===practiceId&&m.role==="dietitian"&&m.status==="active");
    if(!member)return json({success:false,message:"Active dietitian practice membership required."},403,headers);
    const connected=await env.DB.prepare("SELECT 1 AS ok FROM dietitian_requests WHERE practice_id=? AND client_user_id=? AND dietitian_user_id=? AND status='accepted' UNION SELECT 1 AS ok FROM client_profiles WHERE practice_id=? AND user_id=? AND assigned_dietitian_user_id=? LIMIT 1").bind(practiceId,clientId,session.user_id,practiceId,clientId,session.user_id).first();
    if(!connected)return json({success:false,message:"Connected patient not found in this practice."},404,headers);
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS patient_water_logs (id TEXT PRIMARY KEY, client_user_id TEXT NOT NULL, log_date TEXT NOT NULL, amount_ml INTEGER NOT NULL CHECK(amount_ml>0 AND amount_ml<=3000), created_at TEXT NOT NULL)").run();
    const rows=await env.DB.prepare("SELECT id,log_date AS date,amount_ml,created_at FROM patient_water_logs WHERE client_user_id=? AND log_date=? ORDER BY created_at ASC").bind(clientId,date).all();
    return json({success:true,entries:rows.results||[]},200,headers);
   }
   // Practice-scoped clinical nutrition record for an actively connected patient.
   if(path==="/dietitian/clinical-record"&&(request.method==="GET"||request.method==="POST")) {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    if(session.account_type!=="dietitian"||session.is_platform_admin)return json({success:false,message:"Dietitian access required."},403,headers);
    const isWrite=request.method==="POST",b=isWrite?await body(request):null;
    const practiceId=clean(isWrite?b.practice_id:url.searchParams.get("practice_id"),80);
    const clientId=clean(isWrite?b.client_user_id:url.searchParams.get("client_user_id"),80);
    if(!practiceId||!clientId)return json({success:false,message:"Practice and patient are required."},400,headers);
    const member=session.memberships.find(m=>m.practice_id===practiceId&&m.role==="dietitian"&&m.status==="active");
    if(!member)return json({success:false,message:"Active dietitian practice membership required."},403,headers);
    const patient=await env.DB.prepare("SELECT cp.user_id,cp.practice_id,cp.preferred_name,cp.date_of_birth,u.display_name,u.email FROM client_profiles cp JOIN app_users u ON u.id=cp.user_id WHERE cp.practice_id=? AND cp.user_id=? AND (cp.assigned_dietitian_user_id=? OR EXISTS(SELECT 1 FROM dietitian_requests r WHERE r.practice_id=cp.practice_id AND r.client_user_id=cp.user_id AND r.dietitian_user_id=? AND r.status='accepted')) AND u.status='active'").bind(practiceId,clientId,session.user_id,session.user_id).first();
    if(!patient)return json({success:false,message:"Connected patient not found in this practice."},404,headers);
    if(!isWrite){
     const assessment=await env.DB.prepare("SELECT profile_json,patient_notes,status,updated_at FROM clinical_records WHERE practice_id=? AND client_user_id=? AND dietitian_user_id=?").bind(practiceId,clientId,session.user_id).first();
     let profile={};try{profile=JSON.parse(assessment?.profile_json||"{}")}catch{}
     return json({success:true,patient,profile,assessment:assessment?{patient_notes:assessment.patient_notes||"",status:assessment.status||"draft",updated_at:assessment.updated_at}:null},200,headers);
    }
    const profile=b.profile&&typeof b.profile==="object"&&!Array.isArray(b.profile)?b.profile:{};
    const notes=clean(b.patient_notes,4000),status=clean(b.status,20)==="reviewed"?"reviewed":"draft";
    const dob=clean(b.date_of_birth,10),preferred=clean(b.preferred_name,120);
    if(dob&&!/^\\d{4}-\\d{2}-\\d{2}$/.test(dob))return json({success:false,message:"Enter a valid date of birth."},400,headers);
    const stamp=now();
    await env.DB.prepare("INSERT INTO clinical_records(id,practice_id,client_user_id,dietitian_user_id,profile_json,patient_notes,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(practice_id,client_user_id,dietitian_user_id) DO UPDATE SET profile_json=excluded.profile_json,patient_notes=excluded.patient_notes,status=excluded.status,updated_at=excluded.updated_at").bind(id(),practiceId,clientId,session.user_id,JSON.stringify(profile),notes,status,stamp,stamp).run();
    await env.DB.prepare("UPDATE client_profiles SET preferred_name=CASE WHEN ?='' THEN preferred_name ELSE ? END,date_of_birth=CASE WHEN ?='' THEN date_of_birth ELSE ? END WHERE practice_id=? AND user_id=?").bind(preferred,preferred,dob,dob,practiceId,clientId).run();
    await audit(env,session.user_id,practiceId,"clinical_record."+status,"clinical_record",clientId);
    return json({success:true,message:status==="reviewed"?"Clinical record saved and marked reviewed.":"Clinical record draft saved.",status,updated_at:stamp},200,headers);
   }
   if(path==="/dietitian/appointments"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const practiceId=clean(url.searchParams.get("practice_id"),80);
    const rows=await env.DB.prepare("SELECT a.*,cu.display_name AS client_name,du.display_name AS dietitian_name FROM appointments a JOIN app_users cu ON cu.id=a.client_user_id LEFT JOIN app_users du ON du.id=a.dietitian_user_id WHERE a.practice_id=? AND (a.client_user_id=? OR a.dietitian_user_id=?) ORDER BY a.starts_at DESC LIMIT 200").bind(practiceId,session.user_id,session.user_id).all();
    return json({success:true,appointments:rows.results||[]},200,headers);
   }
   if(path==="/dietitian/appointments"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),practiceId=clean(b.practice_id,80),clientId=clean(b.client_user_id,80),starts=clean(b.starts_at,40),ends=clean(b.ends_at,40),notes=clean(b.notes,1000);
    const member=session.memberships.find(m=>m.practice_id===practiceId&&m.role==="dietitian"&&m.status==="active");
    if(!member&&!session.is_platform_admin)return json({success:false,message:"Active dietitian membership required."},403,headers);
    if(!Number.isFinite(Date.parse(starts))||!Number.isFinite(Date.parse(ends))||Date.parse(ends)<=Date.parse(starts))return json({success:false,message:"Choose a valid start and end time."},400,headers);
    const connected=await env.DB.prepare("SELECT 1 AS ok FROM dietitian_requests WHERE practice_id=? AND client_user_id=? AND dietitian_user_id=? AND status='accepted' UNION SELECT 1 AS ok FROM client_profiles WHERE practice_id=? AND user_id=? AND assigned_dietitian_user_id=? LIMIT 1").bind(practiceId,clientId,session.user_id,practiceId,clientId,session.user_id).first();
    if(!connected)return json({success:false,message:"Only connected clients can be scheduled."},403,headers);
    const conflict=await env.DB.prepare("SELECT 1 AS conflict FROM appointments WHERE practice_id=? AND dietitian_user_id=? AND status IN ('requested','confirmed') AND starts_at<? AND ends_at>? LIMIT 1").bind(practiceId,session.user_id,ends,starts).first();
    if(conflict)return json({success:false,message:"This time overlaps another appointment."},409,headers);
    const appointmentId=id();await env.DB.prepare("INSERT INTO appointments(id,practice_id,client_user_id,dietitian_user_id,starts_at,ends_at,status,notes) VALUES(?,?,?,?,?,?,'confirmed',?)").bind(appointmentId,practiceId,clientId,session.user_id,starts,ends,notes).run();
    await audit(env,session.user_id,practiceId,"appointment.scheduled","appointment",appointmentId);
    return json({success:true,appointment_id:appointmentId,message:"Appointment scheduled."},201,headers);
   }

   if(path==="/admin/applicants"&&request.method==="GET") {
    if(!session?.is_platform_admin)return json({success:false,message:"Platform administrator access required."},session?403:401,headers);
    const rows=await env.DB.prepare("SELECT u.id AS user_id,u.display_name,u.email,u.created_at,u.account_type, (SELECT COUNT(*) FROM practice_memberships m WHERE m.user_id=u.id AND m.status='active') AS active_memberships FROM app_users u WHERE u.account_type='dietitian' ORDER BY u.created_at DESC LIMIT 300").all();
    return json({success:true,applicants:rows.results||[]},200,headers);
   }
   if(path==="/admin/applicants/approve"&&request.method==="POST") {
    if(!session?.is_platform_admin)return json({success:false,message:"Platform administrator access required."},session?403:401,headers);
    const b=await body(request),userId=clean(b.user_id,80),practiceId=clean(b.practice_id,80);
    if(!userId)return json({success:false,message:"Applicant account required."},400,headers);
    const applicant=await env.DB.prepare("SELECT id,email,display_name,account_type FROM app_users WHERE id=? AND status='active'").bind(userId).first();
    if(!applicant||applicant.account_type!=="dietitian")return json({success:false,message:"Active dietitian applicant not found."},404,headers);
    let practice=practiceId?await env.DB.prepare("SELECT id,name FROM practices WHERE id=? AND status='active'").bind(practiceId).first():null;
    if(practiceId&&!practice)return json({success:false,message:"Choose an active practice."},400,headers);
    if(!practice){
      practice=await env.DB.prepare("SELECT id,name FROM practices WHERE status='active' ORDER BY created_at LIMIT 1").first();
    }
    if(!practice){
      const pid=id(),slug="prachi-nutrition";
      await env.DB.prepare("INSERT INTO practices(id,name,slug,status) VALUES(?,?,?,'active')").bind(pid,"Prachi Nutrition",slug).run();
      await env.DB.prepare("INSERT INTO practice_settings(practice_id) VALUES(?)").bind(pid).run();
      practice={id:pid,name:"Prachi Nutrition"};
    }
    await env.DB.prepare("INSERT INTO practice_memberships(id,practice_id,user_id,role,status) VALUES(?,?,?,'dietitian','active') ON CONFLICT(practice_id,user_id) DO UPDATE SET role='dietitian',status='active'").bind(id(),practice.id,userId).run();
    await env.DB.prepare("INSERT OR IGNORE INTO dietitian_profiles(id,practice_id,user_id,verification_status) VALUES(?,?,?,'verified')").bind(id(),practice.id,userId).run();
    await env.DB.prepare("UPDATE dietitian_profiles SET verification_status='verified' WHERE user_id=? AND practice_id=?").bind(userId,practice.id).run();
    await audit(env,session.user_id,practice.id,"dietitian.application_approved","user",userId,{applicant_email:applicant.email});
    return json({success:true,message:"Dietitian approved and added to "+practice.name+".",practice_id:practice.id},200,headers);
   }
   if(path==="/admin/dietitians"&&request.method==="GET") {
    if(!session?.is_platform_admin)return json({success:false,message:"Platform administrator access required."},session?403:401,headers);
    const rows=await env.DB.prepare("SELECT u.id AS user_id,u.display_name,u.email,u.phone,u.status AS user_status,u.created_at,u.account_type,(SELECT COUNT(*) FROM practice_memberships m WHERE m.user_id=u.id AND m.status='active') AS active_memberships,dp.practice_id,p.name AS practice_name,dp.credentials,dp.registration_number,dp.bio,dp.verification_status,dd.specialties_json,dd.languages_json,dd.consultation_modes_json,dd.fee_minor,dd.experience_years,dd.accepting_clients FROM app_users u LEFT JOIN dietitian_profiles dp ON dp.user_id=u.id LEFT JOIN practices p ON p.id=dp.practice_id LEFT JOIN dietitian_directory dd ON dd.user_id=dp.user_id AND dd.practice_id=dp.practice_id WHERE u.account_type='dietitian' ORDER BY u.created_at DESC LIMIT 500").all();
    return json({success:true,dietitians:rows.results||[]},200,headers);
   }
   return json({success:false,message:"Not found."},404,headers);
  } catch (e) {
   console.error("API request failed", { path, message: String(e?.message || e), stack: String(e?.stack || "").slice(0,1200) });
   if(e?.message==="too_large") return json({success:false,message:"Request too large."},413,headers);
   if(e?.message==="rate_limit_not_configured") return json({success:false,message:"Authentication protection is not configured. Please contact support."},503,headers);
   if(e instanceof SyntaxError) return json({success:false,message:"Invalid JSON."},400,headers);
   return json({success:false,message:"The service encountered an error. Please try again later."},500,headers);
  }
 }
};
