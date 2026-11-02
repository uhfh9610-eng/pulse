const ITERATIONS = 120000;
const SESSION_TTL = 60 * 60 * 24 * 30;
const NOMINATION_DAYS = 5;
const VOTING_DAYS = 5;
const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2,'0')).join('');
const uid = () => crypto.randomUUID();
const now = () => Math.floor(Date.now() / 1000);
const DAY = 86400;
const json = (d, s = 200, h = {}) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json; charset=utf-8', ...h } });
const fail = (m, s = 400) => json({ error: m }, s);
function randHex(n){ const a = new Uint8Array(n); crypto.getRandomValues(a); return hex(a); }
async function hashPassword(pw, saltHex){
  const salt = new Uint8Array(saltHex.match(/../g).map(h => parseInt(h,16)));
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name:'PBKDF2', salt, iterations:ITERATIONS, hash:'SHA-256' }, key, 256));
}
async function sha256(s){ return hex(await crypto.subtle.digest('SHA-256', enc.encode(s))); }
function ctEqual(a,b){ if (a.length !== b.length) return false; let r = 0; for (let i=0;i<a.length;i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
function getCookie(req, name){ for (const part of (req.headers.get('Cookie')||'').split(';')) { const [k,...v] = part.trim().split('='); if (k === name) return v.join('='); } return null; }
const sessionCookie = (t, age) => `sid=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
const clientIp = req => req.headers.get('CF-Connecting-IP') || 'unknown';
async function currentUser(req, env){
  const token = getCookie(req,'sid'); if (!token) return null;
  const th = await sha256(token);
  const row = await env.DB.prepare(`SELECT u.id, u.username, s.expires_at, r.role, r.expires_at AS role_exp FROM sessions s JOIN users u ON u.id = s.user_id LEFT JOIN roles r ON r.user_id = u.id WHERE s.token_hash = ?`).bind(th).first();
  if (!row) return null;
  if (row.expires_at < now()){ await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(th).run(); return null; }
  let role = row.role || null; if (role === 'sub_admin' && row.role_exp && row.role_exp < now()) role = null;
  return { id: row.id, username: row.username, role };
}
async function createSession(env, userId){
  const t = randHex(32), th = await sha256(t), n = now();
  await env.DB.prepare('INSERT INTO sessions (token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)').bind(th, userId, n, n + SESSION_TTL).run();
  return t;
}
const isAdmin = u => u && (u.role === 'main_admin' || u.role === 'sub_admin');
const isOwner = u => u && u.role === 'main_admin';
async function audit(env, actorId, action, detail){
  await env.DB.prepare('INSERT INTO audit_log (id,actor_id,action,detail,created_at) VALUES (?,?,?,?,?)').bind(uid(), actorId, action, detail || '', now()).run();
}
async function allow(env, key, limit, windowSec){
  const w = Math.floor(now() / windowSec) * windowSec;
  await env.DB.prepare(`INSERT INTO rate_limits (key,window_start,count) VALUES (?,?,1) ON CONFLICT(key,window_start) DO UPDATE SET count = count + 1`).bind(key, w).run();
  const row = await env.DB.prepare('SELECT count FROM rate_limits WHERE key = ? AND window_start = ?').bind(key, w).first();
  return row.count <= limit;
}
const USERNAME_RE = /^[a-z0-9_]{3,20}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const validTitle = s => typeof s === 'string' && s.trim().length >= 1 && s.length <= 300;
const validBody = s => typeof s === 'string' && s.length <= 40000;
function cycleOf(ts){ const d = new Date(ts * 1000); return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}`; }
async function getCurrentElection(env){ return env.DB.prepare(`SELECT * FROM elections ORDER BY created_at DESC LIMIT 1`).first(); }
async function startElection(env, actorId){
  const existing = await getCurrentElection(env);
  if (existing && existing.phase !== 'closed') throw new Error('An election is already running.');
  const t = now(); const id = uid(), cycle = cycleOf(t);
  await env.DB.prepare(`INSERT INTO elections (id,cycle,phase,nomination_ends,voting_ends,created_at) VALUES (?,?,?,?,?,?)`).bind(id, cycle, 'nomination', t + NOMINATION_DAYS*DAY, t + (NOMINATION_DAYS+VOTING_DAYS)*DAY, t).run();
  await audit(env, actorId, 'election.start', cycle); return id;
}
async function tallyElection(env, electionId){
  const rows = await env.DB.prepare(`SELECT c.id, c.user_id, COUNT(ev.voter_id) AS votes, c.created_at FROM candidates c LEFT JOIN election_votes ev ON ev.candidate_id = c.id WHERE c.election_id = ? AND c.disqualified = 0 GROUP BY c.id ORDER BY votes DESC, c.created_at ASC LIMIT 1`).bind(electionId).first();
  return rows || null;
}
async function advanceElection(env, actorId){
  const e = await getCurrentElection(env); if (!e || e.phase === 'closed') return null; const t = now();
  if (e.phase === 'nomination' && t >= e.nomination_ends){
    await env.DB.prepare(`UPDATE elections SET phase='voting' WHERE id=?`).bind(e.id).run();
    await audit(env, actorId, 'election.phase', `${e.cycle} → voting`); return 'voting';
  }
  if (e.phase === 'voting' && t >= e.voting_ends){
    const winner = await tallyElection(env, e.id);
    await env.DB.prepare(`UPDATE elections SET phase='closed', winner_id=? WHERE id=?`).bind(winner ? winner.user_id : null, e.id).run();
    if (winner){
      const termEnd = t + 30*DAY;
      await env.DB.prepare(`INSERT INTO roles (user_id,role,granted_at,expires_at) VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET role='sub_admin', granted_at=excluded.granted_at, expires_at=excluded.expires_at`).bind(winner.user_id, 'sub_admin', t, termEnd).run();
      await audit(env, actorId, 'election.winner', `${e.cycle}: ${winner.user_id} (${winner.votes} votes)`);
    } else { await audit(env, actorId, 'election.winner', `${e.cycle}: no candidates`); }
    return 'closed';
  }
  return null;
}
export default {
  async fetch(req, env){
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    if (req.method !== 'GET' && req.method !== 'HEAD'){
      const origin = req.headers.get('Origin'); if (origin && origin !== url.origin) return fail('Cross-origin request blocked', 403);
    }
    try { return await route(req, env, url); } catch (e){ console.error(e); return fail('Server error', 500); }
  },
  async scheduled(_, env, ctx){ ctx.waitUntil(advanceElection(env, 'cron')); }
};
async function route(req, env, url){
  const path = url.pathname, method = req.method;
  const me = await currentUser(req, env);
  if (path === '/api/me' && method === 'GET'){
    return json({ user: me ? { id: me.id, username: me.username, role: me.role } : null });
  }
  if (path === '/api/register' && method === 'POST'){
    if (!(await allow(env, 'reg:'+clientIp(req), 5, 3600))) return fail('Too many signups. Try later.', 429);
    const { username, email, password } = await req.json().catch(()=>({}));
    const u = String(username||'').trim().toLowerCase(); const e = String(email||'').trim().toLowerCase();
    if (!USERNAME_RE.test(u)) return fail('Username: 3–20 chars, letters/numbers/underscore.');
    if (!EMAIL_RE.test(e)) return fail('Enter a valid email.');
    if (typeof password !== 'string' || password.length < 8) return fail('Password must be 8+ characters.');
    const dup = await env.DB.prepare('SELECT id FROM users WHERE username=? OR email=?').bind(u,e).first();
    if (dup) return fail('Username or email already taken.', 409);
    const salt = randHex(16), hash = await hashPassword(password, salt), id = uid();
    await env.DB.prepare('INSERT INTO users (id,username,email,pass_hash,salt,created_at) VALUES (?,?,?,?,?,?)').bind(id, u, e, hash, salt, now()).run();
    if (env.OWNER_EMAIL && e === env.OWNER_EMAIL.trim().toLowerCase()){
      await env.DB.prepare('INSERT OR REPLACE INTO roles (user_id,role,granted_at,expires_at) VALUES (?,?,?,NULL)').bind(id, 'main_admin', now()).run();
    }
    const token = await createSession(env, id);
    return json({ user:{ id, username:u, role: env.OWNER_EMAIL && e === env.OWNER_EMAIL.trim().toLowerCase() ? 'main_admin' : null } }, 201, { 'Set-Cookie': sessionCookie(token, SESSION_TTL) });
  }
  if (path === '/api/login' && method === 'POST'){
    if (!(await allow(env, 'login:'+clientIp(req), 10, 900))) return fail('Too many attempts.', 429);
    const { email, password } = await req.json().catch(()=>({}));
    const e = String(email||'').trim().toLowerCase();
    const row = await env.DB.prepare('SELECT id,username,pass_hash,salt FROM users WHERE email=?').bind(e).first();
    const computed = await hashPassword(String(password||''), row ? row.salt : '00'.repeat(16));
    if (!row || !ctEqual(computed, row.pass_hash)) return fail('Invalid email or password.', 401);
    await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now()).run();
    const token = await createSession(env, row.id);
    const full = await currentUser(new Request(req.url, { headers: { Cookie: `sid=${token}` } }), env);
    return json({ user:{ id: row.id, username: row.username, role: full ? full.role : null } }, 200, { 'Set-Cookie': sessionCookie(token, SESSION_TTL) });
  }
  if (path === '/api/logout' && method === 'POST'){
    const t = getCookie(req,'sid'); if (t) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(t)).run();
    return json({ ok:true }, 200, { 'Set-Cookie': sessionCookie('', 0) });
  }
  if (path === '/api/communities' && method === 'GET'){
    const { results } = await env.DB.prepare(`SELECT c.name,c.title,c.description, (SELECT COUNT(*) FROM posts p WHERE p.community=c.name AND p.hidden=0) AS post_count FROM communities c ORDER BY c.name`).all();
    return json({ communities: results });
  }
  if (path === '/api/posts' && method === 'GET'){
    const community = url.searchParams.get('community') || ''; const q = (url.searchParams.get('q') || '').trim();
    const sort = url.searchParams.get('sort') || 'hot'; const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get('limit')||'25',10)));
    const offset = Math.max(0, parseInt(url.searchParams.get('offset')||'0',10)); const userId = me ? me.id : '';
    const where = ['p.hidden = 0'], args = [];
    if (community){ where.push('p.community = ?'); args.push(community); }
    if (q){ where.push('(p.title LIKE ? OR p.body LIKE ?)'); args.push(`%${q}%`, `%${q}%`); }
    let order; if (sort === 'new') order = 'p.created_at DESC'; else if (sort === 'top') order = 'score DESC';
    else order = `CAST(score AS REAL)/((MAX(1,CAST(strftime('%s','now') AS INTEGER)-p.created_at)/3600.0)+2) DESC`;
    const sql = `SELECT p.id,p.community,p.title,p.body,p.created_at,u.username AS author, COALESCE(vs.total,0) AS score, COALESCE(cs.total,0) AS comment_count, COALESCE(mv.value,0)  AS my_vote, CASE WHEN sv.post_id IS NULL THEN 0 ELSE 1 END AS saved FROM posts p JOIN users u ON u.id = p.author_id LEFT JOIN (SELECT target_id,SUM(value) total FROM votes WHERE target_type='post' GROUP BY target_id) vs ON vs.target_id=p.id LEFT JOIN (SELECT post_id,COUNT(*) total FROM comments WHERE hidden=0 GROUP BY post_id) cs ON cs.post_id=p.id LEFT JOIN votes mv ON mv.target_id=p.id AND mv.target_type='post' AND mv.user_id=? LEFT JOIN saved sv ON sv.post_id=p.id AND sv.user_id=? WHERE ${where.join(' AND ')} ORDER BY ${order} LIMIT ? OFFSET ?`;
    const { results } = await env.DB.prepare(sql).bind(userId,userId,...args,limit,offset).all();
    return json({ posts: results });
  }
  if (path === '/api/posts' && method === 'POST'){
    if (!me) return fail('Sign in to post.', 401); if (!(await allow(env,'post:'+me.id,10,3600))) return fail('10 posts per hour max.', 429);
    const { community, title, body } = await req.json().catch(()=>({}));
    if (!validTitle(title)) return fail('Title required (max 300).'); if (!validBody(body||'')) return fail('Body too long.');
    const sub = await env.DB.prepare('SELECT name FROM communities WHERE name=?').bind(community).first(); if (!sub) return fail('Unknown community.', 404);
    const id = uid();
    await env.DB.prepare('INSERT INTO posts (id,community,author_id,title,body,created_at) VALUES (?,?,?,?,?,?)').bind(id, community, me.id, title.trim(), (body||'').trim(), now()).run();
    return json({ id }, 201);
  }
  const pm = path.match(/^\/api\/posts\/([\w-]+)$/);
  if (pm && method === 'GET'){
    const userId = me ? me.id : '';
    const row = await env.DB.prepare(`SELECT p.id,p.community,p.title,p.body,p.created_at,p.hidden,u.username AS author, COALESCE(vs.total,0) AS score, COALESCE(cs.total,0) AS comment_count, COALESCE(mv.value,0)  AS my_vote, CASE WHEN sv.post_id IS NULL THEN 0 ELSE 1 END AS saved FROM posts p JOIN users u ON u.id=p.author_id LEFT JOIN (SELECT target_id,SUM(value) total FROM votes WHERE target_type='post' GROUP BY target_id) vs ON vs.target_id=p.id LEFT JOIN (SELECT post_id,COUNT(*) total FROM comments WHERE hidden=0 GROUP BY post_id) cs ON cs.post_id=p.id LEFT JOIN votes mv ON mv.target_id=p.id AND mv.target_type='post' AND mv.user_id=? LEFT JOIN saved sv ON sv.post_id=p.id AND sv.user_id=? WHERE p.id=?`).bind(userId,userId,pm[1]).first();
    if (!row) return fail('Post not found.', 404); if (row.hidden && !isAdmin(me)) return fail('Post not found.', 404);
    return json({ post: row });
  }
    if (path === '/api/comments' && method === 'GET'){
    const postId = url.searchParams.get('postId'); if (!postId) return fail('postId required.'); const userId = me ? me.id : '';
    const { results } = await env.DB.prepare(`SELECT c.id,c.post_id,c.parent_id,c.body,c.created_at,u.username AS author, COALESCE(vs.total,0) AS score, COALESCE(mv.value,0) AS my_vote FROM comments c JOIN users u ON u.id=c.author_id LEFT JOIN (SELECT target_id,SUM(value) total FROM votes WHERE target_type='comment' GROUP BY target_id) vs ON vs.target_id=c.id LEFT JOIN votes mv ON mv.target_id=c.id AND mv.target_type='comment' AND mv.user_id=? WHERE c.post_id=? AND c.hidden=0 ORDER BY c.created_at ASC`).bind(userId, postId).all();
    return json({ comments: results });
  }
  if (path === '/api/comments' && method === 'POST'){
    if (!me) return fail('Sign in to comment.', 401); if (!(await allow(env,'comment:'+me.id,40,3600))) return fail('40 comments per hour max.', 429);
    const { postId, parentId, body } = await req.json().catch(()=>({})); if (!postId) return fail('postId required.'); if (!validBody(body) || !String(body).trim()) return fail('Comment cannot be empty.');
    const post = await env.DB.prepare('SELECT id FROM posts WHERE id=? AND hidden=0').bind(postId).first(); if (!post) return fail('Post not found.', 404);
    if (parentId){ const p = await env.DB.prepare('SELECT id,post_id FROM comments WHERE id=?').bind(parentId).first(); if (!p || p.post_id !== postId) return fail('Invalid parent.', 400); }
    const id = uid(); await env.DB.prepare('INSERT INTO comments (id,post_id,parent_id,author_id,body,created_at) VALUES (?,?,?,?,?,?)').bind(id, postId, parentId||null, me.id, String(body).trim(), now()).run();
    return json({ id }, 201);
  }
  if (path === '/api/vote' && method === 'POST'){
    if (!me) return fail('Sign in to vote.', 401); if (!(await allow(env,'vote:'+me.id,600,3600))) return fail('Too many votes.', 429);
    const { targetType, targetId, value } = await req.json().catch(()=>({})); if (!['post','comment'].includes(targetType)) return fail('Invalid target type.');
    const v = Number(value); if (![-1,0,1].includes(v)) return fail('Invalid vote value.');
    const table = targetType === 'post' ? 'posts' : 'comments'; const exists = await env.DB.prepare(`SELECT id FROM ${table} WHERE id=?`).bind(targetId).first(); if (!exists) return fail('Target not found.', 404);
    if (v === 0){ await env.DB.prepare('DELETE FROM votes WHERE user_id=? AND target_type=? AND target_id=?').bind(me.id, targetType, targetId).run(); }
    else { await env.DB.prepare(`INSERT INTO votes (user_id,target_type,target_id,value,created_at) VALUES (?,?,?,?,?) ON CONFLICT(user_id,target_type,target_id) DO UPDATE SET value=excluded.value, created_at=excluded.created_at`).bind(me.id, targetType, targetId, v, now()).run(); }
    const row = await env.DB.prepare('SELECT COALESCE(SUM(value),0) AS score FROM votes WHERE target_type=? AND target_id=?').bind(targetType, targetId).first();
    return json({ score: row.score, myVote: v });
  }
  if (path === '/api/save' && method === 'POST'){
    if (!me) return fail('Sign in to save.', 401); const { postId } = await req.json().catch(()=>({})); if (!postId) return fail('postId required.');
    const existing = await env.DB.prepare('SELECT 1 x FROM saved WHERE user_id=? AND post_id=?').bind(me.id,postId).first();
    if (existing){ await env.DB.prepare('DELETE FROM saved WHERE user_id=? AND post_id=?').bind(me.id,postId).run(); return json({ saved:false }); }
    await env.DB.prepare('INSERT INTO saved (user_id,post_id,created_at) VALUES (?,?,?)').bind(me.id,postId,now()).run(); return json({ saved:true });
  }
  if (path === '/api/report' && method === 'POST'){
    if (!(await allow(env,'report:'+clientIp(req),20,3600))) return fail('Too many reports.', 429);
    const { targetType, targetId, reason } = await req.json().catch(()=>({})); if (!targetType || !targetId) return fail('Invalid target.'); if (!reason || String(reason).length > 500) return fail('Short reason required.');
    await env.DB.prepare('INSERT INTO reports (id,target_type,target_id,reporter_id,reason,created_at) VALUES (?,?,?,?,?,?)').bind(uid(), String(targetType), String(targetId), me?me.id:null, String(reason), now()).run(); return json({ ok:true });
  }
  if (path === '/api/election' && method === 'GET'){
    await advanceElection(env, 'lazy'); const e = await getCurrentElection(env); if (!e) return json({ election:null });
    const { results: cands } = await env.DB.prepare(`SELECT c.id,c.user_id,c.statement,c.disqualified,u.username, (SELECT COUNT(*) FROM election_votes ev WHERE ev.candidate_id=c.id) AS votes FROM candidates c JOIN users u ON u.id=c.user_id WHERE c.election_id=? ORDER BY votes DESC, c.created_at ASC`).bind(e.id).all();
    let myVote = null, iAmCandidate = false;
    if (me){ const mv = await env.DB.prepare('SELECT candidate_id FROM election_votes WHERE election_id=? AND voter_id=?').bind(e.id, me.id).first(); myVote = mv ? mv.candidate_id : null; iAmCandidate = cands.some(c => c.user_id === me.id); }
    const winner = e.winner_id ? await env.DB.prepare('SELECT username FROM users WHERE id=?').bind(e.winner_id).first() : null;
    return json({ election: { id:e.id, cycle:e.cycle, phase:e.phase, nominationEnds:e.nomination_ends, votingEnds:e.voting_ends, winner: winner ? winner.username : null, candidates: cands, myVote, iAmCandidate } });
  }
  if (path === '/api/election/nominate' && method === 'POST'){
    if (!me) return fail('Sign in to run.', 401); if (!(await allow(env,'nominate:'+me.id,3,86400))) return fail('One nomination per day.', 429); await advanceElection(env,'lazy');
    const e = await getCurrentElection(env); if (!e || e.phase !== 'nomination') return fail('Nominations are not open.', 400); if (now() >= e.nomination_ends) return fail('Nominations closed.', 400);
    const { statement } = await req.json().catch(()=>({})); if (statement && String(statement).length > 500) return fail('Statement too long (max 500).');
    await env.DB.prepare(`INSERT INTO candidates (id,election_id,user_id,statement,created_at) VALUES (?,?,?,?,?) ON CONFLICT(election_id,user_id) DO UPDATE SET statement=excluded.statement`).bind(uid(), e.id, me.id, String(statement||'').trim(), now()).run(); return json({ ok:true });
  }
  if (path === '/api/election/vote' && method === 'POST'){
    if (!me) return fail('Sign in to vote.', 401); if (!(await allow(env,'evote:'+me.id,30,86400))) return fail('Too many attempts.', 429); await advanceElection(env,'lazy');
    const e = await getCurrentElection(env); if (!e || e.phase !== 'voting') return fail('Voting is not open.', 400); if (now() >= e.voting_ends) return fail('Voting closed.', 400);
    const { candidateId } = await req.json().catch(()=>({})); const c = await env.DB.prepare('SELECT id FROM candidates WHERE id=? AND election_id=? AND disqualified=0').bind(candidateId, e.id).first(); if (!c) return fail('Invalid candidate.', 400);
    await env.DB.prepare(`INSERT INTO election_votes (election_id,voter_id,candidate_id,created_at) VALUES (?,?,?,?) ON CONFLICT(election_id,voter_id) DO UPDATE SET candidate_id=excluded.candidate_id`).bind(e.id, me.id, candidateId, now()).run(); return json({ ok:true });
  }
  if (path === '/api/admin/overview' && method === 'GET'){
    if (!isAdmin(me)) return fail('Admin only.', 403); await advanceElection(env, 'lazy'); const e = await getCurrentElection(env);
    const open = await env.DB.prepare('SELECT COUNT(*) n FROM reports WHERE resolved=0').first(); const hiddenPosts = await env.DB.prepare('SELECT COUNT(*) n FROM posts WHERE hidden=1').first(); const hiddenComments = await env.DB.prepare('SELECT COUNT(*) n FROM comments WHERE hidden=1').first();
    return json({ role: me.role, election: e || null, openReports: open.n, hiddenPosts: hiddenPosts.n, hiddenComments: hiddenComments.n });
  }
  if (path === '/api/admin/election/start' && method === 'POST'){
    if (!isOwner(me)) return fail('Main admin only.', 403); try { const id = await startElection(env, me.id); return json({ id }); } catch (e){ return fail(e.message, 409); }
  }
  if (path === '/api/admin/election/advance' && method === 'POST'){
    if (!isOwner(me)) return fail('Main admin only.', 403); const phase = await advanceElection(env, me.id); return json({ phase: phase || 'unchanged' });
  }
  if (path === '/api/admin/candidate/disqualify' && method === 'POST'){
    if (!isOwner(me)) return fail('Main admin only.', 403); const { candidateId, reason } = await req.json().catch(()=>({})); if (!candidateId || !reason) return fail('candidateId and reason required.');
    await env.DB.prepare('UPDATE candidates SET disqualified=1, dq_reason=? WHERE id=?').bind(String(reason), candidateId).run(); await audit(env, me.id, 'candidate.dq', `${candidateId}: ${reason}`); return json({ ok:true });
  }
  if (path === '/api/admin/reports' && method === 'GET'){
    if (!isAdmin(me)) return fail('Admin only.', 403);
    const { results } = await env.DB.prepare(`SELECT r.id,r.target_type,r.target_id,r.reason,r.created_at,u.username AS reporter FROM reports r LEFT JOIN users u ON u.id=r.reporter_id WHERE r.resolved=0 ORDER BY r.created_at DESC LIMIT 100`).all(); return json({ reports: results });
  }
  if (path === '/api/admin/moderate' && method === 'POST'){
    if (!isAdmin(me)) return fail('Admin only.', 403); if (!(await allow(env,'mod:'+me.id,120,3600))) return fail('Moderation rate limit.', 429);
    const { targetType, targetId, action, reason } = await req.json().catch(()=>({})); if (!['post','comment'].includes(targetType)) return fail('Invalid target type.'); if (!['hide','unhide','resolve'].includes(action)) return fail('Invalid action.');
    if (action === 'resolve'){ await env.DB.prepare('UPDATE reports SET resolved=1 WHERE id=?').bind(targetId).run(); return json({ ok:true }); }
    const table = targetType === 'post' ? 'posts' : 'comments'; const hidden = action === 'hide' ? 1 : 0;
    await env.DB.prepare(`UPDATE ${table} SET hidden=?, hidden_by=?, hidden_reason=? WHERE id=?`).bind(hidden, me.id, hidden ? String(reason||'') : null, targetId).run(); await audit(env, me.id, `mod.${action}`, `${targetType}:${targetId}`); return json({ ok:true });
  }
  if (path === '/api/admin/audit' && method === 'GET'){
    if (!isAdmin(me)) return fail('Admin only.', 403);
    const { results } = await env.DB.prepare(`SELECT a.id,a.action,a.detail,a.created_at,u.username AS actor FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 100`).all(); return json({ audit: results });
  }
  return fail('Not found', 404);
      }
