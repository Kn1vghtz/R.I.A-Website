const express = require('express'),
  crypto = require('crypto'),
  fs = require('fs'),
  path = require('path');
try {
  fs.readFileSync('.env', 'utf8')
    .split(/\r?\n/)
    .forEach((l) => {
      const m = l.match(/^([A-Z_]+)=(.*)$/);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].trim();
    });
} catch {}
const {
  DISCORD_CLIENT_ID: CID,
  DISCORD_CLIENT_SECRET: SEC,
  DISCORD_BOT_TOKEN: BOT,
  BASE_URL: BASE,
  SESSION_SECRET: KEY,
  ADMIN_IDS = '',
  PORT = 3000,
} = process.env;
if (!CID || !SEC || !BASE || !KEY || KEY.length < 16) {
  console.error('Missing env vars: see .env.example');
  process.exit(1);
}
const admins = new Set(
  ADMIN_IDS.split(',')
    .map((s) => s.trim())
    .filter(Boolean),
);
const TYPES = ['Scamming', 'Deceptive Work Claims', 'Payment Fraud', 'Impersonation', 'Other'],
  CATS = ['Server Updates', 'Website Updates', 'Bot Updates', 'Scam Updates'];
const F = path.join(__dirname, 'data.json');
let DB = { logs: {}, updates: {}, notes: {} };
try {
  DB = JSON.parse(fs.readFileSync(F, 'utf8'));
} catch {}
DB.staff = DB.staff || {};
const save = () => fs.writeFileSync(F, JSON.stringify(DB));
const sign = (v) => crypto.createHmac('sha256', KEY).update(v).digest('base64url');
const secure = BASE.startsWith('https') ? '; Secure' : '';
const eq = (a, b) =>
  a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const cookie = (req, n) => {
  const c = (req.headers.cookie || '').split('; ').find((x) => x.startsWith(n + '='));
  return c ? c.slice(n.length + 1) : null;
};
function sess(req) {
  const c = cookie(req, 'sw');
  if (!c) return null;
  const [p, sg] = c.split('.');
  if (!p || !sg || !eq(sg, sign(p))) return null;
  try {
    const s = JSON.parse(Buffer.from(p, 'base64url'));
    return s.exp > Date.now() ? s : null;
  } catch {
    return null;
  }
}
const setC = (res, n, v, age) =>
  res.append('Set-Cookie', `${n}=${v}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${secure}`);
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '50kb' }));
app.use((q, r, n) => {
  r.set('X-Content-Type-Options', 'nosniff');
  r.set('Referrer-Policy', 'same-origin');
  r.set('X-Frame-Options', 'DENY');
  n();
});
app.get('/auth/login', (req, res) => {
  const st = crypto.randomBytes(16).toString('hex');
  setC(res, 'st', st, 600);
  res.redirect(
    'https://discord.com/oauth2/authorize?' +
      new URLSearchParams({
        client_id: CID,
        response_type: 'code',
        scope: 'identify',
        redirect_uri: BASE + '/auth/callback',
        state: st,
        prompt: 'none',
      }),
  );
});
app.get('/auth/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const st = cookie(req, 'st');
    if (!code || !state || !st || !eq(String(state), st))
      return res.status(400).send('Invalid login state');
    const t = await (
      await fetch('https://discord.com/api/oauth2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: CID,
          client_secret: SEC,
          grant_type: 'authorization_code',
          code: String(code),
          redirect_uri: BASE + '/auth/callback',
        }),
      })
    ).json();
    if (!t.access_token) return res.status(400).send('Discord login failed');
    const u = await (
      await fetch('https://discord.com/api/users/@me', {
        headers: { Authorization: 'Bearer ' + t.access_token },
      })
    ).json();
    if (!u.id) return res.status(400).send('Discord login failed');
    const p = Buffer.from(
      JSON.stringify({
        id: u.id,
        name: (u.global_name || u.username || 'user').slice(0, 40),
        exp: Date.now() + 7 * 864e5,
      }),
    ).toString('base64url');
    setC(res, 'sw', p + '.' + sign(p), 7 * 86400);
    setC(res, 'st', '', 0);
    res.redirect('/#/' + (admins.has(u.id) ? 'admin' : ''));
  } catch (e) {
    res.status(500).send('Login error');
  }
});
app.get('/auth/logout', (q, r) => {
  setC(r, 'sw', '', 0);
  r.redirect('/');
});
const me = (req) => {
  const s = sess(req);
  return s ? { id: s.id, name: s.name, admin: admins.has(s.id) } : {};
};
app.get('/api/me', (q, r) => r.json(me(q)));
const hits = {};
const limited = (ip) => {
  const n = Date.now(),
    a = (hits[ip] = (hits[ip] || []).filter((t) => n - t < 6e4));
  if (a.length >= 30) return true;
  a.push(n);
  return false;
};
const ok = (v, n) => typeof v === 'string' && v.length <= n,
  today = () => new Date().toISOString().slice(0, 10),
  idOk = (i) => /^[A-Za-z0-9_-]{1,40}$/.test(i);
function clean(c, id, b, m) {
  b = b || {};
  if (c === 'logs') {
    const ev = b.evidence || '';
    if (
      !ok(b.username, 60) ||
      !b.username ||
      !ok(b.description, 2000) ||
      !b.description ||
      !ok(ev, 500) ||
      ev
        .split(/\s+/)
        .filter(Boolean)
        .some((u) => !/^https:\/\/[^\s<>"]+$/.test(u)) ||
      (b.discordId && !/^\d{15,21}$/.test(b.discordId)) ||
      !ok(b.investigator || '', 60)
    )
      return null;
    const o = DB.logs[id];
    return {
      id,
      username: b.username,
      discordId: b.discordId || '',
      status: 'verified',
      description: b.description,
      evidence: ev,
      investigator: b.investigator || '',
      created: o?.created || today(),
      updated: today(),
      createdBy: o?.createdBy || m.id,
      modifiedBy: m.id,
    };
  }
  if (c === 'updates') {
    if (!ok(b.title, 120) || !b.title || !CATS.includes(b.category) || !ok(b.body, 4000) || !b.body)
      return null;
    const o = DB.updates[id];
    return {
      id,
      title: b.title,
      category: b.category,
      body: b.body,
      date: o?.date || today(),
      author: o?.author || m.name,
      modifiedBy: m.id,
    };
  }
  if (c === 'staff') {
    if (
      !/^\d{15,21}$/.test(b.discordId || '') ||
      !ok(b.name || '', 40) ||
      !b.role ||
      !ok(b.role, 40)
    )
      return null;
    return {
      id,
      discordId: b.discordId,
      name: b.name || '',
      role: b.role,
      order: Math.min(99, Math.max(0, parseInt(b.order, 10) || 50)),
    };
  }
  if (c === 'notes') return ok(b.text, 2000) ? { id, text: b.text } : null;
  return null;
}
// ---------- Discord profile lookup (avatar + name) ----------
const PROF = new Map();
const pHits = {};
app.get('/api/profile/:id', async (req, res) => {
  const id = req.params.id;
  if (!/^\d{15,21}$/.test(id)) return res.status(400).json({ error: 'bad id' });
  const hit = PROF.get(id);
  if (hit && Date.now() - hit.t < 36e5) return res.json(hit.v);
  const now = Date.now();
  const list = (pHits[req.ip] = (pHits[req.ip] || []).filter((x) => now - x < 60000));
  if (list.length >= 120) return res.status(429).json({ error: 'Too many requests' });
  list.push(now);
  let v = {
    id,
    name: null,
    avatar: `https://cdn.discordapp.com/embed/avatars/${Number((BigInt(id) >> 22n) % 6n)}.png`,
  };
  if (BOT) {
    try {
      const r = await fetch('https://discord.com/api/v10/users/' + id, {
        headers: { Authorization: 'Bot ' + BOT },
      });
      if (r.ok) {
        const u = await r.json();
        v = {
          id,
          name: u.global_name || u.username,
          username: u.username,
          banner: u.banner
            ? `https://cdn.discordapp.com/banners/${id}/${u.banner}.${u.banner.startsWith('a_') ? 'gif' : 'png'}?size=600`
            : null,
          avatar: u.avatar
            ? `https://cdn.discordapp.com/avatars/${id}/${u.avatar}.${u.avatar.startsWith('a_') ? 'gif' : 'png'}?size=128`
            : v.avatar,
        };
      }
    } catch {}
  }
  PROF.set(id, { t: Date.now(), v });
  res.json(v);
});

// ---------- Live staff presence (Discord gateway) ----------
const GUILD = process.env.DISCORD_GUILD_ID;
const PRES = new Map();
let gwWs = null,
  gwSeq = null,
  gwJoined = false;
const staffIds = () => Object.values(DB.staff).map((m) => m.discordId);
function setPres(uid, status, acts) {
  const c = (acts || []).find((a) => a.type === 4);
  PRES.set(uid, {
    status: status || 'offline',
    text: c && c.state ? String(c.state).slice(0, 60) : '',
  });
}
function askStaff() {
  const ids = staffIds();
  if (!gwJoined || !gwWs || gwWs.readyState !== 1 || !ids.length) return;
  gwWs.send(
    JSON.stringify({
      op: 8,
      d: {
        guild_id: GUILD,
        user_ids: ids.slice(0, 100),
        presences: true,
        limit: 0,
        nonce: 'staff',
      },
    }),
  );
}
function startGateway() {
  if (!BOT || !GUILD)
    return console.log('Staff presence off (set DISCORD_BOT_TOKEN and DISCORD_GUILD_ID)');
  if (typeof WebSocket === 'undefined') return console.log('Staff presence needs Node 22 or newer');
  const ws = (gwWs = new WebSocket('wss://gateway.discord.gg/?v=10&encoding=json'));
  let hb;
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.s != null) gwSeq = m.s;
    if (m.op === 10) {
      hb = setInterval(
        () => ws.readyState === 1 && ws.send(JSON.stringify({ op: 1, d: gwSeq })),
        m.d.heartbeat_interval,
      );
      ws.send(
        JSON.stringify({
          op: 2,
          d: {
            token: BOT,
            intents: 1 | 2 | 256,
            properties: { os: 'linux', browser: 'ria', device: 'ria' },
          },
        }),
      );
    } else if (m.op === 7 || m.op === 9) {
      ws.close();
    } else if (m.op === 0) {
      if (m.t === 'GUILD_CREATE' && m.d.id === GUILD) {
        gwJoined = true;
        (m.d.presences || []).forEach((p) => setPres(p.user.id, p.status, p.activities));
        askStaff();
      }
      if (m.t === 'GUILD_MEMBERS_CHUNK' && m.d.guild_id === GUILD) {
        const seen = new Set((m.d.presences || []).map((p) => p.user.id));
        (m.d.presences || []).forEach((p) => setPres(p.user.id, p.status, p.activities));
        (m.d.members || []).forEach((mem) => {
          if (!seen.has(mem.user.id)) setPres(mem.user.id, 'offline', []);
        });
      }
      if (m.t === 'PRESENCE_UPDATE' && m.d.guild_id === GUILD)
        setPres(m.d.user.id, m.d.status, m.d.activities);
    }
  };
  ws.onclose = (e) => {
    clearInterval(hb);
    gwJoined = false;
    if (e.code === 4014 || e.code === 4013)
      return console.log(
        'Presence blocked: turn ON "Presence Intent" and "Server Members Intent" in the Developer Portal (Bot page).',
      );
    if (e.code === 4004) return console.log('Presence: bot token rejected.');
    setTimeout(startGateway, 5000);
  };
  ws.onerror = () => {};
}
// ---------- Discord server info (invite + online count via widget) ----------
const WID = {};
async function widget(id) {
  const h = WID[id];
  if (h && Date.now() - h.t < 3e5) return h.v;
  let v = { invite: null, online: null, name: null };
  try {
    const r = await fetch(`https://discord.com/api/guilds/${id}/widget.json`);
    if (r.ok) {
      const j = await r.json();
      v = {
        invite: j.instant_invite || null,
        online: j.presence_count ?? null,
        name: j.name || null,
      };
    }
  } catch {}
  WID[id] = { t: Date.now(), v };
  return v;
}
app.get('/api/discord', async (req, res) => {
  res.json({
    main: await widget(process.env.MAIN_GUILD_ID || '1270633085855334454'),
    appeal: await widget(process.env.APPEAL_GUILD_ID || '1343622851361505455'),
  });
});

app.get('/api/presence', (req, res) => {
  const map = {};
  if (gwJoined)
    staffIds().forEach((id) => (map[id] = PRES.get(id) || { status: 'offline', text: '' }));
  res.set('Cache-Control', 'no-store');
  res.json({ enabled: gwJoined, map });
});

app.get('/api/:c', (req, res) => {
  const c = req.params.c;
  if (!DB[c]) return res.status(404).json({ error: 'not found' });
  if (c === 'notes' && !me(req).admin) return res.status(403).json({ error: 'forbidden' });
  res.json(Object.values(DB[c]));
});
const w = (req, res, next) => {
  const m = me(req);
  if (!DB[req.params.c] || !idOk(req.params.id))
    return res.status(400).json({ error: 'bad request' });
  if (!m.admin) return res.status(403).json({ error: 'Admins only' });
  if (req.get('X-Requested-With') !== 'sw') return res.status(403).json({ error: 'bad request' });
  if (limited(req.ip)) return res.status(429).json({ error: 'Too many requests' });
  req.m = m;
  next();
};
app.put('/api/:c/:id', w, (req, res) => {
  const r = clean(req.params.c, req.params.id, req.body, req.m);
  if (!r) return res.status(400).json({ error: 'Invalid data' });
  DB[req.params.c][req.params.id] = r;
  save();
  if (req.params.c === 'staff') askStaff();
  res.json({ ok: 1 });
});
app.delete('/api/:c/:id', w, (req, res) => {
  delete DB[req.params.c][req.params.id];
  save();
  res.json({ ok: 1 });
});
app.use(express.static(path.join(__dirname, 'public')));
startGateway();
setInterval(askStaff, 120000);
app.listen(PORT, () => console.log('ScamWatch running on ' + BASE));