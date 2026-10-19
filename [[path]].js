// API da Trilha de Vídeos para Cloudflare Pages Functions: login, sessão assinada, acessos e dados (D1).
const COLLECTIONS = new Set(['trilha', 'progresso', 'notas']);
const ID_RE = /^[A-Za-z0-9_-]{1,100}$/;
const COOKIE = 'tv_session';
const SESSION_SECONDS = 12 * 60 * 60;
const MAX_FAILS = 5;
const LOCK_SECONDS = 15 * 60;
const MAX_BODY = 250 * 1024;
const PBKDF2_ITER = 100000; // limite do Web Crypto da Cloudflare

let ENV = {};
const enc = new TextEncoder();
const dec = new TextDecoder();
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });
const b64u = (input) => {
  const bytes = typeof input === 'string' ? enc.encode(input) : new Uint8Array(input);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const unb64u = (str) => {
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const timingEq = (a, b) => {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
};
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
const hex = (bytes) => [...new Uint8Array(bytes)].map((x) => x.toString(16).padStart(2, '0')).join('');

function secret() {
  const s = ENV.SESSION_SECRET;
  if (!s || s.length < 32) throw new Error('SESSION_SECRET ausente ou curta (mínimo 32 caracteres).');
  return s;
}
function envUsers() {
  try {
    const u = JSON.parse(ENV.AUTH_USERS || '{}');
    return u && typeof u === 'object' ? u : {};
  } catch {
    return {};
  }
}

// ---------- senha (PBKDF2-SHA256 via Web Crypto) ----------
async function pbkdf2(password, salt, iter, len) {
  const key = await crypto.subtle.importKey('raw', enc.encode(String(password)), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, key, len * 8));
}
async function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iter = parseInt(parts[1], 10);
  const salt = unb64u(parts[2]);
  const expected = unb64u(parts[3]);
  if (!iter || iter > PBKDF2_ITER || !salt.length || !expected.length) return false;
  const got = await pbkdf2(password, salt, iter, expected.length);
  return timingEq(got, expected);
}
async function hashPassword(password) {
  const salt = rand(16);
  const h = await pbkdf2(password, salt, PBKDF2_ITER, 32);
  return `pbkdf2$${PBKDF2_ITER}$` + b64u(salt) + '$' + b64u(h);
}
const DUMMY = `pbkdf2$${PBKDF2_ITER}$` + b64u(new Uint8Array(16)) + '$' + b64u(new Uint8Array(32));

// ---------- armazenamento (D1: tabela kv) ----------
function mkStore(ns) {
  const db = () => ENV.DB;
  return {
    async get(key) {
      const r = await db().prepare('SELECT v FROM kv WHERE ns = ?1 AND k = ?2').bind(ns, key).first();
      return r ? JSON.parse(r.v) : null;
    },
    async setJSON(key, value) {
      await db().prepare('INSERT INTO kv (ns, k, v) VALUES (?1, ?2, ?3) ON CONFLICT(ns, k) DO UPDATE SET v = excluded.v').bind(ns, key, JSON.stringify(value)).run();
    },
    async delete(key) {
      await db().prepare('DELETE FROM kv WHERE ns = ?1 AND k = ?2').bind(ns, key).run();
    },
    async list({ prefix }) {
      const { results } = await db().prepare('SELECT k FROM kv WHERE ns = ?1 AND substr(k, 1, ?2) = ?3').bind(ns, prefix.length, prefix).all();
      return { blobs: results.map((r) => ({ key: r.k })) };
    },
  };
}
const store = () => mkStore('data');
const authStore = () => mkStore('auth');

// ---------- usuários e sessão ----------
const userKey = (name) => 'user/' + b64u(name);
async function findUser(name) {
  const env = envUsers();
  if (Object.prototype.hasOwnProperty.call(env, name))
    return { usuario: name, hash: env[name], papel: 'admin', fixo: true, nome: name, chave: b64u(name) };
  const rec = await authStore().get(userKey(name));
  return rec
    ? { usuario: name, hash: rec.hash, papel: rec.papel === 'admin' ? 'admin' : 'func', fixo: false, nome: rec.nome || name, chave: b64u(name) }
    : null;
}
async function hmac(data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret()), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}
async function signSession(user) {
  const payload = b64u(JSON.stringify({ u: user, exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS }));
  return payload + '.' + b64u(await hmac(payload));
}
async function readSession(req) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + COOKIE + '=([^;]+)'));
  if (!m) return null;
  const [payload, sig] = m[1].split('.');
  if (!payload || !sig) return null;
  const good = await hmac(payload);
  let given;
  try { given = unb64u(sig); } catch { return null; }
  if (!timingEq(good, given)) return null;
  try {
    const p = JSON.parse(dec.decode(unb64u(payload)));
    if (!p.exp || p.exp < Date.now() / 1000) return null;
    return await findUser(String(p.u));
  } catch {
    return null;
  }
}
const cookieHeader = (value, maxAge) => `${COOKIE}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
const meJson = (u) => ({ usuario: u.usuario, papel: u.papel, nome: u.nome, chave: u.chave, trocaSenha: !u.fixo });

// ---------- bloqueio por tentativas ----------
async function ipKey(ip) {
  return hex(await crypto.subtle.digest('SHA-256', enc.encode(String(ip || 'desconhecido')))).slice(0, 32);
}
async function checkLock(key) {
  const rec = await authStore().get(key);
  return rec && rec.until && rec.until > Date.now() ? Math.ceil((rec.until - Date.now()) / 1000) : 0;
}
async function registerFail(key) {
  const st = authStore();
  const rec = (await st.get(key)) || { count: 0 };
  const count = (rec.until && rec.until <= Date.now() ? 0 : rec.count) + 1;
  await st.setJSON(key, count >= MAX_FAILS ? { count: 0, until: Date.now() + LOCK_SECONDS * 1000 } : { count });
}

async function readJson(req) {
  const text = await req.text();
  if (text.length > MAX_BODY) throw Object.assign(new Error('Corpo grande demais'), { status: 413 });
  try {
    return JSON.parse(text || '{}');
  } catch {
    throw Object.assign(new Error('JSON inválido'), { status: 400 });
  }
}

// ---------- permissões ----------
function podeLer(u, col, id) {
  if (col === 'trilha') return true;
  if (col === 'progresso') return u.papel === 'admin' || id === u.chave;
  return id === u.chave;
}
function podeEscrever(u, col, id) {
  if (col === 'trilha') return u.papel === 'admin';
  return id === u.chave;
}
// Módulos marcados como "Em breve": a equipe recebe só nome/descrição, sem as aulas (nem os links dos vídeos).
function filtraTrilha(d, u) {
  if (!d || u.papel === 'admin' || !Array.isArray(d.modulos)) return d;
  return { ...d, modulos: d.modulos.map((m) => (m && m.soon ? { id: m.id, t: m.t, d: m.d, c: m.c, soon: true, vids: [] } : m)) };
}
const cut = (s, n) => String(s || '').slice(0, n);
const rid = () => hex(rand(6));

export async function onRequest(context) {
  ENV = context.env || {};
  return handler(context.request, context);
}

async function handler(req, context) {
  try {
    const url = new URL(req.url);
    const seg = url.pathname.replace(/^\/api\/?/, '').replace(/\/+$/, '').split('/').filter(Boolean).map(decodeURIComponent);
    const method = req.method.toUpperCase();

    if (method !== 'GET' && method !== 'HEAD') {
      const origin = req.headers.get('origin');
      if (origin && origin !== url.origin) return json({ erro: 'Origem não permitida.' }, 403);
      if (req.headers.get('x-requested-with') !== 'trilha-videos') return json({ erro: 'Requisição inválida.' }, 400);
    }

    if (seg[0] === 'login' && method === 'POST') {
      const ip = req.headers.get('cf-connecting-ip') || '';
      const key = await ipKey(ip);
      const wait = await checkLock(key);
      if (wait) return json({ erro: `Muitas tentativas. Tente de novo em ${Math.ceil(wait / 60)} minuto(s).` }, 429);
      const body = await readJson(req);
      const name = String(body.usuario || '').trim().toLowerCase().slice(0, 60);
      const found = await findUser(name);
      const ok = (await verifyPassword(String(body.senha || '').slice(0, 200), found ? found.hash : DUMMY)) && !!found;
      if (!ok) {
        await registerFail(key);
        return json({ erro: 'Usuário ou senha incorretos.' }, 401);
      }
      await authStore().delete(key);
      return json({ ok: true, ...meJson(found) }, 200, { 'set-cookie': cookieHeader(await signSession(name), SESSION_SECONDS) });
    }
    if (seg[0] === 'logout' && method === 'POST') return json({ ok: true }, 200, { 'set-cookie': cookieHeader('', 0) });

    const user = await readSession(req);
    if (!user) return json({ erro: 'Não autenticado.' }, 401);
    const admin = user.papel === 'admin';

    if (seg[0] === 'me' && method === 'GET') return json(meJson(user));

    if (seg[0] === 'senha' && method === 'POST') {
      if (user.fixo) return json({ erro: 'A senha deste usuário é definida no Netlify.' }, 400);
      const b = await readJson(req);
      if (!(await verifyPassword(String(b.atual || '').slice(0, 200), user.hash))) return json({ erro: 'Senha atual incorreta.' }, 400);
      const nova = String(b.nova || '');
      if (nova.length < 6 || nova.length > 100) return json({ erro: 'A nova senha precisa ter de 6 a 100 caracteres.' }, 400);
      const st = authStore();
      const rec = await st.get(userKey(user.usuario));
      await st.setJSON(userKey(user.usuario), { ...rec, hash: await hashPassword(nova) });
      return json({ ok: true });
    }

    // ---- acessos (só administrador) ----
    if (seg[0] === 'usuarios') {
      if (!admin) return json({ erro: 'Apenas administradores.' }, 403);
      const st = authStore();
      if (seg.length === 1 && method === 'GET') {
        const { blobs } = await st.list({ prefix: 'user/' });
        const lista = (await Promise.all(blobs.map(async (x) => {
          const r = await st.get(x.key);
          return r ? { usuario: r.usuario, papel: r.papel === 'admin' ? 'admin' : 'func', nome: r.nome || r.usuario, chave: b64u(r.usuario), fixo: false } : null;
        }))).filter(Boolean);
        Object.keys(envUsers()).forEach((u) => lista.push({ usuario: u, papel: 'admin', nome: u, chave: b64u(u), fixo: true }));
        lista.sort((a, b) => a.usuario.localeCompare(b.usuario));
        return json({ usuarios: lista });
      }
      if (seg.length === 1 && method === 'POST') {
        const b = await readJson(req);
        const nome = String(b.usuario || '').trim().toLowerCase();
        if (!/^[a-z0-9._ -]{3,40}$/.test(nome)) return json({ erro: 'Usuário: 3 a 40 caracteres (letras sem acento, números, ponto, hífen).' }, 400);
        const senha = String(b.senha || '');
        if (senha.length < 6 || senha.length > 100) return json({ erro: 'A senha precisa ter de 6 a 100 caracteres.' }, 400);
        if (await findUser(nome)) return json({ erro: 'Já existe um usuário com esse nome.' }, 409);
        await st.setJSON(userKey(nome), { usuario: nome, hash: await hashPassword(senha), papel: b.papel === 'admin' ? 'admin' : 'func', nome: cut(b.nome, 60) || nome, criado: new Date().toISOString() });
        return json({ ok: true });
      }
      if (seg.length === 2) {
        const nome = String(seg[1]).trim().toLowerCase();
        const u = await findUser(nome);
        if (!u) return json({ erro: 'Usuário não encontrado.' }, 404);
        if (u.fixo) return json({ erro: 'Este administrador é fixo (definido no Netlify).' }, 400);
        if (method === 'PUT') {
          const b = await readJson(req);
          const senha = String(b.senha || '');
          if (senha.length < 6 || senha.length > 100) return json({ erro: 'A senha precisa ter de 6 a 100 caracteres.' }, 400);
          const rec = await st.get(userKey(nome));
          await st.setJSON(userKey(nome), { ...rec, hash: await hashPassword(senha) });
          return json({ ok: true });
        }
        if (method === 'DELETE') {
          await st.delete(userKey(nome));
          return json({ ok: true });
        }
      }
      return json({ erro: 'Não encontrado.' }, 404);
    }

    // ---- comentários por aula ----
    if (seg[0] === 'coment' && ID_RE.test(seg[1] || '')) {
      const st = store();
      const key = 'comentarios/' + seg[1];
      const doc = (await st.get(key)) || { itens: [] };
      if (seg.length === 2 && method === 'GET') return json({ itens: doc.itens });
      const autor = { u: user.usuario, who: user.nome };
      if (seg.length === 2 && method === 'POST') {
        const b = await readJson(req);
        const x = cut(b.x, 1000).trim();
        if (!x) return json({ erro: 'Escreva o comentário.' }, 400);
        const novo = { id: rid(), ...autor, x, em: new Date().toISOString() };
        if (b.parent) {
          const pai = doc.itens.find((c) => c.id === b.parent);
          if (!pai) return json({ erro: 'Comentário não encontrado.' }, 404);
          (pai.re = pai.re || []).push(novo);
        } else doc.itens.unshift({ ...novo, likes: [], re: [] });
        if (doc.itens.length > 500) doc.itens.length = 500;
        await st.setJSON(key, doc);
        return json({ itens: doc.itens });
      }
      if (seg.length === 3 && seg[2] === 'like' && method === 'POST') {
        const b = await readJson(req);
        const c = doc.itens.find((i) => i.id === b.id);
        if (!c) return json({ erro: 'Comentário não encontrado.' }, 404);
        c.likes = c.likes || [];
        const i = c.likes.indexOf(user.usuario);
        if (i >= 0) c.likes.splice(i, 1);
        else c.likes.push(user.usuario);
        await st.setJSON(key, doc);
        return json({ itens: doc.itens });
      }
      if (seg.length === 3 && method === 'DELETE') {
        const id = seg[2];
        const topo = doc.itens.find((c) => c.id === id);
        if (topo) {
          if (topo.u !== user.usuario && !admin) return json({ erro: 'Sem permissão.' }, 403);
          doc.itens = doc.itens.filter((c) => c.id !== id);
        } else {
          for (const c of doc.itens) {
            const r = (c.re || []).find((x) => x.id === id);
            if (r) {
              if (r.u !== user.usuario && !admin) return json({ erro: 'Sem permissão.' }, 403);
              c.re = c.re.filter((x) => x.id !== id);
            }
          }
        }
        await st.setJSON(key, doc);
        return json({ itens: doc.itens });
      }
      return json({ erro: 'Não encontrado.' }, 404);
    }

    // ---- dados genéricos ----
    if (seg[0] === 'col' && seg.length === 2 && method === 'GET') {
      const col = seg[1];
      if (!COLLECTIONS.has(col)) return json({ erro: 'Coleção inválida.' }, 404);
      const st = store();
      const { blobs } = await st.list({ prefix: col + '/' });
      const docs = (await Promise.all(blobs.map(async (b) => {
        const id = b.key.slice(col.length + 1);
        if (!podeLer(user, col, id)) return null;
        const data = await st.get(b.key);
        return data == null ? null : { id, data: col === 'trilha' ? filtraTrilha(data, user) : data };
      }))).filter(Boolean);
      return json({ docs });
    }
    if (seg[0] === 'doc' && seg.length === 3) {
      const [, col, id] = seg;
      if (!COLLECTIONS.has(col) || !ID_RE.test(id)) return json({ erro: 'Caminho inválido.' }, 400);
      const st = store();
      const key = col + '/' + id;
      if (method === 'GET') {
        if (!podeLer(user, col, id)) return json({ erro: 'Sem permissão.' }, 403);
        const data = await st.get(key);
        return data == null ? json({ exists: false }) : json({ exists: true, data: col === 'trilha' ? filtraTrilha(data, user) : data });
      }
      if (!podeEscrever(user, col, id)) return json({ erro: 'Sem permissão para alterar.' }, 403);
      if (method === 'PUT') {
        const body = await readJson(req);
        if (!body || typeof body !== 'object' || Array.isArray(body)) return json({ erro: 'Documento inválido.' }, 400);
        if (col === 'progresso') {
          body.nome = user.nome;
          body.usuario = user.usuario;
        }
        await st.setJSON(key, body);
        return json({ ok: true });
      }
      if (method === 'DELETE') {
        await st.delete(key);
        return json({ ok: true });
      }
    }
    return json({ erro: 'Não encontrado.' }, 404);
  } catch (e) {
    const status = e && e.status ? e.status : 500;
    if (status === 500) console.error('Erro na API:', e && e.message);
    return json({ erro: status === 500 ? 'Erro interno do servidor.' : e.message }, status);
  }
}
