// API do Espelho de Ponto para Cloudflare Pages Functions: login com senha, sessão assinada e armazenamento em D1.
const COLLECTIONS = new Set(['funcionarios', 'ponto', 'periodos', 'config', 'banco']);
const ID_RE = /^[A-Za-z0-9_-]{1,100}$/;
const COOKIE = 'ep_session';
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
// hash falso para gastar o mesmo tempo quando o usuário não existe
const DUMMY = `pbkdf2$${PBKDF2_ITER}$` + b64u(new Uint8Array(16)) + '$' + b64u(new Uint8Array(32));

// ---------- armazenamento (D1: tabela kv) ----------
// Observação: no plano grátis o D1 aceita até 50 consultas por requisição, por isso as listagens
// trazem todos os documentos de uma vez (listDocs) em vez de uma consulta por documento.
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
    async listDocs(prefix) {
      const { results } = await db().prepare('SELECT k, v FROM kv WHERE ns = ?1 AND substr(k, 1, ?2) = ?3').bind(ns, prefix.length, prefix).all();
      return results.map((r) => ({ key: r.k, data: JSON.parse(r.v) }));
    },
  };
}
const store = () => mkStore('data');
const authStore = () => mkStore('auth');

// ---------- usuários e sessão ----------
// usuários criados pelo administrador ficam no banco; os de AUTH_USERS são administradores fixos
const userKey = (name) => 'user/' + b64u(name);
async function findUser(name) {
  const env = envUsers();
  if (Object.prototype.hasOwnProperty.call(env, name)) return { usuario: name, hash: env[name], papel: 'admin', fixo: true };
  const rec = await authStore().get(userKey(name));
  return rec ? { usuario: name, hash: rec.hash, papel: rec.papel === 'admin' ? 'admin' : 'func', n: rec.n, nome: rec.nome || '', fixo: false } : null;
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
  try {
    given = unb64u(sig);
  } catch {
    return null;
  }
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

// funcionário só enxerga os próprios dados; jornada e períodos são comuns
function podeLer(user, col, id) {
  if (user.papel === 'admin') return true;
  const n = String(user.n || '');
  if (!n) return false;
  if (col === 'funcionarios' || col === 'banco') return id === n;
  if (col === 'ponto') return id.startsWith(n + '_');
  return col === 'periodos' || col === 'config';
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

// ponto de entrada da Cloudflare Pages Functions
export async function onRequest(context) {
  ENV = context.env || {};
  return handler(context.request, context);
}

async function handler(req, context) {
  try {
    const url = new URL(req.url);
    const seg = url.pathname.replace(/^\/api\/?/, '').replace(/\/+$/, '').split('/').filter(Boolean).map(decodeURIComponent);
    const method = req.method.toUpperCase();

    // proteção contra CSRF: escritas só com cabeçalho próprio e mesma origem
    if (method !== 'GET' && method !== 'HEAD') {
      const origin = req.headers.get('origin');
      if (origin && origin !== url.origin) return json({ erro: 'Origem não permitida.' }, 403);
      if (req.headers.get('x-requested-with') !== 'espelho-ponto') return json({ erro: 'Requisição inválida.' }, 400);
    }

    if (seg[0] === 'login' && method === 'POST') {
      const ip = req.headers.get('cf-connecting-ip') || '';
      const key = await ipKey(ip);
      const wait = await checkLock(key);
      if (wait) return json({ erro: `Muitas tentativas. Tente de novo em ${Math.ceil(wait / 60)} minuto(s).` }, 429);
      const body = await readJson(req);
      const name = String(body.usuario || '').trim().toLowerCase().slice(0, 60);
      const found = await findUser(name);
      const has = !!found;
      const ok = (await verifyPassword(String(body.senha || '').slice(0, 200), has ? found.hash : DUMMY)) && has;
      if (!ok) {
        await registerFail(key);
        return json({ erro: 'Usuário ou senha incorretos.' }, 401);
      }
      await authStore().delete(key);
      return json(
        { ok: true, usuario: name, papel: found.papel, n: found.n || null, nome: found.nome || '', trocaSenha: !found.fixo },
        200,
        { 'set-cookie': cookieHeader(await signSession(name), SESSION_SECONDS) },
      );
    }

    if (seg[0] === 'logout' && method === 'POST') {
      return json({ ok: true }, 200, { 'set-cookie': cookieHeader('', 0) });
    }

    // tudo abaixo exige sessão válida
    const user = await readSession(req);
    if (!user) return json({ erro: 'Não autenticado.' }, 401);
    const admin = user.papel === 'admin';

    if (seg[0] === 'me' && method === 'GET')
      return json({ usuario: user.usuario, papel: user.papel, n: user.n || null, nome: user.nome || '', trocaSenha: !user.fixo });

    // troca da própria senha (só para usuários criados no sistema)
    if (seg[0] === 'senha' && method === 'POST') {
      if (user.fixo) return json({ erro: 'A senha deste usuário é definida no Cloudflare.' }, 400);
      const b = await readJson(req);
      if (!(await verifyPassword(String(b.atual || '').slice(0, 200), user.hash))) return json({ erro: 'Senha atual incorreta.' }, 400);
      const nova = String(b.nova || '');
      if (nova.length < 6 || nova.length > 100) return json({ erro: 'A nova senha precisa ter de 6 a 100 caracteres.' }, 400);
      const st = authStore();
      const rec = await st.get(userKey(user.usuario));
      await st.setJSON(userKey(user.usuario), { ...rec, hash: await hashPassword(nova) });
      return json({ ok: true });
    }

    // gestão de acessos: só administrador
    if (seg[0] === 'usuarios') {
      if (!admin) return json({ erro: 'Apenas administradores.' }, 403);
      const st = authStore();
      if (seg.length === 1 && method === 'GET') {
        const lista = (await st.listDocs('user/'))
          .map((x) => x.data)
          .filter(Boolean)
          .map((r) => ({ usuario: r.usuario, papel: r.papel === 'admin' ? 'admin' : 'func', n: r.n || null, nome: r.nome || '', fixo: false }));
        Object.keys(envUsers()).forEach((u) => lista.push({ usuario: u, papel: 'admin', n: null, nome: '', fixo: true }));
        lista.sort((a, b) => a.usuario.localeCompare(b.usuario));
        return json({ usuarios: lista });
      }
      if (seg.length === 1 && method === 'POST') {
        const b = await readJson(req);
        const nome = String(b.usuario || '').trim().toLowerCase();
        if (!/^[a-z0-9._ -]{3,40}$/.test(nome)) return json({ erro: 'Usuário: 3 a 40 caracteres (letras sem acento, números, ponto, hífen).' }, 400);
        const senha = String(b.senha || '');
        if (senha.length < 6 || senha.length > 100) return json({ erro: 'A senha precisa ter de 6 a 100 caracteres.' }, 400);
        const papel = b.papel === 'admin' ? 'admin' : 'func';
        const n = papel === 'func' ? parseInt(b.n, 10) : null;
        if (papel === 'func' && !(n >= 1)) return json({ erro: 'Escolha o funcionário.' }, 400);
        if (await findUser(nome)) return json({ erro: 'Já existe um usuário com esse nome.' }, 409);
        await st.setJSON(userKey(nome), { usuario: nome, hash: await hashPassword(senha), papel, n, nome: String(b.nome || '').slice(0, 80), criado: new Date().toISOString() });
        return json({ ok: true });
      }
      if (seg.length === 2) {
        const nome = String(seg[1]).trim().toLowerCase();
        const u = await findUser(nome);
        if (!u) return json({ erro: 'Usuário não encontrado.' }, 404);
        if (u.fixo) return json({ erro: 'Este administrador é fixo (definido no Cloudflare).' }, 400);
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

    if (seg[0] === 'col' && seg.length === 2 && method === 'GET') {
      const col = seg[1];
      if (!COLLECTIONS.has(col)) return json({ erro: 'Coleção inválida.' }, 404);
      const prefix = col + '/';
      const docs = (await store().listDocs(prefix))
        .map((d) => ({ id: d.key.slice(prefix.length), data: d.data }))
        .filter((d) => d.data != null && (admin || podeLer(user, col, d.id)));
      return json({ docs });
    }

    if (seg[0] === 'doc' && seg.length === 3) {
      const [, col, id] = seg;
      if (!COLLECTIONS.has(col) || !ID_RE.test(id)) return json({ erro: 'Caminho inválido.' }, 400);
      const st = store();
      const key = col + '/' + id;
      if (method === 'GET' && !podeLer(user, col, id)) return json({ erro: 'Sem permissão.' }, 403);
      if (method !== 'GET' && !admin) return json({ erro: 'Somente administradores podem alterar dados.' }, 403);
      if (method === 'PUT') {
        const body = await readJson(req);
        if (!body || typeof body !== 'object' || Array.isArray(body)) return json({ erro: 'Documento inválido.' }, 400);
        await st.setJSON(key, body);
        return json({ ok: true });
      }
      if (method === 'DELETE') {
        await st.delete(key);
        return json({ ok: true });
      }
      if (method === 'GET') {
        const data = await st.get(key);
        return data == null ? json({ exists: false }) : json({ exists: true, data });
      }
    }

    return json({ erro: 'Não encontrado.' }, 404);
  } catch (e) {
    const status = e && e.status ? e.status : 500;
    if (status === 500) console.error('Erro na API:', e && e.message);
    return json({ erro: status === 500 ? 'Erro interno do servidor.' : e.message }, status);
  }
}
