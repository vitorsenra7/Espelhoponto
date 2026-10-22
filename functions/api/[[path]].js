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
  const
