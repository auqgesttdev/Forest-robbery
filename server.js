'use strict';

const http = require('http');
const crypto = require('crypto');
const { promisify } = require('util');
const { Server } = require('socket.io');
const { Pool } = require('pg');

const scrypt = promisify(crypto.scrypt);
const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const TOKEN_SECRET = process.env.TOKEN_SECRET;
const ADMIN_NICK = String(process.env.ADMIN_NICK || 'auqgestt').trim().toLowerCase();
const ADMIN_SETUP_KEY = process.env.ADMIN_SETUP_KEY || '';
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30;

if (!DATABASE_URL) throw new Error('DATABASE_URL is missing. Add your Neon connection string in Render Environment.');
if (!TOKEN_SECRET || TOKEN_SECRET.length < 32) {
  throw new Error('TOKEN_SECRET is missing or too short. Add a random secret of at least 32 characters in Render Environment.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  // Verify the database server certificate instead of accepting any certificate.
  ssl: { rejectUnauthorized: true },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      nickname TEXT NOT NULL,
      nickname_key TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      is_banned INTEGER NOT NULL DEFAULT 0,
      coins BIGINT NOT NULL DEFAULT 0,
      unlocked_skins TEXT NOT NULL DEFAULT '["default"]',
      current_skin TEXT NOT NULL DEFAULT 'default',
      unlocked_auras TEXT NOT NULL DEFAULT '["none"]',
      current_aura TEXT NOT NULL DEFAULT 'none',
      total_kills BIGINT NOT NULL DEFAULT 0,
      coin_sync_window BIGINT NOT NULL DEFAULT 0,
      coin_sync_amount BIGINT NOT NULL DEFAULT 0,
      settings TEXT NOT NULL DEFAULT '{"sound":true,"music":false,"showCoords":false}',
      created_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS bans (
      user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      reason TEXT NOT NULL DEFAULT 'Вы забанены владельцем',
      created_at BIGINT NOT NULL
    );
  `);
  console.log('Neon PostgreSQL database is ready');
}

const skinPrices = { default: 0, knight: 50, ranger: 100, mage: 150, noble: 300, ghost: 500 };
const auraPrices = { none: 0, fire: 150, ice: 200, nature: 250, magic: 400, golden: 600 };
const validSettings = new Set(['sound', 'music', 'showCoords']);
const rooms = new Map();
const userSockets = new Map();
const loginAttempts = new Map();

async function findUserById(id) {
  const r = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return r.rows[0] || null;
}
async function findUserByNick(key) {
  const r = await pool.query('SELECT * FROM users WHERE nickname_key = $1', [key]);
  return r.rows[0] || null;
}
function normalizeNick(value) {
  return String(value || '').normalize('NFKC').trim();
}
function nicknameKey(value) { return normalizeNick(value).toLocaleLowerCase('en-US'); }
function safeJson(value, fallback) {
  try { return JSON.parse(value); } catch (_) { return fallback; }
}
function publicProfile(row) {
  return {
    id: Number(row.id),
    nickname: row.nickname,
    isAdmin: !!row.is_admin,
    coins: Number(row.coins),
    unlockedSkins: safeJson(row.unlocked_skins, ['default']),
    currentSkin: row.current_skin,
    unlockedAuras: safeJson(row.unlocked_auras, ['none']),
    currentAura: row.current_aura,
    totalKills: Number(row.total_kills),
    settings: safeJson(row.settings, { sound: true, music: false, showCoords: false })
  };
}
function signToken(userId) {
  const payload = Buffer.from(JSON.stringify({ uid: Number(userId), exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS })).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
async function verifyToken(token) {
  if (typeof token !== 'string' || token.length > 2048) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(parts[0]).digest();
  let actual;
  try { actual = Buffer.from(parts[1], 'base64url'); } catch (_) { return null; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    if (!payload.uid || payload.exp < Math.floor(Date.now() / 1000)) return null;
    const user = await findUserById(payload.uid);
    if (!user || user.is_banned) return null;
    return user;
  } catch (_) { return null; }
}
async function hashPassword(password, salt) {
  const derived = await scrypt(password, salt, 64);
  return derived.toString('hex');
}
function passwordMatches(a, b) {
  const aa = Buffer.from(a, 'hex'), bb = Buffer.from(b, 'hex');
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function bearer(req) {
  const value = req.headers.authorization || '';
  return value.startsWith('Bearer ') ? value.slice(7) : '';
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 32 * 1024) { reject(new Error('Слишком большой запрос')); req.destroy(); }
    });
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch (_) { reject(new Error('Некорректный JSON')); }
    });
    req.on('error', reject);
  });
}
function corsOrigin(req) {
  const configured = process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map(x => x.trim()).filter(Boolean) : null;
  const origin = req && req.headers && req.headers.origin;
  if (!configured || !configured.length) return '*';
  return origin && configured.includes(origin) ? origin : configured[0];
}
function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Vary': 'Origin', 'Access-Control-Allow-Origin': corsOrigin(res.req), 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS' });
  res.end(JSON.stringify(data));
}
async function authUser(req) { return verifyToken(bearer(req)); }
function boundedInt(value, min, max, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.max(min, Math.min(max, Math.floor(n))) : fallback;
}
function sanitizeProfileInput(body, old) {
  const coins = boundedInt(body.coins, 0, 100000000, Number(old.coins));
  const totalKills = boundedInt(body.totalKills, 0, 100000000, Number(old.total_kills));
  const skins = Array.isArray(body.unlockedSkins) ? [...new Set(body.unlockedSkins.filter(x => Object.prototype.hasOwnProperty.call(skinPrices, x)))].slice(0, 20) : safeJson(old.unlocked_skins, ['default']);
  const auras = Array.isArray(body.unlockedAuras) ? [...new Set(body.unlockedAuras.filter(x => Object.prototype.hasOwnProperty.call(auraPrices, x)))].slice(0, 20) : safeJson(old.unlocked_auras, ['none']);
  if (!skins.includes('default')) skins.unshift('default');
  if (!auras.includes('none')) auras.unshift('none');
  const currentSkin = skins.includes(body.currentSkin) ? body.currentSkin : (skins.includes(old.current_skin) ? old.current_skin : 'default');
  const currentAura = auras.includes(body.currentAura) ? body.currentAura : (auras.includes(old.current_aura) ? old.current_aura : 'none');
  const oldSettings = safeJson(old.settings, { sound: true, music: false, showCoords: false });
  const settings = { ...oldSettings };
  if (body.settings && typeof body.settings === 'object') {
    for (const key of validSettings) if (typeof body.settings[key] === 'boolean') settings[key] = body.settings[key];
  }
  return { coins, totalKills, skins, auras, currentSkin, currentAura, settings };
}
async function saveProfileFromClient(userId, body) {
  const old = await findUserById(userId);
  if (!old) return null;
  const p = sanitizeProfileInput(body, old);
  await pool.query(
    'UPDATE users SET coins=$1, unlocked_skins=$2, current_skin=$3, unlocked_auras=$4, current_aura=$5, total_kills=$6, settings=$7 WHERE id=$8',
    [p.coins, JSON.stringify(p.skins), p.currentSkin, JSON.stringify(p.auras), p.currentAura, p.totalKills, JSON.stringify(p.settings), userId]
  );
  return publicProfile(await findUserById(userId));
}
function detachFromRoom(socket) {
  if (!socket.roomId) return;
  const room = rooms.get(socket.roomId);
  if (room) {
    delete room.players[socket.id];
    socket.to(socket.roomId).emit('playerLeft', socket.id);
    if (Object.keys(room.players).length === 0) rooms.delete(socket.roomId);
  }
  socket.leave(socket.roomId);
  socket.roomId = null;
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Vary': 'Origin', 'Access-Control-Allow-Origin': corsOrigin(req), 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS' });
    return res.end();
  }
  const url = new URL(req.url, 'http://localhost');
  try {
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Forest Robber server OK');
    }
    if (req.method === 'GET' && url.pathname === '/health') return sendJson(res, 200, { ok: true });

    if (req.method === 'POST' && url.pathname === '/api/register') {
      const body = await readBody(req);
      const nickname = normalizeNick(body.nickname);
      const key = nicknameKey(nickname);
      const password = String(body.password || '');
      if (!/^[\p{L}\p{N}_-]{3,16}$/u.test(nickname)) return sendJson(res, 400, { error: 'Ник: 3–16 символов, буквы, цифры, _ или -' });
      if (password.length < 8 || password.length > 128) return sendJson(res, 400, { error: 'Пароль должен содержать от 8 до 128 символов' });
      if (await findUserByNick(key)) return sendJson(res, 409, { error: 'Этот никнейм уже занят' });
      const salt = crypto.randomBytes(16).toString('hex');
      const passwordHash = await hashPassword(password, salt);
      const wantsAdmin = key === ADMIN_NICK && ADMIN_SETUP_KEY && String(body.adminSetupKey || '') === ADMIN_SETUP_KEY;
      if (key === ADMIN_NICK && ADMIN_SETUP_KEY && !wantsAdmin) return sendJson(res, 403, { error: 'Для регистрации этого ника требуется ключ владельца' });
      try {
        const result = await pool.query(
          'INSERT INTO users (nickname,nickname_key,password_hash,password_salt,is_admin,created_at) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
          [nickname, key, passwordHash, salt, wantsAdmin ? 1 : 0, Date.now()]
        );
        const row = await findUserById(result.rows[0].id);
        return sendJson(res, 201, { token: signToken(row.id), profile: publicProfile(row) });
      } catch (e) {
        if (e.code === '23505') return sendJson(res, 409, { error: 'Этот никнейм уже занят' });
        throw e;
      }
    }

    if (req.method === 'POST' && url.pathname === '/api/login') {
      const body = await readBody(req);
      const key = nicknameKey(body.nickname);
      const ip = req.socket.remoteAddress || 'unknown';
      const attempt = loginAttempts.get(ip) || { count: 0, until: 0 };
      if (attempt.until > Date.now() && attempt.count >= 12) return sendJson(res, 429, { error: 'Слишком много попыток. Попробуйте позже.' });
      const row = await findUserByNick(key);
      const password = String(body.password || '');
      let ok = false;
      if (row && password.length <= 128) {
        const candidate = await hashPassword(password, row.password_salt);
        ok = passwordMatches(candidate, row.password_hash);
      }
      if (!ok || (row && row.is_banned)) {
        attempt.count += 1; attempt.until = Date.now() + 10 * 60 * 1000; loginAttempts.set(ip, attempt);
        return sendJson(res, 401, { error: 'Неверный никнейм или пароль' });
      }
      loginAttempts.delete(ip);
      return sendJson(res, 200, { token: signToken(row.id), profile: publicProfile(row) });
    }

    if (req.method === 'GET' && url.pathname === '/api/profile') {
      const user = await authUser(req);
      if (!user) return sendJson(res, 401, { error: 'Сессия истекла. Войдите снова.' });
      return sendJson(res, 200, { profile: publicProfile(user) });
    }

    if (req.method === 'POST' && url.pathname === '/api/profile/sync') {
      const user = await authUser(req);
      if (!user) return sendJson(res, 401, { error: 'Требуется вход' });
      const body = await readBody(req);
      const row = await findUserById(user.id);
      const now = Date.now();
      let windowStart = Number(row.coin_sync_window) || 0;
      let windowAmount = Number(row.coin_sync_amount) || 0;
      if (now - windowStart >= 60000) { windowStart = now; windowAmount = 0; }
      const requested = boundedInt(body.earnedCoins, 0, 100000, 0);
      const accepted = Math.min(requested, Math.max(0, 40 - windowAmount));
      const totalKills = boundedInt(body.totalKills, 0, 100000000, Number(row.total_kills));
      const oldSettings = safeJson(row.settings, { sound:true, music:false, showCoords:false });
      const settings = { ...oldSettings };
      if (body.settings && typeof body.settings === 'object') for (const key of validSettings) if (typeof body.settings[key] === 'boolean') settings[key] = body.settings[key];
      await pool.query(
        'UPDATE users SET coins=LEAST(coins + $1, 100000000), total_kills=$2, settings=$3, coin_sync_window=$4, coin_sync_amount=$5 WHERE id=$6',
        [accepted, totalKills, JSON.stringify(settings), windowStart, windowAmount + accepted, user.id]
      );
      const profile = publicProfile(await findUserById(user.id));
      return sendJson(res, 200, { profile, acceptedCoins: accepted, cappedCoins: requested - accepted });
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/grant-self') {
      const user = await authUser(req);
      if (!user || !user.is_admin) return sendJson(res, 403, { error: 'Недостаточно прав' });
      const body = await readBody(req);
      const amount = boundedInt(body.amount, 1, 10000, 1000);
      await pool.query('UPDATE users SET coins=LEAST(coins + $1, 100000000) WHERE id=$2', [amount, user.id]);
      return sendJson(res, 200, { profile: publicProfile(await findUserById(user.id)) });
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/unlock-auras') {
      const user = await authUser(req);
      if (!user || !user.is_admin) return sendJson(res, 403, { error: 'Недостаточно прав' });
      await pool.query(`UPDATE users SET unlocked_auras='["none","fire","ice","nature","magic","golden"]' WHERE id=$1`, [user.id]);
      return sendJson(res, 200, { profile: publicProfile(await findUserById(user.id)) });
    }

    if (req.method === 'POST' && url.pathname === '/api/shop/purchase') {
      const user = await authUser(req);
      if (!user) return sendJson(res, 401, { error: 'Требуется вход' });
      const body = await readBody(req);
      const type = body.type === 'aura' ? 'aura' : body.type === 'skin' ? 'skin' : '';
      const id = String(body.id || '');
      const price = type === 'skin' ? skinPrices[id] : type === 'aura' ? auraPrices[id] : undefined;
      if (price === undefined || price <= 0) return sendJson(res, 400, { error: 'Неизвестный предмет' });
      const table = type === 'skin' ? 'unlocked_skins' : 'unlocked_auras';
      const current = await findUserById(user.id);
      const owned = safeJson(current[table], []);
      if (owned.includes(id)) return sendJson(res, 409, { error: 'Предмет уже куплен' });
      if (Number(current.coins) < price) return sendJson(res, 400, { error: 'Недостаточно монет' });
      const next = [...owned, id];
      const nextCoins = Number(current.coins) - price;
      if (type === 'skin') await pool.query('UPDATE users SET coins=$1, unlocked_skins=$2, current_skin=$3 WHERE id=$4', [nextCoins, JSON.stringify(next), id, user.id]);
      else await pool.query('UPDATE users SET coins=$1, unlocked_auras=$2, current_aura=$3 WHERE id=$4', [nextCoins, JSON.stringify(next), id, user.id]);
      return sendJson(res, 200, { profile: publicProfile(await findUserById(user.id)) });
    }

    if (req.method === 'POST' && url.pathname === '/api/shop/select') {
      const user = await authUser(req);
      if (!user) return sendJson(res, 401, { error: 'Требуется вход' });
      const body = await readBody(req);
      const id = String(body.id || '');
      if (body.type === 'skin') {
        const row = await findUserById(user.id); const owned = safeJson(row.unlocked_skins, ['default']);
        if (!owned.includes(id)) return sendJson(res, 403, { error: 'Этот скин не куплен' });
        await pool.query('UPDATE users SET current_skin=$1 WHERE id=$2', [id, user.id]);
      } else if (body.type === 'aura') {
        const row = await findUserById(user.id); const owned = safeJson(row.unlocked_auras, ['none']);
        if (!owned.includes(id)) return sendJson(res, 403, { error: 'Эта аура не куплена' });
        await pool.query('UPDATE users SET current_aura=$1 WHERE id=$2', [id, user.id]);
      } else return sendJson(res, 400, { error: 'Неизвестный тип предмета' });
      return sendJson(res, 200, { profile: publicProfile(await findUserById(user.id)) });
    }

    return sendJson(res, 404, { error: 'Не найдено' });
  } catch (error) {
    console.error('HTTP error:', error);
    if (!res.headersSent) sendJson(res, 500, { error: 'Внутренняя ошибка сервера' });
  }
});

const io = new Server(server, {
  cors: { origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map(x => x.trim()) : '*', methods: ['GET', 'POST'] },
  maxHttpBufferSize: 1e5
});
io.use(async (socket, next) => {
  try {
    const user = await verifyToken(socket.handshake.auth && socket.handshake.auth.token);
    if (!user) return next(new Error('AUTH_REQUIRED'));
    socket.user = user;
    next();
  } catch (error) {
    console.error('Socket authentication error:', error);
    next(new Error('AUTH_REQUIRED'));
  }
});

io.on('connection', socket => {
  const uid = socket.user.id;
  if (!userSockets.has(uid)) userSockets.set(uid, new Set());
  userSockets.get(uid).add(socket.id);

  socket.on('joinRoom', async (data = {}) => {
    try {
      const roomId = String(data.roomId || '').trim().toUpperCase().slice(0, 12);
      if (!/^[A-Z0-9_-]{3,12}$/.test(roomId)) return socket.emit('roomError', { message: 'Некорректный код комнаты' });
      detachFromRoom(socket);
      let room = rooms.get(roomId);
      if (!room) { room = { players: Object.create(null) }; rooms.set(roomId, room); }
      const existing = Object.values(room.players).find(p => p.userId === uid);
      if (existing) return socket.emit('roomError', { message: 'Этот аккаунт уже находится в комнате' });
      if (Object.keys(room.players).length >= 4) return socket.emit('roomError', { message: 'Комната заполнена (максимум 4 игрока)' });
      const profileRow = await findUserById(uid);
      if (!profileRow) return socket.emit('roomError', { message: 'Аккаунт не найден' });
      const profile = publicProfile(profileRow);
      socket.join(roomId); socket.roomId = roomId;
      room.players[socket.id] = { id: socket.id, userId: uid, nickname: profile.nickname, skin: profile.currentSkin, x: 2500, y: 2500, dir: 0, hp: 100, moving: false, deathAnnounced: false, deathCause: '', damageLockUntil: 0, pvpCooldownAt: 0 };
      socket.emit('roomState', { players: room.players });
      socket.to(roomId).emit('playerJoined', room.players[socket.id]);
    } catch (error) {
      console.error('joinRoom error:', error);
      socket.emit('roomError', { message: 'Не удалось войти в комнату' });
    }
  });

  socket.on('playerUpdate', async (data = {}) => {
    try {
      if (!socket.roomId) return;
      const room = rooms.get(socket.roomId); const p = room && room.players[socket.id];
      if (!p) return;
      const num = (v, min, max, fallback) => Number.isFinite(Number(v)) ? Math.max(min, Math.min(max, Number(v))) : fallback;
      p.x = num(data.x, 0, 5000, p.x); p.y = num(data.y, 0, 5000, p.y);
      p.dir = num(data.dir, -Math.PI * 2, Math.PI * 2, p.dir);
      if (Date.now() >= (p.damageLockUntil || 0)) p.hp = num(data.hp, 0, 100, p.hp);
      if (p.hp > 0) { p.deathAnnounced = false; p.deathCause = ''; }
      p.moving = data.moving === true;
      const profile = await findUserById(uid);
      if (profile) { p.nickname = profile.nickname; p.skin = profile.current_skin; }
      socket.to(socket.roomId).volatile.emit('playerMoved', { ...p });
    } catch (error) { console.error('playerUpdate error:', error); }
  });

  socket.on('playerDamage', (data = {}) => {
    try {
      if (!socket.roomId) return;
      const room = rooms.get(socket.roomId);
      const attacker = room && room.players[socket.id];
      const target = room && room.players[String(data.targetId || '')];
      if (!attacker || !target || target.id === attacker.id || target.hp <= 0) return;
      const SAFE_X = 2500, SAFE_Y = 2500, SAFE_R = 230;
      const inSafe = p => Math.hypot(p.x - SAFE_X, p.y - SAFE_Y) <= SAFE_R;
      if (inSafe(attacker) || inSafe(target)) return;
      const kind = data.kind === 'bullet' ? 'bullet' : 'melee';
      const now = Date.now();
      const cooldown = kind === 'bullet' ? 180 : 350;
      if (now - (attacker.pvpCooldownAt || 0) < cooldown) return;
      const distance = Math.hypot(target.x - attacker.x, target.y - attacker.y);
      if (kind === 'melee') {
        if (distance > 100) return;
        let angle = Math.atan2(target.y - attacker.y, target.x - attacker.x);
        let diff = Math.abs(angle - attacker.dir);
        while (diff > Math.PI) diff = Math.abs(diff - Math.PI * 2);
        if (diff > 0.9) return;
      } else {
        if (distance > 850) return;
        const ix = Number(data.impactX), iy = Number(data.impactY);
        if (!Number.isFinite(ix) || !Number.isFinite(iy) || Math.hypot(ix-target.x, iy-target.y) > 48) return;
        const angle = Math.atan2(target.y - attacker.y, target.x - attacker.x);
        let diff = Math.abs(angle - attacker.dir);
        while (diff > Math.PI) diff = Math.abs(diff - Math.PI * 2);
        if (diff > 0.45) return;
      }
      attacker.pvpCooldownAt = now;
      target.damageLockUntil = now + 250;
      const damage = kind === 'bullet' ? 28 : 20;
      target.hp = Math.max(0, Math.min(100, Number(target.hp) - damage));
      target.deathCause = attacker.nickname;
      const targetSocket = io.sockets.sockets.get(target.id);
      if (targetSocket) targetSocket.emit('playerDamaged', {
        targetId: target.id, hp: target.hp, killerNickname: attacker.nickname
      });
      if (target.hp <= 0 && !target.deathAnnounced) {
        target.deathAnnounced = true;
        io.to(socket.roomId).emit('killFeed', { message: `☠️ ${target.nickname} убит игроком ${attacker.nickname}` });
      }
    } catch (error) { console.error('playerDamage error:', error); }
  });

  socket.on('playerDeath', (data = {}) => {
    if (!socket.roomId) return;
    const room = rooms.get(socket.roomId);
    const p = room && room.players[socket.id];
    if (!p || p.hp > 0 || p.deathAnnounced) return;
    p.deathAnnounced = true;
    const cause = p.deathCause || String(data.cause || 'бот').replace(/[<>]/g, '').slice(0, 40);
    io.to(socket.roomId).emit('killFeed', { message: `☠️ ${p.nickname} погиб от: ${cause}` });
  });

  socket.on('playerKill', (data = {}) => {
    if (!socket.roomId) return;
    const room = rooms.get(socket.roomId);
    if (!room || !room.players[socket.id]) return;
    const target = String(data.target || 'бот').replace(/[<>]/g, '').slice(0, 50);
    io.to(socket.roomId).emit('killFeed', { message: `⚔️ ${socket.user.nickname} убил: ${target}` });
  });

  socket.on('chatMessage', (data = {}) => {
    if (!socket.roomId) return;
    const room = rooms.get(socket.roomId); if (!room || !room.players[socket.id]) return;
    const text = String(data.text || '').trim().slice(0, 120);
    if (!text) return;
    io.to(socket.roomId).emit('chatMessage', { id: socket.id, nickname: socket.user.nickname, text, time: Date.now() });
  });

  socket.on('adminAction', async (data = {}) => {
    try {
      const admin = await findUserById(uid);
      if (!admin || !admin.is_admin) return socket.emit('adminError', { message: 'Недостаточно прав' });
      if (data.action === 'weather') {
        const allowed = new Set(['clear', 'rain', 'storm', 'fog']);
        if (allowed.has(data.weather) && socket.roomId) io.to(socket.roomId).emit('adminWeather', { weather: data.weather });
        return;
      }
      const room = socket.roomId && rooms.get(socket.roomId);
      const self = room && room.players[socket.id];
      if (data.action === 'spawnBoss') {
        if (!room || !self) return socket.emit('adminError', { message: 'Сначала войдите в кооперативную комнату' });
        const bx = Math.max(100, Math.min(4900, self.x + Math.cos(self.dir || 0) * 360));
        const by = Math.max(100, Math.min(4900, self.y + Math.sin(self.dir || 0) * 360));
        io.to(socket.roomId).emit('bossSpawn', { x: bx, y: by, byAdmin: true });
        return;
      }
      const target = room && room.players[String(data.targetId || '')];
      if (!target) return;
      const targetSocket = io.sockets.sockets.get(target.id);
      if (data.action === 'teleportToAdmin') {
        if (!self || !targetSocket) return;
        target.x = Math.max(30, Math.min(4970, self.x + 45));
        target.y = Math.max(30, Math.min(4970, self.y + 45));
        targetSocket.emit('adminTeleport', { x: target.x, y: target.y });
        io.to(socket.roomId).emit('playerMoved', { id: target.id, ...target });
        return;
      } else if (data.action === 'giveItem') {
        const allowedItems = new Set(['givePistol','giveVehicles','giveWood']);
        if (allowedItems.has(data.item) && targetSocket) targetSocket.emit('adminGift', { item: data.item });
        return;
      } else if (data.action === 'giveCoins') {
        const amount = boundedInt(data.amount, 1, 10000, 100);
        await pool.query('UPDATE users SET coins=LEAST(coins + $1, 100000000) WHERE id=$2', [amount, target.userId]);
        const updated = publicProfile(await findUserById(target.userId));
        if (targetSocket) targetSocket.emit('profileUpdated', { profile: updated, message: `Владелец выдал вам ${amount} монет` });
      } else if (data.action === 'kick') {
        if (targetSocket) { targetSocket.emit('adminKicked', { reason: 'Вас выгнал владелец' }); setTimeout(() => targetSocket.disconnect(true), 100); }
      } else if (data.action === 'ban') {
        await pool.query('UPDATE users SET is_banned=1 WHERE id=$1', [target.userId]);
        await pool.query(
          `INSERT INTO bans(user_id,reason,created_at) VALUES($1,$2,$3)
           ON CONFLICT(user_id) DO UPDATE SET reason=EXCLUDED.reason, created_at=EXCLUDED.created_at`,
          [target.userId, 'Вы забанены владельцем', Date.now()]
        );
        const sockets = userSockets.get(target.userId);
        if (sockets) for (const sid of sockets) {
          const s = io.sockets.sockets.get(sid);
          if (s) { s.emit('adminBanned', { reason: 'Вы забанены владельцем' }); setTimeout(() => s.disconnect(true), 100); }
        }
      }
    } catch (error) {
      console.error('adminAction error:', error);
      socket.emit('adminError', { message: 'Ошибка выполнения команды' });
    }
  });

  socket.on('leaveRoom', () => detachFromRoom(socket));
  socket.on('disconnect', () => {
    detachFromRoom(socket);
    const set = userSockets.get(uid);
    if (set) { set.delete(socket.id); if (!set.size) userSockets.delete(uid); }
  });
});

async function start() {
  await initDatabase();
  server.listen(PORT, () => console.log(`Forest Robber server listening on ${PORT}; database: Neon PostgreSQL`));
}
start().catch(error => {
  console.error('Failed to start server:', error);
  process.exit(1);
});

process.on('SIGTERM', async () => {
  try { await pool.end(); } finally { process.exit(0); }
});
