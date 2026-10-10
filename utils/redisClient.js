const redis = require('redis');

const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
let client;
let isConnected = false;

async function init() {
  if (client && isConnected) return client;
  if (isConnected === false && client) return null; // already tried and failed, don't retry
  
  try {
    client = redis.createClient({ url: REDIS_URL });
    // Suppress error logging for reconnects
    client.on('error', () => {}); // silent fail
    await client.connect();
    isConnected = true;
    console.log('[REDIS] Connected');
    return client;
  } catch (e) {
    isConnected = false; // mark as attempted but failed
    // silent fail — app continues without Redis
    return null;
  }
}

async function setRefreshJti(userId, jti, ttlSeconds) {
  try {
    const c = await init();
    if (!c) return false;
    const key = `refresh_jti:${userId}:${jti}`;
    await c.set(key, '1', { EX: ttlSeconds });
    return true;
  } catch (e) {
    return false;
  }
}

async function checkRefreshJti(userId, jti) {
  try {
    const c = await init();
    if (!c) return false;
    const key = `refresh_jti:${userId}:${jti}`;
    const v = await c.get(key);
    return !!v;
  } catch (e) {
    return false;
  }
}

async function deleteRefreshJti(userId, jti) {
  try {
    const c = await init();
    if (!c) return false;
    const key = `refresh_jti:${userId}:${jti}`;
    await c.del(key);
    return true;
  } catch (e) {
    return false;
  }
}

async function lpushQueue(queue, value) {
  try {
    const c = await init();
    if (!c) return false;
    await c.lPush(queue, value);
    return true;
  } catch (e) {
    return false;
  }
}

async function rpopQueue(queue) {
  try {
    const c = await init();
    if (!c) return null;
    const v = await c.rPop(queue);
    return v;
  } catch (e) {
    return null;
  }
}

module.exports = { init, setRefreshJti, checkRefreshJti, deleteRefreshJti, lpushQueue, rpopQueue };
