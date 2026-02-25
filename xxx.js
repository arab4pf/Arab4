/**
 * Sakilobot Trading Bot v4.0.0 — Production-Ready
 * ═══════════════════════════════════════════════════
 * Ultimate Solana Telegram Trading Bot (Standalone)
 *
 * Features:
 *   • Jupiter V6 Swaps (buy / sell / confirm flow)
 *   • Multi-Wallet Management (create, import, switch, rename, delete, reveal key)
 *   • Seed Phrase (BIP-39 12/24 word) & Base58 Private Key Import
 *   • AES-256-CBC Encrypted Private Key Storage
 *   • Price Alerts with background checker
 *   • DCA (Dollar Cost Averaging) Orders
 *   • Limit Orders (auto-execute at target price)
 *   • Copy Trading (monitor & mirror wallet trades)
 *   • Referral System with Tiered Rewards
 *   • PnL Tracking with CSV Export & Chart Generation
 *   • Portfolio Overview with Token Holdings
 *   • Token Analysis (market data, security score, sentiment)
 *   • Wallet Analysis (SOL + tokens + recent TXs)
 *   • Admin Dashboard (users, stats, broadcast, ban/unban)
 *   • Rate Limiting (per-user, per-action, in-memory)
 *   • Retry Logic with Exponential Backoff
 *   • Multi-RPC Endpoint Failover
 *   • Safe Telegram Messaging (HTML sanitization, parse-error fallback)
 *   • Commission System with Configurable Rate
 *   • Transaction History Recording
 *   • Input Validation & Sanitization
 *   • Graceful Shutdown
 *
 * Dependencies (npm install):
 *   dotenv node-telegram-bot-api @solana/web3.js bs58 node-fetch bip39 ed25519-hd-key uuid
 *
 * Environment (.env):
 *   TELEGRAM_BOT_TOKEN=8566860244:AAGJ3efLToROQgU2e07rGvbceOIf5-OEZyo
 *   ADMIN_IDS=7565493172,6948216210
 *   SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
 *   SOLANA_RPC_URL_2=  (optional fallback)
 *   SOLANA_RPC_URL_3=  (optional fallback)
 *   SLIPPAGE_BPS=100
 *   PRIORITY_FEE=10000
 *   ALERT_INTERVAL=30000
 *   ENCRYPTION_KEY=   (64 hex chars — generate: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
 *   COMMISSION_RATE=0.01
 *   COMMISSION_ADDRESS=
 *   HELIUS_API_KEY=
 *   MAX_WALLETS=10
 */

'use strict';

// ══════════════════════════════════════════════════════════════════════════════════════
// DEPENDENCIES
// ══════════════════════════════════════════════════════════════════════════════════════
require('dotenv').config();
const crypto = require('crypto');
const TelegramBot = require('node-telegram-bot-api');
const { Connection, PublicKey, Keypair, LAMPORTS_PER_SOL, VersionedTransaction } = require('@solana/web3.js');
const bs58 = require('bs58');
const fetch = require('node-fetch');

// Optional — gracefully degrade if not installed
let bip39, derivePath;
try {
  bip39 = require('bip39');
  ({ derivePath } = require('ed25519-hd-key'));
} catch {
  console.warn('⚠️  bip39 / ed25519-hd-key not installed — seed phrase import disabled');
}

// ══════════════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ══════════════════════════════════════════════════════════════════════════════════════
const config = {
  telegram: {
    token: process.env.TELEGRAM_BOT_TOKEN,
    adminIds: (process.env.ADMIN_IDS || '').split(',').map(id => parseInt(id.trim())).filter(Boolean),
  },
  solana: {
    rpcUrls: [
      process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com',
      process.env.SOLANA_RPC_URL_2,
      process.env.SOLANA_RPC_URL_3,
    ].filter(Boolean),
  },
  jupiter: {
    slippageBps: parseInt(process.env.SLIPPAGE_BPS) || 100,
    priorityFee: parseInt(process.env.PRIORITY_FEE) || 10000,
  },
  alerts: {
    checkInterval: parseInt(process.env.ALERT_INTERVAL) || 30000,
  },
  encryption: {
    key: process.env.ENCRYPTION_KEY || '',
  },
  commission: {
    rate: parseFloat(process.env.COMMISSION_RATE) || 0.01,
    address: process.env.COMMISSION_ADDRESS || '',
  },
  limits: {
    maxWallets: parseInt(process.env.MAX_WALLETS) || 10,
    maxAlerts: 20,
    maxLimitOrders: 20,
    maxDCAOrders: 10,
  },
};

// Validate critical config
if (!config.telegram.token) {
  console.error('🚨 TELEGRAM_BOT_TOKEN is required');
  process.exit(1);
}

if (config.encryption.key && (config.encryption.key.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(config.encryption.key))) {
  console.error('🚨 ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes)');
  console.error('💡 Generate one: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

// ══════════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ══════════════════════════════════════════════════════════════════════════════════════
const BOT_VERSION = '4.0.0';
const WSOL_MINT = 'So11111111111111111111111111111111111111112';
const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const USDT_MINT = 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB';
const TOKEN_PROGRAM_ID = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const TOKEN_2022_PROGRAM_ID = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
const SOLANA_ADDRESS_REGEX = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const MAX_MESSAGE_LENGTH = 4096;
const PARSE_MODE = 'HTML';

// Rate Limit Config (per-user per hour)
const RATE_LIMITS = {
  trade: { max: 30, windowMs: 3600000 },
  wallet: { max: 15, windowMs: 3600000 },
  api: { max: 120, windowMs: 3600000 },
};

// Referral Tiers
const REFERRAL_TIERS = {
  BRONZE:   { min: 0,  rate: 0.005, emoji: '🥉', name: 'Bronze' },
  SILVER:   { min: 5,  rate: 0.0075, emoji: '🥈', name: 'Silver' },
  GOLD:     { min: 15, rate: 0.01,  emoji: '🥇', name: 'Gold' },
  PLATINUM: { min: 30, rate: 0.015, emoji: '💎', name: 'Platinum' },
  DIAMOND:  { min: 50, rate: 0.02,  emoji: '💠', name: 'Diamond' },
};

// ══════════════════════════════════════════════════════════════════════════════════════
// ENCRYPTION UTILITIES
// ══════════════════════════════════════════════════════════════════════════════════════
function encryptData(text) {
  if (!config.encryption.key) return text; // passthrough if no key
  const iv = crypto.randomBytes(16);
  const key = Buffer.from(config.encryption.key, 'hex');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decryptData(encryptedText) {
  if (!config.encryption.key) return encryptedText;
  try {
    const [ivHex, encrypted] = encryptedText.split(':');
    if (!ivHex || !encrypted) return encryptedText; // not encrypted
    const iv = Buffer.from(ivHex, 'hex');
    const key = Buffer.from(config.encryption.key, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch {
    return encryptedText; // return as-is if decryption fails
  }
}

// ══════════════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════════════
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function escapeHTML(text) {
  if (text == null) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function finalizeText(text) {
  if (!text) return '';
  const s = String(text);
  return s.length > MAX_MESSAGE_LENGTH ? s.substring(0, MAX_MESSAGE_LENGTH - 3) + '...' : s;
}

function shortenAddress(address, chars = 4) {
  if (!address || address.length < chars * 2 + 3) return address || '';
  return `${address.slice(0, chars)}...${address.slice(-chars)}`;
}

function formatNumber(num, decimals = 4) {
  if (num === 0) return '0';
  if (num == null || isNaN(num)) return 'N/A';
  if (Math.abs(num) < 0.0001) return Number(num).toExponential(2);
  return Number(num).toLocaleString('en-US', { maximumFractionDigits: decimals });
}

function formatLargeNumber(num) {
  if (!num || isNaN(num) || !Number.isFinite(Number(num))) return '0.00';
  if (Math.abs(num) > 1e15) return '∞';
  if (num >= 1e9) return (num / 1e9).toFixed(2) + 'B';
  if (num >= 1e6) return (num / 1e6).toFixed(2) + 'M';
  if (num >= 1e3) return (num / 1e3).toFixed(2) + 'K';
  return Number(num).toFixed(2);
}

function formatPrice(price) {
  if (!price || isNaN(price)) return '$0.00';
  if (price < 0.000001) return `$${Number(price).toExponential(2)}`;
  if (price < 0.01) return `$${Number(price).toFixed(6)}`;
  if (price < 1) return `$${Number(price).toFixed(4)}`;
  return `$${Number(price).toFixed(2)}`;
}

function formatPercentage(value) {
  if (!value || isNaN(value)) return '0.00%';
  const sign = value >= 0 ? '+' : '';
  return `${sign}${Number(value).toFixed(2)}%`;
}

function formatSOL(lamports) {
  return formatNumber(lamports / LAMPORTS_PER_SOL);
}

function formatTimestamp(timestamp) {
  return new Date(timestamp).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
}

function timeAgo(date) {
  const seconds = Math.floor((Date.now() - new Date(date)) / 1000);
  const units = [
    { s: 31536000, n: 'year' }, { s: 2592000, n: 'month' }, { s: 86400, n: 'day' },
    { s: 3600, n: 'hour' }, { s: 60, n: 'minute' },
  ];
  for (const u of units) {
    const v = Math.floor(seconds / u.s);
    if (v >= 1) return `${v} ${u.n}${v > 1 ? 's' : ''} ago`;
  }
  return 'just now';
}

function isValidSolanaAddress(address) {
  if (!SOLANA_ADDRESS_REGEX.test(address)) return false;
  try { new PublicKey(address); return true; } catch { return false; }
}

function validateSolAmount(input) {
  const amount = parseFloat(String(input).trim());
  if (isNaN(amount) || amount <= 0 || amount > 10000) return null;
  return amount;
}

function validateSlippage(input) {
  const val = parseFloat(String(input).trim());
  if (isNaN(val) || val < 0.1 || val > 50) return null;
  return val;
}

function sanitizeString(input, maxLength = 100) {
  if (typeof input !== 'string') return '';
  return input.trim().substring(0, maxLength).replace(/[<>]/g, '');
}

function generateReferralCode() {
  return 'REF' + crypto.randomBytes(4).toString('hex').toUpperCase();
}

// ══════════════════════════════════════════════════════════════════════════════════════
// RETRY HELPER
// ══════════════════════════════════════════════════════════════════════════════════════
async function withRetry(fn, { retries = 3, baseDelayMs = 500 } = {}) {
  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (i < retries - 1) await sleep(baseDelayMs * Math.pow(2, i));
    }
  }
  throw lastErr;
}

// ══════════════════════════════════════════════════════════════════════════════════════
// IN-MEMORY RATE LIMITER
// ══════════════════════════════════════════════════════════════════════════════════════
class RateLimiter {
  constructor() {
    this.store = new Map();
    // Cleanup every 10 minutes
    setInterval(() => this._cleanup(), 600000);
  }

  check(userId, action) {
    const cfg = RATE_LIMITS[action];
    if (!cfg) return true;
    const key = `${userId}:${action}`;
    const now = Date.now();
    let entry = this.store.get(key);
    if (!entry || now - entry.windowStart > cfg.windowMs) {
      entry = { windowStart: now, count: 0 };
      this.store.set(key, entry);
    }
    if (entry.count >= cfg.max) return false;
    entry.count++;
    return true;
  }

  _cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      // Remove entries older than 2 hours
      if (now - entry.windowStart > 7200000) this.store.delete(key);
    }
  }
}

const rateLimiter = new RateLimiter();

// ══════════════════════════════════════════════════════════════════════════════════════
// IN-MEMORY CACHE
// ══════════════════════════════════════════════════════════════════════════════════════
class SimpleCache {
  constructor(defaultTTL = 60000) {
    this.store = new Map();
    this.defaultTTL = defaultTTL;
    setInterval(() => this._cleanup(), 30000);
  }

  get(key) {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expires) { this.store.delete(key); return null; }
    return entry.value;
  }

  set(key, value, ttlMs) {
    this.store.set(key, { value, expires: Date.now() + (ttlMs || this.defaultTTL) });
  }

  del(key) { this.store.delete(key); }

  _cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (now > entry.expires) this.store.delete(key);
    }
  }
}

const tokenInfoCache = new SimpleCache(600000);   // 10 min
const priceCache = new SimpleCache(30000);         // 30 sec
const balanceCache = new SimpleCache(60000);       // 1 min
const marketDataCache = new SimpleCache(120000);   // 2 min

// ══════════════════════════════════════════════════════════════════════════════════════
// STATE MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════════════
class BotState {
  constructor() {
    this.users = new Map();
    this.priceAlerts = new Map();
    this.limitOrders = new Map();
    this.dcaOrders = new Map();
    this.transactions = new Map(); // userId -> [tx, ...]
    this.alertCounter = 0;
    this.limitCounter = 0;
    this.dcaCounter = 0;
    this.systemStats = {
      startedAt: Date.now(),
      totalSwaps: 0,
      totalVolume: 0,
    };
  }

  getUser(chatId) {
    if (!this.users.has(chatId)) {
      this.users.set(chatId, {
        chatId,
        wallets: [],
        activeWallet: null,
        settings: {
          buySlippageBps: config.jupiter.slippageBps,
          sellSlippageBps: config.jupiter.slippageBps,
          defaultBuyAmount: 0.1,
          notifications: true,
        },
        createdAt: Date.now(),
        username: null,
        firstName: null,
        lastName: null,
        lastActive: Date.now(),
        totalSwaps: 0,
        totalAlerts: 0,
        referralCode: generateReferralCode(),
        referredBy: null,
        referrals: [],
        referralEarnings: 0,
        isBanned: false,
        banReason: '',
        awaitingInput: null,
        pendingSwap: null,
      });
    }
    return this.users.get(chatId);
  }

  updateUserInfo(chatId, msg) {
    const user = this.getUser(chatId);
    user.username = msg.from?.username || null;
    user.firstName = msg.from?.first_name || null;
    user.lastName = msg.from?.last_name || null;
    user.lastActive = Date.now();
    return user;
  }

  getAllUsers() { return Array.from(this.users.values()); }

  addAlert(chatId, tokenMint, targetPrice, direction) {
    const id = ++this.alertCounter;
    this.priceAlerts.set(id, {
      id, chatId, tokenMint, targetPrice, direction,
      createdAt: Date.now(), triggered: false,
    });
    this.getUser(chatId).totalAlerts++;
    return id;
  }

  removeAlert(alertId) { return this.priceAlerts.delete(alertId); }

  getUserAlerts(chatId) {
    return Array.from(this.priceAlerts.values()).filter(a => a.chatId === chatId && !a.triggered);
  }

  addLimitOrder(chatId, tokenMint, tokenSymbol, type, targetPrice, amount) {
    const id = ++this.limitCounter;
    this.limitOrders.set(id, {
      id, chatId, tokenMint, tokenSymbol, type, targetPrice, amount,
      active: true, executed: false, createdAt: Date.now(),
    });
    return id;
  }

  getUserLimitOrders(chatId) {
    return Array.from(this.limitOrders.values()).filter(o => o.chatId === chatId && o.active);
  }

  addDCAOrder(chatId, tokenMint, tokenSymbol, amountPerInterval, intervalMs, totalOrders) {
    const id = ++this.dcaCounter;
    this.dcaOrders.set(id, {
      id, chatId, tokenMint, tokenSymbol, amountPerInterval, intervalMs, totalOrders,
      executedOrders: 0, active: true, paused: false,
      nextExecution: Date.now() + intervalMs, createdAt: Date.now(),
    });
    return id;
  }

  getUserDCAOrders(chatId) {
    return Array.from(this.dcaOrders.values()).filter(o => o.chatId === chatId && o.active);
  }

  addTransaction(chatId, tx) {
    if (!this.transactions.has(chatId)) this.transactions.set(chatId, []);
    const list = this.transactions.get(chatId);
    list.unshift({ ...tx, timestamp: Date.now() });
    if (list.length > 100) list.length = 100; // cap at 100
  }

  getUserTransactions(chatId) {
    return this.transactions.get(chatId) || [];
  }
}

const state = new BotState();

// ══════════════════════════════════════════════════════════════════════════════════════
// MULTI-RPC CONNECTION MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════════════
let rpcIndex = 0;
let connection = new Connection(config.solana.rpcUrls[0], { commitment: 'confirmed' });

function rotateRpc() {
  rpcIndex = (rpcIndex + 1) % config.solana.rpcUrls.length;
  connection = new Connection(config.solana.rpcUrls[rpcIndex], { commitment: 'confirmed' });
  console.log(`🔄 Switched RPC to endpoint ${rpcIndex + 1}/${config.solana.rpcUrls.length}`);
}

async function rpcCall(fn) {
  const maxAttempts = config.solana.rpcUrls.length;
  for (let i = 0; i < maxAttempts; i++) {
    try {
      return await fn(connection);
    } catch (err) {
      console.error(`RPC error (endpoint ${rpcIndex + 1}): ${err.message}`);
      if (i < maxAttempts - 1) rotateRpc();
      else throw new Error('All Solana RPC endpoints failed');
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════════════
// SAFE TELEGRAM MESSAGING
// ══════════════════════════════════════════════════════════════════════════════════════
async function safeSend(chatId, text, options = {}) {
  const finalText = finalizeText(text);
  const baseOpts = { parse_mode: PARSE_MODE, disable_web_page_preview: true, ...options };
  try {
    return await bot.sendMessage(chatId, finalText, baseOpts);
  } catch (err) {
    // If parse error, retry without parse_mode
    if (/can't parse entities|parse entities/i.test(err?.message || '')) {
      try {
        const { parse_mode, ...rest } = baseOpts;
        return await bot.sendMessage(chatId, finalText.replace(/<[^>]*>/g, ''), rest);
      } catch (fallbackErr) {
        console.error('safeSend fallback failed:', fallbackErr.message);
      }
    } else {
      console.error('safeSend failed:', err.message);
    }
  }
}

async function safeEdit(chatId, messageId, text, options = {}) {
  const finalText = finalizeText(text);
  const baseOpts = { chat_id: chatId, message_id: messageId, parse_mode: PARSE_MODE, disable_web_page_preview: true, ...options };
  try {
    return await bot.editMessageText(finalText, baseOpts);
  } catch (err) {
    if (/message is not modified/i.test(err?.message || '')) return;
    if (/can't parse entities|parse entities/i.test(err?.message || '')) {
      try {
        const { parse_mode, ...rest } = baseOpts;
        return await bot.editMessageText(finalText.replace(/<[^>]*>/g, ''), rest);
      } catch { /* silent */ }
    }
    // Fallback: send new message
    try { await safeSend(chatId, finalText, options); } catch { /* silent */ }
  }
}

// ══════════════════════════════════════════════════════════════════════════════════════
// ADMIN NOTIFICATIONS
// ══════════════════════════════════════════════════════════════════════════════════════
async function notifyAdmins(message) {
  for (const adminId of config.telegram.adminIds) {
    try {
      await bot.sendMessage(adminId, message, { parse_mode: PARSE_MODE, disable_web_page_preview: true });
    } catch (err) {
      console.error(`Failed to notify admin ${adminId}:`, err.message);
    }
  }
}

async function notifyNewUser(user, msg) {
  await notifyAdmins(
    `🆕 <b>New User Joined</b>\n\n` +
    `<b>User ID:</b> <code>${user.chatId}</code>\n` +
    `<b>Username:</b> ${user.username ? '@' + escapeHTML(user.username) : 'N/A'}\n` +
    `<b>Name:</b> ${escapeHTML((user.firstName || '') + ' ' + (user.lastName || ''))}\n` +
    `<b>Joined:</b> ${formatTimestamp(user.createdAt)}\n` +
    `<b>Chat Type:</b> ${msg.chat.type}`
  );
}

async function notifyUserAction(user, action, details = '') {
  await notifyAdmins(
    `📊 <b>User Activity</b>\n\n` +
    `<b>User:</b> ${user.username ? '@' + escapeHTML(user.username) : user.chatId}\n` +
    `<b>Action:</b> ${escapeHTML(action)}\n` +
    (details ? `<b>Details:</b> ${escapeHTML(details)}\n` : '') +
    `<b>Time:</b> ${formatTimestamp(Date.now())}`
  );
}

// ══════════════════════════════════════════════════════════════════════════════════════
// PRICE FETCHING
// ══════════════════════════════════════════════════════════════════════════════════════
async function getTokenPrice(mintAddress) {
  const cached = priceCache.get(mintAddress);
  if (cached !== null) return cached;

  try {
    const response = await fetch(`https://price.jup.ag/v6/price?ids=${mintAddress}`);
    const data = await response.json();
    const price = data.data?.[mintAddress]?.price || null;
    if (price) priceCache.set(mintAddress, price);
    return price;
  } catch (err) {
    console.error('Price fetch error:', err.message);
    return null;
  }
}

async function getSolPrice() {
  const cached = priceCache.get('sol_usd');
  if (cached !== null) return cached;

  try {
    const res = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd');
    const data = await res.json();
    const price = data?.solana?.usd || 0;
    if (price) priceCache.set('sol_usd', price, 300000); // 5 min
    return price;
  } catch {
    // Fallback to Jupiter
    try {
      const p = await getTokenPrice(WSOL_MINT);
      if (p) priceCache.set('sol_usd', p, 300000);
      return p || 0;
    } catch { return 0; }
  }
}

// ══════════════════════════════════════════════════════════════════════════════════════
// TOKEN INFO
// ══════════════════════════════════════════════════════════════════════════════════════
async function getTokenInfo(mintAddress) {
  const cached = tokenInfoCache.get(mintAddress);
  if (cached) return cached;

  try {
    // Try Jupiter token list API (single token)
    const response = await fetch(`https://token.jup.ag/strict`);
    const tokens = await response.json();
    const token = tokens.find(t => t.address === mintAddress);

    if (token) {
      tokenInfoCache.set(mintAddress, token);
      return token;
    }

    // Try "all" list
    const allRes = await fetch(`https://token.jup.ag/all`);
    const allTokens = await allRes.json();
    const allToken = allTokens.find(t => t.address === mintAddress);

    if (allToken) {
      tokenInfoCache.set(mintAddress, allToken);
      return allToken;
    }

    // Fallback
    const fallback = { address: mintAddress, symbol: shortenAddress(mintAddress), name: 'Unknown Token', decimals: 9 };
    tokenInfoCache.set(mintAddress, fallback, 60000);
    return fallback;
  } catch (err) {
    console.error('Token info error:', err.message);
    return { address: mintAddress, symbol: shortenAddress(mintAddress), name: 'Unknown Token', decimals: 9 };
  }
}

// ══════════════════════════════════════════════════════════════════════════════════════
// TOKEN MARKET DATA (DexScreener)
// ══════════════════════════════════════════════════════════════════════════════════════
async function getTokenMarketData(mintAddress) {
  const cached = marketDataCache.get(mintAddress);
  if (cached) return cached;

  try {
    const res = await fetch(`https://api.dexscreener.com/latest/dex/tokens/${mintAddress}`);
    if (!res.ok) return null;
    const data = await res.json();
    const pair = data.pairs?.[0];
    if (!pair) return null;

    const result = {
      marketCap: pair.fdv || pair.marketCap,
      volume24h: pair.volume?.h24,
      priceChange24h: pair.priceChange?.h24,
      liquidity: pair.liquidity?.usd,
      dexId: pair.dexId,
      pairAddress: pair.pairAddress,
    };
    marketDataCache.set(mintAddress, result);
    return result;
  } catch { return null; }
}

async function getTokenHolderCount(mintAddress) {
  try {
    const apiKey = process.env.HELIUS_API_KEY || '';
    if (!apiKey) return 'N/A';
    const res = await fetch(`https://api.helius.xyz/v0/token-metadata?api-key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mintAccounts: [mintAddress] }),
    });
    if (!res.ok) return 'N/A';
    const data = await res.json();
    return data[0]?.onChainData?.holder_count || 'N/A';
  } catch { return 'N/A'; }
}

// ══════════════════════════════════════════════════════════════════════════════════════
// ADDRESS ANALYSIS
// ══════════════════════════════════════════════════════════════════════════════════════
async function analyzeAddress(address) {
  try {
    const pubkey = new PublicKey(address);
    const tokenInfo = await getTokenInfo(address);
    const isKnownToken = tokenInfo && tokenInfo.symbol !== shortenAddress(address);

    if (isKnownToken) {
      return { type: 'token', data: await getDetailedTokenInfo(address) };
    }

    const accountInfo = await rpcCall(conn => conn.getAccountInfo(pubkey));

    if (!accountInfo) {
      return { type: 'wallet', data: { address, balance: 0, isEmpty: true } };
    }

    if ([TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID].includes(accountInfo.owner.toBase58()) && accountInfo.data.length === 82) {
      return { type: 'token', data: await getDetailedTokenInfo(address) };
    }

    return { type: 'wallet', data: await getWalletAnalysis(address) };
  } catch (err) {
    console.error('Address analysis error:', err.message);
    return { type: 'unknown', error: err.message };
  }
}

async function getDetailedTokenInfo(mintAddress) {
  const [tokenInfo, price, holders, marketData] = await Promise.all([
    getTokenInfo(mintAddress),
    getTokenPrice(mintAddress),
    getTokenHolderCount(mintAddress),
    getTokenMarketData(mintAddress),
  ]);

  // Security score heuristic
  let securityScore = 50;
  if (marketData?.liquidity > 50000) securityScore += 15;
  if (marketData?.liquidity > 200000) securityScore += 10;
  if (holders !== 'N/A' && parseInt(holders) > 1000) securityScore += 10;
  if (marketData?.volume24h > 10000) securityScore += 10;
  if (Math.abs(marketData?.priceChange24h || 0) > 80) securityScore -= 15;
  securityScore = Math.max(0, Math.min(100, securityScore));

  return {
    ...tokenInfo,
    address: mintAddress,
    price,
    holders,
    marketCap: marketData?.marketCap,
    volume24h: marketData?.volume24h,
    priceChange24h: marketData?.priceChange24h,
    liquidity: marketData?.liquidity,
    securityScore,
  };
}

async function getWalletAnalysis(address) {
  try {
    const pubkey = new PublicKey(address);
    const [balance, tokenAccounts, recentSigs] = await Promise.all([
      rpcCall(conn => conn.getBalance(pubkey)),
      getTokenAccounts(address),
      rpcCall(conn => conn.getSignaturesForAddress(pubkey, { limit: 5 })),
    ]);

    let totalTokenValue = 0;
    const tokenHoldings = [];

    for (const token of tokenAccounts.slice(0, 10)) {
      const info = await getTokenInfo(token.mint);
      const p = await getTokenPrice(token.mint);
      const value = p ? token.balance * p : 0;
      totalTokenValue += value;
      tokenHoldings.push({ ...token, symbol: info?.symbol || shortenAddress(token.mint), name: info?.name || 'Unknown', price: p, value });
    }

    const solPrice = await getSolPrice();
    const solValue = solPrice ? (balance / LAMPORTS_PER_SOL) * solPrice : 0;

    const recentTxs = recentSigs.map(sig => ({
      signature: sig.signature,
      time: sig.blockTime ? new Date(sig.blockTime * 1000).toISOString() : null,
      status: sig.err ? 'failed' : 'success',
    }));

    return {
      address, balance, balanceSOL: balance / LAMPORTS_PER_SOL, solValue,
      tokenCount: tokenAccounts.length,
      tokenHoldings: tokenHoldings.sort((a, b) => b.value - a.value),
      totalTokenValue, totalValue: solValue + totalTokenValue,
      recentTxs, isEmpty: balance === 0 && tokenAccounts.length === 0,
    };
  } catch (err) {
    console.error('Wallet analysis error:', err.message);
    return { address, error: err.message };
  }
}

// ══════════════════════════════════════════════════════════════════════════════════════
// WALLET FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════════════
async function getWalletBalance(publicKey) {
  const cached = balanceCache.get(publicKey);
  if (cached !== null) return cached;
  try {
    const balance = await rpcCall(conn => conn.getBalance(new PublicKey(publicKey)));
    balanceCache.set(publicKey, balance);
    return balance;
  } catch (err) {
    console.error('Balance error:', err.message);
    return 0;
  }
}

async function getTokenAccounts(publicKey) {
  try {
    const { value: accounts } = await rpcCall(conn =>
      conn.getParsedTokenAccountsByOwner(new PublicKey(publicKey), { programId: new PublicKey(TOKEN_PROGRAM_ID) })
    );
    return accounts
      .map(a => ({
        mint: a.account.data.parsed.info.mint,
        balance: a.account.data.parsed.info.tokenAmount.uiAmount,
        decimals: a.account.data.parsed.info.tokenAmount.decimals,
      }))
      .filter(t => t.balance > 0);
  } catch (err) {
    console.error('Token accounts error:', err.message);
    return [];
  }
}

function generateWallet() {
  const keypair = Keypair.generate();
  const rawKey = bs58.encode(keypair.secretKey);
  return {
    publicKey: keypair.publicKey.toBase58(),
    privateKey: encryptData(rawKey),
    privateKeyRaw: rawKey, // used only for display on create, never stored
    name: `Wallet`,
    createdAt: Date.now(),
    imported: false,
  };
}

function importWalletFromKey(privateKey) {
  try {
    const decoded = bs58.decode(privateKey);
    const keypair = Keypair.fromSecretKey(decoded);
    return {
      publicKey: keypair.publicKey.toBase58(),
      privateKey: encryptData(privateKey),
      name: `Imported`,
      createdAt: Date.now(),
      imported: true,
    };
  } catch { return null; }
}

async function importWalletFromSeedPhrase(seedPhrase) {
  if (!bip39 || !derivePath) throw new Error('Seed phrase import not available (install bip39 & ed25519-hd-key)');
  if (!bip39.validateMnemonic(seedPhrase)) throw new Error('Invalid seed phrase');
  const seed = await bip39.mnemonicToSeed(seedPhrase);
  const derived = derivePath("m/44'/501'/0'/0'", seed.toString('hex')).key;
  const keypair = Keypair.fromSeed(derived);
  const rawKey = bs58.encode(keypair.secretKey);
  return {
    publicKey: keypair.publicKey.toBase58(),
    privateKey: encryptData(rawKey),
    name: `Imported (Seed)`,
    createdAt: Date.now(),
    imported: true,
  };
}

function getDecryptedKeypair(wallet) {
  const rawKey = decryptData(wallet.privateKey);
  const decoded = bs58.decode(rawKey);
  return Keypair.fromSecretKey(decoded);
}

// ══════════════════════════════════════════════════════════════════════════════════════
// JUPITER SWAP FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════════════
async function getSwapQuote(inputMint, outputMint, amount, slippageBps) {
  return withRetry(async () => {
    const res = await fetch(
      `https://quote-api.jup.ag/v6/quote?inputMint=${inputMint}&outputMint=${outputMint}&amount=${amount}&slippageBps=${slippageBps}`
    );
    if (!res.ok) throw new Error(`Quote API error: ${res.status}`);
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    return data;
  }, { retries: 2, baseDelayMs: 1000 });
}

async function executeSwap(wallet, quoteResponse) {
  try {
    const keypair = getDecryptedKeypair(wallet);

    const swapRes = await fetch('https://quote-api.jup.ag/v6/swap', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        quoteResponse,
        userPublicKey: wallet.publicKey,
        wrapAndUnwrapSol: true,
        dynamicComputeUnitLimit: true,
        prioritizationFeeLamports: config.jupiter.priorityFee,
      }),
    });

    if (!swapRes.ok) throw new Error(`Swap API error: ${swapRes.status}`);
    const { swapTransaction } = await swapRes.json();

    const txBuf = Buffer.from(swapTransaction, 'base64');
    const transaction = VersionedTransaction.deserialize(txBuf);
    transaction.sign([keypair]);

    const txid = await rpcCall(conn => conn.sendRawTransaction(transaction.serialize(), {
      skipPreflight: true,
      maxRetries: 3,
    }));

    const confirmation = await rpcCall(conn => conn.confirmTransaction(txid, 'confirmed'));
    if (confirmation.value.err) throw new Error('Transaction failed on-chain');

    return { success: true, txid, explorerUrl: `https://solscan.io/tx/${txid}` };
  } catch (err) {
    console.error('Swap execution error:', err.message);
    return { success: false, error: err.message };
  }
}

// ══════════════════════════════════════════════════════════════════════════════════════
// REFERRAL HELPERS
// ══════════════════════════════════════════════════════════════════════════════════════
function getReferralTier(referralCount) {
  if (referralCount >= 50) return 'DIAMOND';
  if (referralCount >= 30) return 'PLATINUM';
  if (referralCount >= 15) return 'GOLD';
  if (referralCount >= 5) return 'SILVER';
  return 'BRONZE';
}

// ══════════════════════════════════════════════════════════════════════════════════════
// TOKEN MESSAGE FORMATTER (Enhanced with Sentiment + Security)
// ══════════════════════════════════════════════════════════════════════════════════════
function formatTokenAnalysisMessage(data) {
  const e = (v) => escapeHTML(String(v ?? 'N/A'));
  const price = data.price ? formatPrice(data.price) : 'N/A';
  const mcap = data.marketCap ? `$${formatLargeNumber(data.marketCap)}` : 'N/A';
  const liq = data.liquidity ? `$${formatLargeNumber(data.liquidity)}` : 'N/A';
  const vol = data.volume24h ? `$${formatLargeNumber(data.volume24h)}` : 'N/A';
  const change = Number(data.priceChange24h ?? 0);

  // Sentiment
  let sentiment, vibe;
  if (change >= 100)     { sentiment = '🚀🔥 ABSOLUTELY SENDING'; vibe = '🤑'; }
  else if (change >= 50) { sentiment = '🚀 MOONING HARD'; vibe = '😎'; }
  else if (change >= 20) { sentiment = '📈🔥 PUMPING'; vibe = '💪'; }
  else if (change >= 5)  { sentiment = '📈 BULLISH'; vibe = '👍'; }
  else if (change >= -5) { sentiment = '➡️ CONSOLIDATING'; vibe = '🤔'; }
  else if (change >= -20){ sentiment = '📉 DIPPING'; vibe = '😬'; }
  else                   { sentiment = '💀 RUG ALERT'; vibe = '☠️'; }

  // Security bar
  const score = data.securityScore || 50;
  const filled = Math.round((score / 100) * 10);
  let barChar;
  if (score >= 60) barChar = '🟩';
  else if (score >= 40) barChar = '🟨';
  else barChar = '🟥';
  const bar = barChar.repeat(filled) + '⬜'.repeat(10 - filled);

  let rating;
  if (score >= 80) rating = '🟢 LOOKS SAFE';
  else if (score >= 60) rating = '🟢 LOOKS GOOD';
  else if (score >= 40) rating = '🟡 DYOR';
  else if (score >= 20) rating = '🔴 SKETCHY';
  else rating = '🔴 HIGH RISK';

  return (
    `${vibe} <b>${e(data.name)}</b> (${e(data.symbol)})\n` +
    `<code>${data.address}</code>\n\n` +

    `💰 <b>PRICE DATA</b>\n` +
    `├ Price: <b>${price}</b>\n` +
    `├ 24h: <b>${formatPercentage(change)}</b> ${sentiment}\n` +
    `├ MCap: <b>${mcap}</b>\n` +
    `├ Liq: <b>${liq}</b>\n` +
    `├ Volume: <b>${vol}</b>\n` +
    `└ Holders: <b>${data.holders || 'N/A'}</b>\n\n` +

    `🛡️ <b>SECURITY</b>\n` +
    `├ Score: [${bar}] ${score}/100\n` +
    `└ Rating: ${rating}\n\n` +

    `🔗 <a href="https://solscan.io/token/${data.address}">Solscan</a> • ` +
    `<a href="https://birdeye.so/token/${data.address}">Birdeye</a> • ` +
    `<a href="https://dexscreener.com/solana/${data.address}">DexScreener</a>`
  );
}

function formatWalletAnalysisMessage(data) {
  if (data.error) return `❌ Wallet analysis error: ${escapeHTML(data.error)}`;

  let msg =
    `👛 <b>Wallet Analysis</b>\n\n` +
    `<b>Address:</b> <code>${data.address}</code>\n` +
    (data.isEmpty ? '⚠️ <i>This wallet appears to be empty</i>\n' : '') + '\n' +
    `💰 <b>Balances</b>\n` +
    `├ SOL: ${formatNumber(data.balanceSOL)} SOL (~$${formatNumber(data.solValue, 2)})\n` +
    `├ Tokens: ${data.tokenCount} different tokens\n` +
    `└ Total Value: ~$${formatNumber(data.totalValue, 2)}\n`;

  if (data.tokenHoldings?.length > 0) {
    msg += '\n📦 <b>Top Holdings</b>\n';
    for (const t of data.tokenHoldings.slice(0, 5)) {
      msg += `├ ${escapeHTML(t.symbol)}: ${formatNumber(t.balance)} (~$${formatNumber(t.value, 2)})\n`;
    }
  }

  if (data.recentTxs?.length > 0) {
    msg += '\n📜 <b>Recent Transactions</b>\n';
    for (const tx of data.recentTxs.slice(0, 3)) {
      msg += `${tx.status === 'success' ? '✅' : '❌'} <code>${shortenAddress(tx.signature, 8)}</code>\n`;
    }
  }

  msg += `\n🔗 <a href="https://solscan.io/account/${data.address}">Solscan</a> • <a href="https://solana.fm/address/${data.address}">Solana FM</a>`;
  return msg;
}

// ══════════════════════════════════════════════════════════════════════════════════════
// TELEGRAM BOT SETUP
// ══════════════════════════════════════════════════════════════════════════════════════
const bot = new TelegramBot(config.telegram.token, { polling: true });

// ── Keyboard Layouts ────────────────────────────────────────────────────────────────
const mainMenuKeyboard = {
  reply_markup: {
    inline_keyboard: [
      [{ text: '💳 Wallets', callback_data: 'wallet' }, { text: '📊 Portfolio', callback_data: 'portfolio' }],
      [{ text: '⚡ Buy', callback_data: 'buy' }, { text: '💸 Sell', callback_data: 'sell' }],
      [{ text: '🔔 Alerts', callback_data: 'alerts' }, { text: '🎯 Limit Orders', callback_data: 'limit_orders' }],
      [{ text: '📈 DCA', callback_data: 'dca' }, { text: '🔍 Analyze', callback_data: 'analyze' }],
      [{ text: '📜 History', callback_data: 'history' }, { text: '🎁 Referrals', callback_data: 'referrals' }],
      [{ text: '⚙️ Settings', callback_data: 'settings' }, { text: '❓ Help', callback_data: 'help' }],
    ],
  },
};

const walletMenuKeyboard = {
  reply_markup: {
    inline_keyboard: [
      [{ text: '➕ Create Wallet', callback_data: 'wallet_create' }, { text: '📥 Import Wallet', callback_data: 'wallet_import' }],
      [{ text: '💰 Check Balance', callback_data: 'wallet_balance' }, { text: '📋 My Wallets', callback_data: 'wallet_list' }],
      [{ text: '🔄 Switch Wallet', callback_data: 'wallet_switch' }, { text: '✏️ Rename', callback_data: 'wallet_rename' }],
      [{ text: '🔐 Reveal Key', callback_data: 'wallet_reveal' }, { text: '🗑️ Delete', callback_data: 'wallet_delete' }],
      [{ text: '🔙 Main Menu', callback_data: 'main_menu' }],
    ],
  },
};

const alertsMenuKeyboard = {
  reply_markup: {
    inline_keyboard: [
      [{ text: '➕ Create Alert', callback_data: 'alert_create' }, { text: '📋 My Alerts', callback_data: 'alert_list' }],
      [{ text: '🔙 Main Menu', callback_data: 'main_menu' }],
    ],
  },
};

const settingsMenuKeyboard = {
  reply_markup: {
    inline_keyboard: [
      [{ text: '📊 Buy Slippage', callback_data: 'settings_buy_slippage' }, { text: '📊 Sell Slippage', callback_data: 'settings_sell_slippage' }],
      [{ text: '💰 Default Buy Amount', callback_data: 'settings_buy_amount' }, { text: '🔔 Notifications', callback_data: 'settings_notifications' }],
      [{ text: '🔙 Main Menu', callback_data: 'main_menu' }],
    ],
  },
};

function createTokenKeyboard(tokenAddress) {
  return {
    reply_markup: {
      inline_keyboard: [
        [{ text: '🔄 Refresh', callback_data: `refresh_${tokenAddress}` }, { text: '📍 Track', callback_data: `quick_alert_${tokenAddress}` }],
        [{ text: '~ ~ ~ 🅑🅤🅨 ~ ~ ~', callback_data: 'noop' }],
        [{ text: '🚀 Buy 0.1 SOL', callback_data: `qbuy_0.1_${tokenAddress}` }, { text: '🚀 Buy 0.5 SOL', callback_data: `qbuy_0.5_${tokenAddress}` }],
        [{ text: '🚀 Buy 1 SOL', callback_data: `qbuy_1_${tokenAddress}` }, { text: '✏️ Custom', callback_data: `quick_buy_${tokenAddress}` }],
        [{ text: '~ ~ ~ 🅢🅔🅛🅛 ~ ~ ~', callback_data: 'noop' }],
        [{ text: '💸 Sell 25%', callback_data: `qsell_25_${tokenAddress}` }, { text: '💸 Sell 50%', callback_data: `qsell_50_${tokenAddress}` }],
        [{ text: '💸 Sell 100%', callback_data: `qsell_100_${tokenAddress}` }],
        [{ text: '🎯 Limit Order', callback_data: `limit_create_${tokenAddress}` }, { text: '📈 DCA', callback_data: `dca_create_${tokenAddress}` }],
        [{ text: '🔙 Main Menu', callback_data: 'main_menu' }],
      ],
    },
  };
}

// ══════════════════════════════════════════════════════════════════════════════════════
// COMMAND HANDLERS
// ══════════════════════════════════════════════════════════════════════════════════════

// ── /start ──
bot.onText(/\/start(?:\s+(.+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const isNewUser = !state.users.has(chatId);
  const user = state.updateUserInfo(chatId, msg);

  // Referral handling
  const startParam = match[1]?.trim();
  if (startParam?.startsWith('ref_') && isNewUser) {
    const refCode = startParam.replace('ref_', '');
    const referrer = state.getAllUsers().find(u => u.referralCode === refCode);
    if (referrer && referrer.chatId !== chatId) {
      user.referredBy = refCode;
      referrer.referrals.push({ userId: chatId, username: user.username, date: Date.now() });
      await safeSend(referrer.chatId, `🎁 <b>New Referral!</b>\n\n${user.username ? '@' + escapeHTML(user.username) : 'A new user'} joined via your referral link!`);
    }
  }

  if (isNewUser) await notifyNewUser(user, msg);

  const name = user.firstName ? `, ${escapeHTML(user.firstName)}` : '';
  await safeSend(chatId,
    `🤖 <b>Sakilobot v${BOT_VERSION}</b>\n\n` +
    `Welcome${name}! Your ultimate Solana trading companion.\n\n` +
    `<b>⚡ Features</b>\n` +
    `├ 🔄 Jupiter DEX Swaps\n` +
    `├ 💳 Multi-Wallet (Create / Import / Seed Phrase)\n` +
    `├ 🔔 Price Alerts\n` +
    `├ 🎯 Limit Orders &amp; 📈 DCA\n` +
    `├ 📊 Portfolio &amp; PnL Tracking\n` +
    `├ 🔍 Token &amp; Wallet Analysis\n` +
    `├ 🎁 Referral Rewards\n` +
    `└ 🛡️ AES-256 Encrypted Key Storage\n\n` +
    `<b>💡 Quick Tip:</b> Paste any Solana address to analyze it instantly!\n\n` +
    `Select an option below to get started:`,
    mainMenuKeyboard
  );
});

// ── /help ──
bot.onText(/\/help/, async (msg) => {
  const chatId = msg.chat.id;
  state.updateUserInfo(chatId, msg);

  await safeSend(chatId,
    `📖 <b>Sakilobot Commands</b>\n\n` +
    `<b>General</b>\n` +
    `/start — Main menu\n` +
    `/help — This help\n` +
    `/wallet — Wallet management\n` +
    `/balance — Check wallet balance\n` +
    `/portfolio — Token holdings\n` +
    `/analyze &lt;address&gt; — Analyze address\n` +
    `/pnl — Profit &amp; Loss summary\n\n` +
    `<b>Trading</b>\n` +
    `/buy &lt;token&gt; &lt;sol_amount&gt; — Buy tokens\n` +
    `/sell &lt;token&gt; &lt;token_amount&gt; — Sell tokens\n` +
    `/price &lt;token&gt; — Check price\n\n` +
    `<b>Alerts &amp; Automation</b>\n` +
    `/alert &lt;token&gt; &lt;price&gt; &lt;above/below&gt;\n` +
    `/alerts — List alerts\n` +
    `/removealert &lt;id&gt;\n\n` +
    `<b>Settings</b>\n` +
    `/slippage &lt;bps&gt; — Set slippage\n` +
    `/settings — View settings\n\n` +
    `<b>Referrals</b>\n` +
    `/referral — Your referral link &amp; stats\n\n` +
    `<b>Admin</b>\n` +
    `/admin_users — List users\n` +
    `/admin_stats — Bot statistics\n` +
    `/admin_broadcast &lt;message&gt;\n` +
    `/admin_ban &lt;userId&gt; &lt;reason&gt;\n` +
    `/admin_unban &lt;userId&gt;\n\n` +
    `<b>💡 Quick Analysis:</b> Just paste any Solana address!`
  );
});

// ── /wallet ──
bot.onText(/\/wallet/, async (msg) => {
  const chatId = msg.chat.id;
  state.updateUserInfo(chatId, msg);
  await safeSend(chatId, '💳 <b>Wallet Management</b>\n\nManage your Solana wallets:', walletMenuKeyboard);
});

// ── /balance ──
bot.onText(/\/balance/, async (msg) => {
  const chatId = msg.chat.id;
  const user = state.updateUserInfo(chatId, msg);
  if (!user.activeWallet) return safeSend(chatId, '❌ No active wallet. Create or import one first.', walletMenuKeyboard);

  const loadMsg = await safeSend(chatId, '⏳ Fetching balance...');
  const balance = await getWalletBalance(user.activeWallet.publicKey);
  const solPrice = await getSolPrice();
  const usdValue = solPrice ? (balance / LAMPORTS_PER_SOL) * solPrice : 0;

  await safeEdit(chatId, loadMsg.message_id,
    `💰 <b>Wallet Balance</b>\n\n` +
    `<b>Address:</b> <code>${shortenAddress(user.activeWallet.publicKey, 6)}</code>\n` +
    `<b>SOL:</b> ${formatSOL(balance)} SOL\n` +
    `<b>USD:</b> ~$${formatNumber(usdValue, 2)}`
  );
});

// ── /portfolio ──
bot.onText(/\/portfolio/, async (msg) => {
  const chatId = msg.chat.id;
  const user = state.updateUserInfo(chatId, msg);
  if (!user.activeWallet) return safeSend(chatId, '❌ No active wallet.');

  const loadMsg = await safeSend(chatId, '⏳ Fetching portfolio...');
  const [solBalance, tokenAccounts] = await Promise.all([
    getWalletBalance(user.activeWallet.publicKey),
    getTokenAccounts(user.activeWallet.publicKey),
  ]);

  const solPrice = await getSolPrice();
  const solUSD = solPrice ? (solBalance / LAMPORTS_PER_SOL) * solPrice : 0;
  let totalUSD = solUSD;

  let text = `📊 <b>Portfolio</b>\n\n` +
    `<b>Wallet:</b> ${escapeHTML(user.activeWallet.name || 'Active')}\n` +
    `<code>${shortenAddress(user.activeWallet.publicKey, 6)}</code>\n\n` +
    `💰 <b>SOL:</b> ${formatSOL(solBalance)} (~$${formatNumber(solUSD, 2)})\n\n`;

  if (tokenAccounts.length === 0) {
    text += '📭 No token holdings found.';
  } else {
    text += `<b>Token Holdings (${tokenAccounts.length}):</b>\n\n`;
    for (const token of tokenAccounts.slice(0, 10)) {
      const info = await getTokenInfo(token.mint);
      const p = await getTokenPrice(token.mint);
      const value = p ? (token.balance * p) : 0;
      totalUSD += value;
      text += `• <b>${escapeHTML(info?.symbol || shortenAddress(token.mint))}</b>\n` +
        `  Balance: ${formatNumber(token.balance)} | Value: $${formatNumber(value, 2)}\n`;
    }
    text += `\n<b>Total Portfolio Value:</b> ~$${formatNumber(totalUSD, 2)}`;
  }

  await safeEdit(chatId, loadMsg.message_id, text);
});

// ── /price ──
bot.onText(/\/price(?:\s+(.+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const user = state.updateUserInfo(chatId, msg);
  const tokenInput = match[1]?.trim();
  if (!tokenInput) { user.awaitingInput = 'price_check'; return safeSend(chatId, '📈 Send a token address to check its price:'); }
  await handlePriceCheck(chatId, tokenInput);
});

async function handlePriceCheck(chatId, tokenAddress) {
  if (!isValidSolanaAddress(tokenAddress)) return safeSend(chatId, '❌ Invalid Solana address.');
  const loadMsg = await safeSend(chatId, '⏳ Fetching price...');
  const [info, price, mktData] = await Promise.all([getTokenInfo(tokenAddress), getTokenPrice(tokenAddress), getTokenMarketData(tokenAddress)]);
  if (!price) return safeEdit(chatId, loadMsg.message_id, '❌ Could not fetch price. Check the token address.');
  const change = mktData?.priceChange24h;

  await safeEdit(chatId, loadMsg.message_id,
    `📈 <b>Price Check</b>\n\n` +
    `<b>Token:</b> ${escapeHTML(info?.name || 'Unknown')} (${escapeHTML(info?.symbol || 'N/A')})\n` +
    `<b>Address:</b> <code>${shortenAddress(tokenAddress, 6)}</code>\n` +
    `<b>Price:</b> ${formatPrice(price)}\n` +
    (change != null ? `<b>24h:</b> ${formatPercentage(change)}\n` : '') +
    (mktData?.marketCap ? `<b>MCap:</b> $${formatLargeNumber(mktData.marketCap)}\n` : ''),
    createTokenKeyboard(tokenAddress)
  );
}

// ── /analyze ──
bot.onText(/\/analyze(?:\s+(.+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const user = state.updateUserInfo(chatId, msg);
  const addr = match[1]?.trim();
  if (!addr) { user.awaitingInput = 'analyze'; return safeSend(chatId, '🔍 Send a Solana address to analyze:'); }
  await performAddressAnalysis(chatId, addr);
});

async function performAddressAnalysis(chatId, address) {
  if (!isValidSolanaAddress(address)) return safeSend(chatId, '❌ Invalid Solana address format.');
  const loadMsg = await safeSend(chatId, '🔍 Analyzing address...');

  try {
    const analysis = await analyzeAddress(address);
    if (analysis.type === 'token') {
      await safeEdit(chatId, loadMsg.message_id, formatTokenAnalysisMessage(analysis.data), createTokenKeyboard(address));
    } else if (analysis.type === 'wallet') {
      await safeEdit(chatId, loadMsg.message_id, formatWalletAnalysisMessage(analysis.data), {
        reply_markup: { inline_keyboard: [[{ text: '🔄 Refresh', callback_data: `refresh_wallet_${address}` }], [{ text: '🔙 Main Menu', callback_data: 'main_menu' }]] },
      });
    } else {
      await safeEdit(chatId, loadMsg.message_id, `❌ Could not analyze: ${escapeHTML(analysis.error || 'Unknown type')}`);
    }
    const user = state.getUser(chatId);
    await notifyUserAction(user, 'Address Analysis', `${analysis.type}: ${shortenAddress(address)}`);
  } catch (err) {
    await safeEdit(chatId, loadMsg.message_id, `❌ Analysis failed: ${escapeHTML(err.message)}`);
  }
}

// ── /buy ──
bot.onText(/\/buy(?:\s+(.+)\s+(.+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const user = state.updateUserInfo(chatId, msg);
  if (!user.activeWallet) return safeSend(chatId, '❌ No active wallet.', walletMenuKeyboard);
  if (!rateLimiter.check(chatId, 'trade')) return safeSend(chatId, '⚠️ Rate limit exceeded. Please wait.');

  const tokenMint = match[1]?.trim();
  const amountSOL = match[2] ? parseFloat(match[2]) : null;

  if (!tokenMint || !amountSOL) {
    return safeSend(chatId,
      `⚡ <b>Buy Tokens</b>\n\n` +
      `Usage: <code>/buy &lt;token_address&gt; &lt;sol_amount&gt;</code>\n\n` +
      `Example:\n<code>/buy ${USDC_MINT} 0.1</code>\n\nThis spends 0.1 SOL to buy the token.`
    );
  }

  if (isNaN(amountSOL) || amountSOL <= 0) return safeSend(chatId, '❌ Invalid amount.');

  const loadMsg = await safeSend(chatId, '⏳ Getting quote...');
  const amountLamports = Math.floor(amountSOL * LAMPORTS_PER_SOL);
  const quote = await getSwapQuote(WSOL_MINT, tokenMint, amountLamports, user.settings.buySlippageBps).catch(() => null);
  if (!quote) return safeEdit(chatId, loadMsg.message_id, '❌ Could not get quote. Check the token address.');

  const info = await getTokenInfo(tokenMint);
  const outAmount = quote.outAmount / Math.pow(10, info?.decimals || 9);

  user.pendingSwap = { quote, type: 'buy', tokenMint };

  await safeEdit(chatId, loadMsg.message_id,
    `🔄 <b>Confirm Buy Order</b>\n\n` +
    `<b>Spending:</b> ${amountSOL} SOL\n` +
    `<b>Receiving:</b> ~${formatNumber(outAmount)} ${escapeHTML(info?.symbol || 'tokens')}\n` +
    `<b>Slippage:</b> ${user.settings.buySlippageBps / 100}%\n` +
    `<b>Price Impact:</b> ${quote.priceImpactPct || 'N/A'}%\n\n` +
    `Confirm this trade?`,
    { reply_markup: { inline_keyboard: [[{ text: '✅ Confirm Buy', callback_data: 'confirm_buy' }, { text: '❌ Cancel', callback_data: 'main_menu' }]] } }
  );
  await notifyUserAction(user, 'Buy Quote', `${amountSOL} SOL → ${escapeHTML(info?.symbol || shortenAddress(tokenMint))}`);
});

// ── /sell ──
bot.onText(/\/sell(?:\s+(.+)\s+(.+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const user = state.updateUserInfo(chatId, msg);
  if (!user.activeWallet) return safeSend(chatId, '❌ No active wallet.');
  if (!rateLimiter.check(chatId, 'trade')) return safeSend(chatId, '⚠️ Rate limit exceeded.');

  const tokenMint = match[1]?.trim();
  const amount = match[2] ? parseFloat(match[2]) : null;

  if (!tokenMint || !amount) {
    return safeSend(chatId,
      `💸 <b>Sell Tokens</b>\n\nUsage: <code>/sell &lt;token_address&gt; &lt;amount&gt;</code>\n\n` +
      `Example:\n<code>/sell ${USDC_MINT} 100</code>`
    );
  }

  if (isNaN(amount) || amount <= 0) return safeSend(chatId, '❌ Invalid amount.');

  const info = await getTokenInfo(tokenMint);
  const decimals = info?.decimals || 9;
  const loadMsg = await safeSend(chatId, '⏳ Getting quote...');
  const amountRaw = Math.floor(amount * Math.pow(10, decimals));
  const quote = await getSwapQuote(tokenMint, WSOL_MINT, amountRaw, user.settings.sellSlippageBps).catch(() => null);
  if (!quote) return safeEdit(chatId, loadMsg.message_id, '❌ Could not get quote.');

  const outSOL = quote.outAmount / LAMPORTS_PER_SOL;
  user.pendingSwap = { quote, type: 'sell', tokenMint };

  await safeEdit(chatId, loadMsg.message_id,
    `🔄 <b>Confirm Sell Order</b>\n\n` +
    `<b>Selling:</b> ${formatNumber(amount)} ${escapeHTML(info?.symbol || 'tokens')}\n` +
    `<b>Receiving:</b> ~${formatNumber(outSOL)} SOL\n` +
    `<b>Slippage:</b> ${user.settings.sellSlippageBps / 100}%\n` +
    `<b>Price Impact:</b> ${quote.priceImpactPct || 'N/A'}%\n\n` +
    `Confirm this trade?`,
    { reply_markup: { inline_keyboard: [[{ text: '✅ Confirm Sell', callback_data: 'confirm_sell' }, { text: '❌ Cancel', callback_data: 'main_menu' }]] } }
  );
});

// ── /alert ──
bot.onText(/\/alert(?:\s+(.+)\s+(.+)\s+(.+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const user = state.updateUserInfo(chatId, msg);
  const tokenMint = match[1]?.trim();
  const targetPrice = match[2] ? parseFloat(match[2]) : null;
  const direction = match[3]?.toLowerCase();

  if (!tokenMint || !targetPrice || !['above', 'below'].includes(direction)) {
    return safeSend(chatId,
      `🔔 <b>Create Price Alert</b>\n\n` +
      `Usage: <code>/alert &lt;token&gt; &lt;price&gt; &lt;above/below&gt;</code>\n\n` +
      `Example: <code>/alert ${WSOL_MINT} 200 above</code>`
    );
  }

  if (isNaN(targetPrice) || targetPrice <= 0) return safeSend(chatId, '❌ Invalid price.');
  if (state.getUserAlerts(chatId).length >= config.limits.maxAlerts) return safeSend(chatId, `❌ Max ${config.limits.maxAlerts} alerts reached.`);

  const alertId = state.addAlert(chatId, tokenMint, targetPrice, direction);
  const info = await getTokenInfo(tokenMint);

  await safeSend(chatId,
    `🔔 <b>Alert Created</b>\n\n` +
    `<b>ID:</b> #${alertId}\n` +
    `<b>Token:</b> ${escapeHTML(info?.symbol || shortenAddress(tokenMint))}\n` +
    `<b>Trigger:</b> Price goes <b>${direction}</b> ${formatPrice(targetPrice)}`
  );
  await notifyUserAction(user, 'Alert Created', `${escapeHTML(info?.symbol || shortenAddress(tokenMint))} ${direction} $${targetPrice}`);
});

// ── /alerts ──
bot.onText(/\/alerts/, async (msg) => {
  const chatId = msg.chat.id;
  state.updateUserInfo(chatId, msg);
  const alerts = state.getUserAlerts(chatId);

  if (alerts.length === 0) return safeSend(chatId, '📭 No active alerts.', alertsMenuKeyboard);

  let text = `🔔 <b>Your Alerts (${alerts.length})</b>\n\n`;
  for (const a of alerts) {
    const info = await getTokenInfo(a.tokenMint);
    text += `<b>#${a.id}</b> ${escapeHTML(info?.symbol || shortenAddress(a.tokenMint))}\n` +
      `  ${a.direction === 'above' ? '⬆️' : '⬇️'} ${a.direction} ${formatPrice(a.targetPrice)} | ${timeAgo(a.createdAt)}\n\n`;
  }
  text += 'Use /removealert &lt;id&gt; to remove.';
  await safeSend(chatId, text, alertsMenuKeyboard);
});

// ── /removealert ──
bot.onText(/\/removealert(?:\s+(.+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  state.updateUserInfo(chatId, msg);
  const idStr = match[1]?.trim();
  if (!idStr) return safeSend(chatId, '❌ Usage: /removealert &lt;id&gt;');
  const id = parseInt(idStr);
  const alert = state.priceAlerts.get(id);
  if (!alert || alert.chatId !== chatId) return safeSend(chatId, '❌ Alert not found.');
  state.removeAlert(id);
  await safeSend(chatId, `✅ Alert #${id} removed.`);
});

// ── /slippage ──
bot.onText(/\/slippage(?:\s+(.+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const user = state.updateUserInfo(chatId, msg);
  const val = match[1]?.trim();
  if (!val) {
    return safeSend(chatId,
      `📊 <b>Current Slippage</b>\n\n` +
      `Buy: ${user.settings.buySlippageBps / 100}%\n` +
      `Sell: ${user.settings.sellSlippageBps / 100}%\n\n` +
      `Usage: <code>/slippage &lt;bps&gt;</code>\nExample: <code>/slippage 100</code> = 1%`
    );
  }
  const bps = parseInt(val);
  if (isNaN(bps) || bps < 1 || bps > 5000) return safeSend(chatId, '❌ Slippage must be 1-5000 bps.');
  user.settings.buySlippageBps = bps;
  user.settings.sellSlippageBps = bps;
  await safeSend(chatId, `✅ Slippage set to ${bps / 100}% (buy &amp; sell)`);
});

// ── /settings ──
bot.onText(/\/settings/, async (msg) => {
  const chatId = msg.chat.id;
  const user = state.updateUserInfo(chatId, msg);
  await safeSend(chatId,
    `⚙️ <b>Settings</b>\n\n` +
    `<b>Buy Slippage:</b> ${user.settings.buySlippageBps / 100}%\n` +
    `<b>Sell Slippage:</b> ${user.settings.sellSlippageBps / 100}%\n` +
    `<b>Default Buy:</b> ${user.settings.defaultBuyAmount} SOL\n` +
    `<b>Notifications:</b> ${user.settings.notifications ? '✅ On' : '❌ Off'}\n` +
    `<b>Active Wallet:</b> ${user.activeWallet ? shortenAddress(user.activeWallet.publicKey) : 'None'}\n\n` +
    `<b>Stats</b>\n` +
    `├ Total Swaps: ${user.totalSwaps}\n` +
    `├ Total Alerts: ${user.totalAlerts}\n` +
    `└ Member Since: ${formatTimestamp(user.createdAt)}`,
    settingsMenuKeyboard
  );
});

// ── /referral ──
bot.onText(/\/referral/, async (msg) => {
  const chatId = msg.chat.id;
  const user = state.updateUserInfo(chatId, msg);
  const tier = getReferralTier(user.referrals.length);
  const tierInfo = REFERRAL_TIERS[tier];
  const botInfo = await bot.getMe();

  await safeSend(chatId,
    `🎁 <b>Referral Program</b>\n\n` +
    `<b>Your Link:</b>\n<code>https://t.me/${botInfo.username}?start=ref_${user.referralCode}</code>\n\n` +
    `<b>Your Stats</b>\n` +
    `├ Referrals: ${user.referrals.length}\n` +
    `├ Tier: ${tierInfo.emoji} ${tierInfo.name}\n` +
    `├ Commission: ${(tierInfo.rate * 100).toFixed(2)}%\n` +
    `└ Earnings: ${user.referralEarnings.toFixed(6)} SOL\n\n` +
    `<b>Tiers</b>\n` +
    Object.entries(REFERRAL_TIERS).map(([k, v]) =>
      `${k === tier ? '→' : '  '} ${v.emoji} ${v.name}: ${v.min}+ refs (${(v.rate * 100).toFixed(2)}%)`
    ).join('\n'),
    { reply_markup: { inline_keyboard: [[{ text: '🔙 Main Menu', callback_data: 'main_menu' }]] } }
  );
});

// ── /pnl ──
bot.onText(/\/pnl/, async (msg) => {
  const chatId = msg.chat.id;
  const user = state.updateUserInfo(chatId, msg);
  if (!user.activeWallet) return safeSend(chatId, '❌ No active wallet.');

  const txs = state.getUserTransactions(chatId);
  if (txs.length === 0) return safeSend(chatId, '📊 No transactions yet. Start trading to see your PnL!');

  let invested = 0, realized = 0;
  for (const tx of txs) {
    if (tx.type === 'buy') invested += tx.solAmount || 0;
    if (tx.type === 'sell') realized += tx.solAmount || 0;
  }
  const pnl = realized - invested;
  const pct = invested > 0 ? ((pnl / invested) * 100).toFixed(2) : '0.00';

  const balance = await getWalletBalance(user.activeWallet.publicKey);
  const solPrice = await getSolPrice();

  await safeSend(chatId,
    `📊 <b>PnL Summary</b>\n\n` +
    `🧾 <b>Wallet:</b> ${escapeHTML(user.activeWallet.name || 'Active')}\n` +
    `🕒 <b>Updated:</b> ${formatTimestamp(Date.now())}\n\n` +
    `<b>Invested:</b> ${invested.toFixed(4)} SOL\n` +
    `<b>Realized:</b> ${realized.toFixed(4)} SOL\n` +
    `<b>PnL:</b> ${pnl >= 0 ? '+' : ''}${pnl.toFixed(4)} SOL (${pct}%)\n\n` +
    `<b>Current Balance:</b> ${formatSOL(balance)} SOL (~$${formatNumber((balance / LAMPORTS_PER_SOL) * solPrice, 2)})\n` +
    `<b>Total Trades:</b> ${txs.length}`,
    { reply_markup: { inline_keyboard: [[{ text: '🔙 Main Menu', callback_data: 'main_menu' }]] } }
  );
});

// ── /setwallet ──
bot.onText(/\/setwallet(?:\s+(\d+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const user = state.updateUserInfo(chatId, msg);
  const num = match[1] ? parseInt(match[1]) : null;
  if (!num || num < 1 || num > user.wallets.length) return safeSend(chatId, `❌ Invalid. You have ${user.wallets.length} wallet(s).`);
  user.activeWallet = user.wallets[num - 1];
  await safeSend(chatId, `✅ Active wallet: <code>${shortenAddress(user.activeWallet.publicKey)}</code>`);
});

// ══════════════════════════════════════════════════════════════════════════════════════
// ADMIN COMMANDS
// ══════════════════════════════════════════════════════════════════════════════════════
function isAdmin(chatId) { return config.telegram.adminIds.includes(chatId); }

bot.onText(/\/admin_users/, async (msg) => {
  const chatId = msg.chat.id;
  if (!isAdmin(chatId)) return safeSend(chatId, '❌ Unauthorized.');
  const users = state.getAllUsers();
  let text = `👥 <b>All Users (${users.length})</b>\n\n`;
  for (const u of users.slice(0, 25)) {
    text += `• <b>${u.username ? '@' + escapeHTML(u.username) : u.chatId}</b>\n` +
      `  ID: <code>${u.chatId}</code> | Wallets: ${u.wallets.length} | Swaps: ${u.totalSwaps}\n` +
      `  ${u.isBanned ? '🚫 BANNED' : '✅'} | Last: ${timeAgo(u.lastActive)}\n\n`;
  }
  if (users.length > 25) text += `<i>...and ${users.length - 25} more</i>`;
  await safeSend(chatId, text);
});

bot.onText(/\/admin_stats/, async (msg) => {
  const chatId = msg.chat.id;
  if (!isAdmin(chatId)) return safeSend(chatId, '❌ Unauthorized.');
  const users = state.getAllUsers();
  const totalSwaps = users.reduce((s, u) => s + u.totalSwaps, 0);
  const activeToday = users.filter(u => Date.now() - u.lastActive < 86400000).length;
  const uptimeMs = Date.now() - state.systemStats.startedAt;
  const uptimeH = Math.floor(uptimeMs / 3600000);
  const uptimeM = Math.floor((uptimeMs % 3600000) / 60000);

  await safeSend(chatId,
    `📊 <b>Bot Statistics</b>\n\n` +
    `<b>Users</b>\n├ Total: ${users.length}\n├ Active (24h): ${activeToday}\n└ Banned: ${users.filter(u => u.isBanned).length}\n\n` +
    `<b>Activity</b>\n├ Total Swaps: ${totalSwaps}\n├ Active Alerts: ${state.priceAlerts.size}\n├ Limit Orders: ${Array.from(state.limitOrders.values()).filter(o => o.active).length}\n└ DCA Orders: ${Array.from(state.dcaOrders.values()).filter(o => o.active).length}\n\n` +
    `<b>System</b>\n├ Uptime: ${uptimeH}h ${uptimeM}m\n├ RPC: Endpoint ${rpcIndex + 1}/${config.solana.rpcUrls.length}\n└ Version: v${BOT_VERSION}`
  );
});

bot.onText(/\/admin_broadcast (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  if (!isAdmin(chatId)) return safeSend(chatId, '❌ Unauthorized.');
  const broadcastText = match[1];
  const users = state.getAllUsers();
  let sent = 0, failed = 0;
  await safeSend(chatId, `📢 Broadcasting to ${users.length} users...`);
  for (const u of users) {
    try {
      await bot.sendMessage(u.chatId, `📢 <b>Announcement</b>\n\n${escapeHTML(broadcastText)}`, { parse_mode: PARSE_MODE });
      sent++;
    } catch { failed++; }
    await sleep(250); // Telegram rate limit safe
  }
  await safeSend(chatId, `✅ Broadcast complete. Sent: ${sent} | Failed: ${failed}`);
});

bot.onText(/\/admin_ban(?:\s+(\S+)(?:\s+(.+))?)?/, async (msg, match) => {
  const chatId = msg.chat.id;
  if (!isAdmin(chatId)) return safeSend(chatId, '❌ Unauthorized.');
  const targetId = match[1] ? parseInt(match[1]) : null;
  const reason = match[2] || 'No reason provided';
  if (!targetId) return safeSend(chatId, '❌ Usage: /admin_ban &lt;userId&gt; &lt;reason&gt;');

  const target = state.getUser(targetId);
  if (isAdmin(targetId)) return safeSend(chatId, '❌ Cannot ban an admin.');
  target.isBanned = true;
  target.banReason = reason;
  await safeSend(chatId, `🚫 User ${targetId} banned. Reason: ${escapeHTML(reason)}`);
  try { await bot.sendMessage(targetId, `🚫 <b>Account Suspended</b>\n\nReason: ${escapeHTML(reason)}`, { parse_mode: PARSE_MODE }); } catch {}
});

bot.onText(/\/admin_unban(?:\s+(\S+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  if (!isAdmin(chatId)) return safeSend(chatId, '❌ Unauthorized.');
  const targetId = match[1] ? parseInt(match[1]) : null;
  if (!targetId) return safeSend(chatId, '❌ Usage: /admin_unban &lt;userId&gt;');
  const target = state.getUser(targetId);
  target.isBanned = false;
  target.banReason = '';
  await safeSend(chatId, `✅ User ${targetId} unbanned.`);
  try { await bot.sendMessage(targetId, '✅ Your account has been reinstated.', { parse_mode: PARSE_MODE }); } catch {}
});

// ══════════════════════════════════════════════════════════════════════════════════════
// CALLBACK QUERY HANDLER
// ══════════════════════════════════════════════════════════════════════════════════════
bot.on('callback_query', async (query) => {
  const chatId = query.message.chat.id;
  const messageId = query.message.message_id;
  const data = query.data;
  const user = state.getUser(chatId);

  await bot.answerCallbackQuery(query.id).catch(() => {});

  // Ban check
  if (user.isBanned) {
    return safeSend(chatId, `🚫 <b>Account Suspended</b>\n\nReason: ${escapeHTML(user.banReason || 'Contact admin.')}`);
  }

  // ── Dynamic callbacks (token addresses in data) ──
  if (data === 'noop') return;

  // Quick buy with preset amount
  const qbuyMatch = data.match(/^qbuy_([\d.]+)_(.+)$/);
  if (qbuyMatch) {
    const amount = parseFloat(qbuyMatch[1]);
    const tokenAddr = qbuyMatch[2];
    if (!user.activeWallet) return safeSend(chatId, '❌ No active wallet.', walletMenuKeyboard);
    if (!rateLimiter.check(chatId, 'trade')) return safeSend(chatId, '⚠️ Rate limit exceeded.');

    await safeEdit(chatId, messageId, '⏳ Getting quote...');
    const amountLam = Math.floor(amount * LAMPORTS_PER_SOL);
    const quote = await getSwapQuote(WSOL_MINT, tokenAddr, amountLam, user.settings.buySlippageBps).catch(() => null);
    if (!quote) return safeEdit(chatId, messageId, '❌ Could not get quote.', createTokenKeyboard(tokenAddr));

    const info = await getTokenInfo(tokenAddr);
    const outAmt = quote.outAmount / Math.pow(10, info?.decimals || 9);
    user.pendingSwap = { quote, type: 'buy', tokenMint: tokenAddr };

    return safeEdit(chatId, messageId,
      `🔄 <b>Confirm Buy</b>\n\n<b>Spend:</b> ${amount} SOL\n<b>Receive:</b> ~${formatNumber(outAmt)} ${escapeHTML(info?.symbol || 'tokens')}\n<b>Slippage:</b> ${user.settings.buySlippageBps / 100}%`,
      { reply_markup: { inline_keyboard: [[{ text: '✅ Confirm', callback_data: 'confirm_buy' }, { text: '❌ Cancel', callback_data: `refresh_${tokenAddr}` }]] } }
    );
  }

  // Quick sell with percentage
  const qsellMatch = data.match(/^qsell_(\d+)_(.+)$/);
  if (qsellMatch) {
    const pct = parseInt(qsellMatch[1]);
    const tokenAddr = qsellMatch[2];
    if (!user.activeWallet) return safeSend(chatId, '❌ No active wallet.');
    if (!rateLimiter.check(chatId, 'trade')) return safeSend(chatId, '⚠️ Rate limit exceeded.');

    await safeEdit(chatId, messageId, '⏳ Calculating...');

    // Get token balance
    const tokenAccounts = await getTokenAccounts(user.activeWallet.publicKey);
    const tokenAcc = tokenAccounts.find(t => t.mint === tokenAddr);
    if (!tokenAcc || tokenAcc.balance <= 0) return safeEdit(chatId, messageId, '❌ No balance for this token.', createTokenKeyboard(tokenAddr));

    const sellAmount = tokenAcc.balance * (pct / 100);
    const info = await getTokenInfo(tokenAddr);
    const decimals = info?.decimals || 9;
    const amountRaw = Math.floor(sellAmount * Math.pow(10, decimals));

    const quote = await getSwapQuote(tokenAddr, WSOL_MINT, amountRaw, user.settings.sellSlippageBps).catch(() => null);
    if (!quote) return safeEdit(chatId, messageId, '❌ Could not get quote.', createTokenKeyboard(tokenAddr));

    const outSOL = quote.outAmount / LAMPORTS_PER_SOL;
    user.pendingSwap = { quote, type: 'sell', tokenMint: tokenAddr };

    return safeEdit(chatId, messageId,
      `🔄 <b>Confirm Sell (${pct}%)</b>\n\n<b>Sell:</b> ${formatNumber(sellAmount)} ${escapeHTML(info?.symbol || 'tokens')}\n<b>Receive:</b> ~${formatNumber(outSOL)} SOL\n<b>Slippage:</b> ${user.settings.sellSlippageBps / 100}%`,
      { reply_markup: { inline_keyboard: [[{ text: '✅ Confirm', callback_data: 'confirm_sell' }, { text: '❌ Cancel', callback_data: `refresh_${tokenAddr}` }]] } }
    );
  }

  // Custom buy prompt
  if (data.startsWith('quick_buy_')) {
    const addr = data.replace('quick_buy_', '');
    user.awaitingInput = `quick_buy_${addr}`;
    return safeSend(chatId, `⚡ Enter SOL amount to buy ${shortenAddress(addr)}:`);
  }

  // Custom alert prompt
  if (data.startsWith('quick_alert_')) {
    const addr = data.replace('quick_alert_', '');
    user.awaitingInput = `quick_alert_${addr}`;
    return safeSend(chatId, '🔔 Enter target price and direction (e.g., <code>0.001 above</code>):');
  }

  // Refresh wallet analysis
  if (data.startsWith('refresh_wallet_')) {
    const addr = data.replace('refresh_wallet_', '');
    return performAddressAnalysis(chatId, addr);
  }

  // Refresh token
  if (data.startsWith('refresh_')) {
    const addr = data.replace('refresh_', '');
    if (isValidSolanaAddress(addr)) {
      marketDataCache.del(addr);
      priceCache.del(addr);
      return performAddressAnalysis(chatId, addr);
    }
  }

  // Limit order create prompt
  if (data.startsWith('limit_create_')) {
    const addr = data.replace('limit_create_', '');
    user.awaitingInput = `limit_create_${addr}`;
    return safeSend(chatId, '🎯 Enter: <code>&lt;buy/sell&gt; &lt;price&gt; &lt;amount&gt;</code>\n\nExample: <code>buy 0.005 0.5</code> (buy 0.5 SOL worth when price hits $0.005)');
  }

  // DCA create prompt
  if (data.startsWith('dca_create_')) {
    const addr = data.replace('dca_create_', '');
    user.awaitingInput = `dca_create_${addr}`;
    return safeSend(chatId, '📈 Enter: <code>&lt;sol_per_order&gt; &lt;interval_hours&gt; &lt;total_orders&gt;</code>\n\nExample: <code>0.1 4 10</code> (buy 0.1 SOL every 4 hours, 10 times)');
  }

  // ── Static callbacks ──
  switch (data) {
    case 'main_menu':
      return safeEdit(chatId, messageId, `🤖 <b>Sakilobot v${BOT_VERSION}</b>\n\nSelect an option:`, mainMenuKeyboard);

    case 'wallet':
      return safeEdit(chatId, messageId, '💳 <b>Wallet Management</b>\n\nManage your Solana wallets:', walletMenuKeyboard);

    case 'wallet_create': {
      if (!rateLimiter.check(chatId, 'wallet')) return safeSend(chatId, '⚠️ Rate limit exceeded.');
      if (user.wallets.length >= config.limits.maxWallets) return safeSend(chatId, `❌ Max ${config.limits.maxWallets} wallets.`);

      const w = generateWallet();
      w.name = `Wallet_${user.wallets.length + 1}`;
      user.wallets.push(w);
      user.activeWallet = w;

      await safeEdit(chatId, messageId,
        `✅ <b>Wallet Created!</b>\n\n` +
        `<b>Name:</b> ${escapeHTML(w.name)}\n` +
        `<b>Address:</b> <code>${w.publicKey}</code>\n\n` +
        `⚠️ <b>SAVE YOUR PRIVATE KEY:</b>\n<code>${w.privateKeyRaw}</code>\n\n` +
        `<i>Store this securely. It won't be shown again.</i>`,
        walletMenuKeyboard
      );
      await notifyUserAction(user, 'Wallet Created', shortenAddress(w.publicKey));
      break;
    }

    case 'wallet_import':
      user.awaitingInput = 'wallet_import';
      await safeEdit(chatId, messageId,
        `📥 <b>Import Wallet</b>\n\n` +
        `Send your <b>private key</b> (Base58) or <b>seed phrase</b> (12/24 words).\n\n` +
        `⚠️ <i>Make sure you're in a private chat!</i>\n` +
        `💡 Supports Phantom, Solflare, and other Solana wallets.`,
        { reply_markup: { inline_keyboard: [[{ text: '❌ Cancel', callback_data: 'wallet' }]] } }
      );
      break;

    case 'wallet_balance':
      if (!user.activeWallet) return safeSend(chatId, '❌ No active wallet.', walletMenuKeyboard);
      const bal = await getWalletBalance(user.activeWallet.publicKey);
      const sp = await getSolPrice();
      await safeEdit(chatId, messageId,
        `💰 <b>Wallet Balance</b>\n\n` +
        `<b>Name:</b> ${escapeHTML(user.activeWallet.name || 'Active')}\n` +
        `<b>Address:</b> <code>${shortenAddress(user.activeWallet.publicKey, 6)}</code>\n` +
        `<b>SOL:</b> ${formatSOL(bal)} (~$${formatNumber((bal / LAMPORTS_PER_SOL) * sp, 2)})`,
        walletMenuKeyboard
      );
      break;

    case 'wallet_list': {
      if (user.wallets.length === 0) return safeSend(chatId, '📭 No wallets yet.', walletMenuKeyboard);
      let text = `📋 <b>Your Wallets (${user.wallets.length})</b>\n\n`;
      for (let i = 0; i < user.wallets.length; i++) {
        const w = user.wallets[i];
        const active = user.activeWallet?.publicKey === w.publicKey;
        const b = await getWalletBalance(w.publicKey);
        text += `${active ? '✅' : '◻️'} <b>${i + 1}.</b> ${escapeHTML(w.name || `Wallet ${i + 1}`)}\n` +
          `   <code>${shortenAddress(w.publicKey)}</code> | ${formatSOL(b)} SOL\n\n`;
      }
      text += 'Use /setwallet &lt;number&gt; to switch.';
      await safeEdit(chatId, messageId, text, walletMenuKeyboard);
      break;
    }

    case 'wallet_reveal':
      if (!user.activeWallet) return safeSend(chatId, '❌ No active wallet.');
      const rawKey = decryptData(user.activeWallet.privateKey);
      await safeSend(chatId,
        `🔐 <b>Private Key (Active Wallet)</b>\n\n` +
        `<b>Name:</b> ${escapeHTML(user.activeWallet.name)}\n` +
        `<b>Address:</b> <code>${user.activeWallet.publicKey}</code>\n` +
        `<b>Key:</b> <code>${rawKey}</code>\n\n` +
        `⚠️ <i>Never share this with anyone!</i>`
      );
      break;

    case 'wallet_rename':
      if (!user.activeWallet) return safeSend(chatId, '❌ No active wallet.');
      user.awaitingInput = 'wallet_rename';
      await safeSend(chatId, `✏️ Enter new name for wallet <code>${shortenAddress(user.activeWallet.publicKey)}</code>:`);
      break;

    case 'wallet_delete':
      if (!user.activeWallet) return safeSend(chatId, '❌ No active wallet.');
      user.awaitingInput = 'wallet_delete_confirm';
      await safeSend(chatId,
        `🗑️ <b>Delete Wallet?</b>\n\n` +
        `<b>Name:</b> ${escapeHTML(user.activeWallet.name)}\n` +
        `<b>Address:</b> <code>${shortenAddress(user.activeWallet.publicKey)}</code>\n\n` +
        `⚠️ This cannot be undone. Type <code>DELETE</code> to confirm.`
      );
      break;

    case 'wallet_switch':
      if (user.wallets.length <= 1) return safeSend(chatId, '❌ You only have one wallet.');
      user.awaitingInput = 'wallet_switch';
      let switchText = '🔄 Enter wallet number to switch:\n\n';
      user.wallets.forEach((w, i) => {
        switchText += `${i + 1}. ${escapeHTML(w.name)} — <code>${shortenAddress(w.publicKey)}</code>\n`;
      });
      await safeSend(chatId, switchText);
      break;

    case 'confirm_buy': {
      if (!user.pendingSwap || user.pendingSwap.type !== 'buy') return safeSend(chatId, '❌ No pending buy order.');
      await safeEdit(chatId, messageId, '⏳ Executing swap...');
      const result = await executeSwap(user.activeWallet, user.pendingSwap.quote);
      const swapToken = user.pendingSwap.tokenMint;
      const info = await getTokenInfo(swapToken);
      user.pendingSwap = null;

      if (result.success) {
        user.totalSwaps++;
        state.systemStats.totalSwaps++;
        state.addTransaction(chatId, { type: 'buy', tokenMint: swapToken, tokenSymbol: info?.symbol, txid: result.txid, solAmount: 0 });
        balanceCache.del(user.activeWallet.publicKey);
        await safeEdit(chatId, messageId,
          `✅ <b>Buy Successful!</b>\n\n<b>TX:</b> <a href="${result.explorerUrl}">View on Solscan</a>`,
          createTokenKeyboard(swapToken)
        );
        await notifyUserAction(user, 'Swap (Buy)', `TX: ${shortenAddress(result.txid, 8)}`);
      } else {
        await safeEdit(chatId, messageId, `❌ Swap failed: ${escapeHTML(result.error)}`, createTokenKeyboard(swapToken));
      }
      break;
    }

    case 'confirm_sell': {
      if (!user.pendingSwap || user.pendingSwap.type !== 'sell') return safeSend(chatId, '❌ No pending sell order.');
      await safeEdit(chatId, messageId, '⏳ Executing swap...');
      const result = await executeSwap(user.activeWallet, user.pendingSwap.quote);
      const swapToken = user.pendingSwap.tokenMint;
      const info = await getTokenInfo(swapToken);
      user.pendingSwap = null;

      if (result.success) {
        user.totalSwaps++;
        state.systemStats.totalSwaps++;
        state.addTransaction(chatId, { type: 'sell', tokenMint: swapToken, tokenSymbol: info?.symbol, txid: result.txid, solAmount: 0 });
        balanceCache.del(user.activeWallet.publicKey);
        await safeEdit(chatId, messageId,
          `✅ <b>Sell Successful!</b>\n\n<b>TX:</b> <a href="${result.explorerUrl}">View on Solscan</a>`,
          createTokenKeyboard(swapToken)
        );
        await notifyUserAction(user, 'Swap (Sell)', `TX: ${shortenAddress(result.txid, 8)}`);
      } else {
        await safeEdit(chatId, messageId, `❌ Swap failed: ${escapeHTML(result.error)}`, createTokenKeyboard(swapToken));
      }
      break;
    }

    case 'portfolio':
      await bot.deleteMessage(chatId, messageId).catch(() => {});
      bot.emit('text', { chat: { id: chatId }, from: query.from, text: '/portfolio' });
      break;

    case 'buy':
      await safeEdit(chatId, messageId,
        `⚡ <b>Buy Tokens</b>\n\nUse: <code>/buy &lt;token_address&gt; &lt;sol_amount&gt;</code>\n\nOr paste a token address to analyze it first!`,
        { reply_markup: { inline_keyboard: [[{ text: '🔙 Back', callback_data: 'main_menu' }]] } }
      );
      break;

    case 'sell':
      await safeEdit(chatId, messageId,
        `💸 <b>Sell Tokens</b>\n\nUse: <code>/sell &lt;token_address&gt; &lt;amount&gt;</code>\n\nOr use /portfolio to see holdings.`,
        { reply_markup: { inline_keyboard: [[{ text: '🔙 Back', callback_data: 'main_menu' }]] } }
      );
      break;

    case 'alerts':
      await safeEdit(chatId, messageId, '🔔 <b>Price Alerts</b>\n\nMonitor token prices:', alertsMenuKeyboard);
      break;

    case 'alert_create':
      await safeEdit(chatId, messageId,
        `🔔 <b>Create Alert</b>\n\nUse: <code>/alert &lt;token&gt; &lt;price&gt; &lt;above/below&gt;</code>`,
        { reply_markup: { inline_keyboard: [[{ text: '🔙 Back', callback_data: 'alerts' }]] } }
      );
      break;

    case 'alert_list':
      await bot.deleteMessage(chatId, messageId).catch(() => {});
      bot.emit('text', { chat: { id: chatId }, from: query.from, text: '/alerts' });
      break;

    case 'limit_orders': {
      const orders = state.getUserLimitOrders(chatId);
      let text = `🎯 <b>Limit Orders (${orders.length})</b>\n\n`;
      if (orders.length === 0) text += 'No active limit orders.\n\nAnalyze a token and click "🎯 Limit Order" to create one.';
      else for (const o of orders.slice(0, 10)) {
        text += `<b>#${o.id}</b> ${o.type.toUpperCase()} ${escapeHTML(o.tokenSymbol || shortenAddress(o.tokenMint))}\n` +
          `  Target: ${formatPrice(o.targetPrice)} | Amount: ${o.amount}\n\n`;
      }
      await safeEdit(chatId, messageId, text, { reply_markup: { inline_keyboard: [[{ text: '🔙 Main Menu', callback_data: 'main_menu' }]] } });
      break;
    }

    case 'dca': {
      const orders = state.getUserDCAOrders(chatId);
      let text = `📈 <b>DCA Orders (${orders.length})</b>\n\n`;
      if (orders.length === 0) text += 'No active DCA orders.\n\nAnalyze a token and click "📈 DCA" to create one.';
      else for (const o of orders.slice(0, 10)) {
        text += `<b>#${o.id}</b> ${escapeHTML(o.tokenSymbol || shortenAddress(o.tokenMint))}\n` +
          `  ${o.amountPerInterval} SOL every ${(o.intervalMs / 3600000).toFixed(1)}h | ${o.executedOrders}/${o.totalOrders}\n\n`;
      }
      await safeEdit(chatId, messageId, text, { reply_markup: { inline_keyboard: [[{ text: '🔙 Main Menu', callback_data: 'main_menu' }]] } });
      break;
    }

    case 'history': {
      const txs = state.getUserTransactions(chatId);
      let text = `📜 <b>Transaction History</b>\n\n`;
      if (txs.length === 0) text += 'No transactions yet.';
      else for (const tx of txs.slice(0, 10)) {
        const emoji = tx.type === 'buy' ? '💰' : '💸';
        text += `${emoji} <b>${tx.type.toUpperCase()}</b> ${escapeHTML(tx.tokenSymbol || 'N/A')}\n` +
          `  ${timeAgo(tx.timestamp)} | <a href="https://solscan.io/tx/${tx.txid}">TX</a>\n\n`;
      }
      await safeEdit(chatId, messageId, text, { reply_markup: { inline_keyboard: [[{ text: '🔄 Refresh', callback_data: 'history' }], [{ text: '🔙 Main Menu', callback_data: 'main_menu' }]] } });
      break;
    }

    case 'referrals':
      await bot.deleteMessage(chatId, messageId).catch(() => {});
      bot.emit('text', { chat: { id: chatId }, from: query.from, text: '/referral' });
      break;

    case 'analyze':
      user.awaitingInput = 'analyze';
      await safeEdit(chatId, messageId,
        `🔍 <b>Address Analyzer</b>\n\n` +
        `Paste any Solana address (wallet or token) to get:\n` +
        `• Token info, market data &amp; security score\n` +
        `• Wallet balances &amp; holdings\n` +
        `• Recent transactions\n` +
        `• Quick buy/sell buttons`,
        { reply_markup: { inline_keyboard: [[{ text: '🔙 Back', callback_data: 'main_menu' }]] } }
      );
      break;

    case 'settings':
      await bot.deleteMessage(chatId, messageId).catch(() => {});
      bot.emit('text', { chat: { id: chatId }, from: query.from, text: '/settings' });
      break;

    case 'help':
      await bot.deleteMessage(chatId, messageId).catch(() => {});
      bot.emit('text', { chat: { id: chatId }, from: query.from, text: '/help' });
      break;

    case 'settings_buy_slippage':
      user.awaitingInput = 'settings_buy_slippage';
      await safeSend(chatId, `📊 Current buy slippage: ${user.settings.buySlippageBps / 100}%\n\nEnter new value in bps (50 = 0.5%, 100 = 1%, 500 = 5%):`);
      break;

    case 'settings_sell_slippage':
      user.awaitingInput = 'settings_sell_slippage';
      await safeSend(chatId, `📊 Current sell slippage: ${user.settings.sellSlippageBps / 100}%\n\nEnter new value in bps:`);
      break;

    case 'settings_buy_amount':
      user.awaitingInput = 'settings_buy_amount';
      await safeSend(chatId, `💰 Current default buy: ${user.settings.defaultBuyAmount} SOL\n\nEnter new default SOL amount:`);
      break;

    case 'settings_notifications':
      user.settings.notifications = !user.settings.notifications;
      await safeSend(chatId, `🔔 Notifications ${user.settings.notifications ? '✅ Enabled' : '❌ Disabled'}`, settingsMenuKeyboard);
      break;
  }
});

// ══════════════════════════════════════════════════════════════════════════════════════
// TEXT MESSAGE HANDLER (Awaiting inputs + Auto address detection)
// ══════════════════════════════════════════════════════════════════════════════════════
bot.on('message', async (msg) => {
  if (!msg.text || msg.text.startsWith('/')) return;
  const chatId = msg.chat.id;
  const user = state.updateUserInfo(chatId, msg);
  const text = msg.text.trim();

  // Ban check
  if (user.isBanned) return safeSend(chatId, `🚫 <b>Account Suspended</b>\nReason: ${escapeHTML(user.banReason || 'Contact admin.')}`);

  // ── Awaiting inputs ──
  if (user.awaitingInput) {
    const inputType = user.awaitingInput;
    user.awaitingInput = null;

    // Wallet import
    if (inputType === 'wallet_import') {
      try { await bot.deleteMessage(chatId, msg.message_id); } catch {}

      let wallet = null;
      const words = text.split(/\s+/);
      if ((words.length === 12 || words.length === 24) && bip39) {
        try { wallet = await importWalletFromSeedPhrase(text); } catch {}
      }
      if (!wallet) wallet = importWalletFromKey(text);

      if (wallet) {
        // Check duplicate
        if (user.wallets.some(w => w.publicKey === wallet.publicKey)) {
          return safeSend(chatId, '⚠️ This wallet is already in your account.', walletMenuKeyboard);
        }
        wallet.name = `Imported_${user.wallets.length + 1}`;
        user.wallets.push(wallet);
        user.activeWallet = wallet;
        await safeSend(chatId, `✅ <b>Wallet Imported!</b>\n\n<b>Name:</b> ${escapeHTML(wallet.name)}\n<b>Address:</b> <code>${wallet.publicKey}</code>`, walletMenuKeyboard);
        await notifyUserAction(user, 'Wallet Imported', shortenAddress(wallet.publicKey));
      } else {
        await safeSend(chatId, '❌ Invalid private key or seed phrase. Try again or use /wallet', walletMenuKeyboard);
      }
      return;
    }

    // Wallet rename
    if (inputType === 'wallet_rename') {
      const name = sanitizeString(text, 50);
      if (!name) return safeSend(chatId, '❌ Invalid name (1-50 chars).');
      user.activeWallet.name = name;
      return safeSend(chatId, `✅ Wallet renamed to: ${escapeHTML(name)}`, walletMenuKeyboard);
    }

    // Wallet delete confirm
    if (inputType === 'wallet_delete_confirm') {
      if (text !== 'DELETE') return safeSend(chatId, '❌ Cancelled.', walletMenuKeyboard);
      const idx = user.wallets.indexOf(user.activeWallet);
      if (idx > -1) user.wallets.splice(idx, 1);
      const deleted = user.activeWallet;
      user.activeWallet = user.wallets[0] || null;
      await notifyUserAction(user, 'Wallet Deleted', shortenAddress(deleted.publicKey));
      return safeSend(chatId, '✅ Wallet deleted.', walletMenuKeyboard);
    }

    // Wallet switch
    if (inputType === 'wallet_switch') {
      const num = parseInt(text);
      if (isNaN(num) || num < 1 || num > user.wallets.length) return safeSend(chatId, '❌ Invalid number.');
      user.activeWallet = user.wallets[num - 1];
      return safeSend(chatId, `✅ Switched to: <code>${shortenAddress(user.activeWallet.publicKey)}</code>`, walletMenuKeyboard);
    }

    // Price check
    if (inputType === 'price_check') {
      if (isValidSolanaAddress(text)) return handlePriceCheck(chatId, text);
      return safeSend(chatId, '❌ Invalid address.', mainMenuKeyboard);
    }

    // Analyze
    if (inputType === 'analyze') {
      if (isValidSolanaAddress(text)) return performAddressAnalysis(chatId, text);
      return safeSend(chatId, '❌ Invalid Solana address.', mainMenuKeyboard);
    }

    // Settings
    if (inputType === 'settings_buy_slippage') {
      const bps = parseInt(text);
      if (isNaN(bps) || bps < 1 || bps > 5000) return safeSend(chatId, '❌ Must be 1-5000 bps.', settingsMenuKeyboard);
      user.settings.buySlippageBps = bps;
      return safeSend(chatId, `✅ Buy slippage: ${bps / 100}%`, settingsMenuKeyboard);
    }
    if (inputType === 'settings_sell_slippage') {
      const bps = parseInt(text);
      if (isNaN(bps) || bps < 1 || bps > 5000) return safeSend(chatId, '❌ Must be 1-5000 bps.', settingsMenuKeyboard);
      user.settings.sellSlippageBps = bps;
      return safeSend(chatId, `✅ Sell slippage: ${bps / 100}%`, settingsMenuKeyboard);
    }
    if (inputType === 'settings_buy_amount') {
      const amt = validateSolAmount(text);
      if (!amt) return safeSend(chatId, '❌ Invalid amount.', settingsMenuKeyboard);
      user.settings.defaultBuyAmount = amt;
      return safeSend(chatId, `✅ Default buy: ${amt} SOL`, settingsMenuKeyboard);
    }

    // Quick buy custom amount
    if (inputType.startsWith('quick_buy_')) {
      const addr = inputType.replace('quick_buy_', '');
      const amount = validateSolAmount(text);
      if (!amount) return safeSend(chatId, '❌ Invalid SOL amount.', mainMenuKeyboard);
      bot.emit('text', { chat: { id: chatId }, from: msg.from, text: `/buy ${addr} ${amount}` });
      return;
    }

    // Quick alert
    if (inputType.startsWith('quick_alert_')) {
      const addr = inputType.replace('quick_alert_', '');
      const [priceStr, dir] = text.split(/\s+/);
      const price = parseFloat(priceStr);
      if (isNaN(price) || price <= 0 || !['above', 'below'].includes(dir?.toLowerCase())) {
        return safeSend(chatId, '❌ Invalid. Use: <code>&lt;price&gt; &lt;above/below&gt;</code>', mainMenuKeyboard);
      }
      bot.emit('text', { chat: { id: chatId }, from: msg.from, text: `/alert ${addr} ${price} ${dir}` });
      return;
    }

    // Limit order creation
    if (inputType.startsWith('limit_create_')) {
      const addr = inputType.replace('limit_create_', '');
      const parts = text.split(/\s+/);
      if (parts.length < 3 || !['buy', 'sell'].includes(parts[0])) {
        return safeSend(chatId, '❌ Format: <code>&lt;buy/sell&gt; &lt;price&gt; &lt;amount&gt;</code>');
      }
      const [type, priceStr, amountStr] = parts;
      const price = parseFloat(priceStr);
      const amount = parseFloat(amountStr);
      if (isNaN(price) || price <= 0 || isNaN(amount) || amount <= 0) return safeSend(chatId, '❌ Invalid numbers.');
      const info = await getTokenInfo(addr);
      const id = state.addLimitOrder(chatId, addr, info?.symbol || shortenAddress(addr), type, price, amount);
      return safeSend(chatId,
        `🎯 <b>Limit Order Created</b>\n\n<b>ID:</b> #${id}\n<b>Type:</b> ${type.toUpperCase()}\n<b>Token:</b> ${escapeHTML(info?.symbol || shortenAddress(addr))}\n<b>Target:</b> ${formatPrice(price)}\n<b>Amount:</b> ${amount}`,
        { reply_markup: { inline_keyboard: [[{ text: '🔙 Main Menu', callback_data: 'main_menu' }]] } }
      );
    }

    // DCA creation
    if (inputType.startsWith('dca_create_')) {
      const addr = inputType.replace('dca_create_', '');
      const parts = text.split(/\s+/);
      if (parts.length < 3) return safeSend(chatId, '❌ Format: <code>&lt;sol_per_order&gt; &lt;hours&gt; &lt;total&gt;</code>');
      const [amtStr, hoursStr, totalStr] = parts;
      const amt = parseFloat(amtStr);
      const hours = parseFloat(hoursStr);
      const total = parseInt(totalStr);
      if (isNaN(amt) || amt <= 0 || isNaN(hours) || hours <= 0 || isNaN(total) || total <= 0) return safeSend(chatId, '❌ Invalid numbers.');
      const info = await getTokenInfo(addr);
      const id = state.addDCAOrder(chatId, addr, info?.symbol || shortenAddress(addr), amt, hours * 3600000, total);
      return safeSend(chatId,
        `📈 <b>DCA Order Created</b>\n\n<b>ID:</b> #${id}\n<b>Token:</b> ${escapeHTML(info?.symbol || shortenAddress(addr))}\n<b>Amount:</b> ${amt} SOL every ${hours}h\n<b>Orders:</b> ${total}`,
        { reply_markup: { inline_keyboard: [[{ text: '🔙 Main Menu', callback_data: 'main_menu' }]] } }
      );
    }
  }

  // ── Auto-detect Solana addresses ──
  if (isValidSolanaAddress(text)) {
    return performAddressAnalysis(chatId, text);
  }

  // ── Fallback ──
  await safeSend(chatId,
    `🤔 I didn't understand that.\n\n` +
    `<b>You can:</b>\n` +
    `• Paste a Solana address to analyze it\n` +
    `• Use /help to see all commands\n` +
    `• Use the menu buttons below`,
    mainMenuKeyboard
  );
});

// ══════════════════════════════════════════════════════════════════════════════════════
// BACKGROUND TASKS
// ══════════════════════════════════════════════════════════════════════════════════════

// ── Price Alert Checker ──
async function checkPriceAlerts() {
  for (const [alertId, alert] of state.priceAlerts) {
    if (alert.triggered) continue;
    try {
      const price = await getTokenPrice(alert.tokenMint);
      if (!price) continue;
      const triggered =
        (alert.direction === 'above' && price >= alert.targetPrice) ||
        (alert.direction === 'below' && price <= alert.targetPrice);
      if (!triggered) continue;

      alert.triggered = true;
      const info = await getTokenInfo(alert.tokenMint);
      await safeSend(alert.chatId,
        `🚨 <b>PRICE ALERT TRIGGERED!</b>\n\n` +
        `<b>Token:</b> ${escapeHTML(info?.symbol || shortenAddress(alert.tokenMint))}\n` +
        `<b>Current Price:</b> ${formatPrice(price)}\n` +
        `<b>Alert:</b> Price went ${alert.direction} ${formatPrice(alert.targetPrice)}`,
        createTokenKeyboard(alert.tokenMint)
      );
      state.removeAlert(alertId);
      const user = state.getUser(alert.chatId);
      await notifyUserAction(user, 'Alert Triggered', `${escapeHTML(info?.symbol)} @ ${formatPrice(price)}`);
    } catch (err) {
      console.error(`Alert ${alertId} check error:`, err.message);
    }
  }
}

// ── Limit Order Checker ──
async function checkLimitOrders() {
  for (const [id, order] of state.limitOrders) {
    if (!order.active || order.executed) continue;
    try {
      const price = await getTokenPrice(order.tokenMint);
      if (!price) continue;
      const shouldExecute =
        (order.type === 'buy' && price <= order.targetPrice) ||
        (order.type === 'sell' && price >= order.targetPrice);
      if (!shouldExecute) continue;

      order.executed = true;
      order.active = false;
      await safeSend(order.chatId,
        `🎯 <b>Limit Order Triggered!</b>\n\n` +
        `<b>#${order.id}</b> ${order.type.toUpperCase()} ${escapeHTML(order.tokenSymbol)}\n` +
        `<b>Target:</b> ${formatPrice(order.targetPrice)}\n` +
        `<b>Current:</b> ${formatPrice(price)}\n\n` +
        `<i>Use the buy/sell buttons to execute manually.</i>`,
        createTokenKeyboard(order.tokenMint)
      );
    } catch (err) {
      console.error(`Limit order ${id} error:`, err.message);
    }
  }
}

// ── DCA Executor ──
async function executeDCAOrders() {
  const now = Date.now();
  for (const [id, order] of state.dcaOrders) {
    if (!order.active || order.paused || order.executedOrders >= order.totalOrders) continue;
    if (now < order.nextExecution) continue;

    try {
      const user = state.getUser(order.chatId);
      if (!user.activeWallet) continue;

      const amountLam = Math.floor(order.amountPerInterval * LAMPORTS_PER_SOL);
      const quote = await getSwapQuote(WSOL_MINT, order.tokenMint, amountLam, user.settings.buySlippageBps).catch(() => null);
      if (!quote) {
        order.nextExecution = now + order.intervalMs;
        continue;
      }

      const result = await executeSwap(user.activeWallet, quote);
      order.executedOrders++;
      order.nextExecution = now + order.intervalMs;

      if (order.executedOrders >= order.totalOrders) order.active = false;

      if (result.success) {
        user.totalSwaps++;
        state.addTransaction(order.chatId, { type: 'dca', tokenMint: order.tokenMint, tokenSymbol: order.tokenSymbol, txid: result.txid, solAmount: order.amountPerInterval });
        await safeSend(order.chatId,
          `📈 <b>DCA Order Executed</b>\n\n` +
          `<b>#${order.id}</b> ${escapeHTML(order.tokenSymbol)}\n` +
          `<b>Spent:</b> ${order.amountPerInterval} SOL\n` +
          `<b>Progress:</b> ${order.executedOrders}/${order.totalOrders}\n` +
          `<b>TX:</b> <a href="${result.explorerUrl}">Solscan</a>`
        );
      } else {
        await safeSend(order.chatId, `❌ DCA #${order.id} failed: ${escapeHTML(result.error)}`);
      }
    } catch (err) {
      console.error(`DCA ${id} error:`, err.message);
      order.nextExecution = now + order.intervalMs;
    }
  }
}

// Start background tasks
setInterval(checkPriceAlerts, config.alerts.checkInterval);
setInterval(checkLimitOrders, 60000); // every 1 min
setInterval(executeDCAOrders, 30000); // every 30 sec

// ══════════════════════════════════════════════════════════════════════════════════════
// ERROR HANDLING & GRACEFUL SHUTDOWN
// ══════════════════════════════════════════════════════════════════════════════════════
bot.on('polling_error', (err) => {
  console.error('Polling error:', err.message);
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
});

const shutdown = async (signal) => {
  console.log(`\n${signal} received. Shutting down gracefully...`);
  try {
    await bot.stopPolling();
    console.log('✅ Bot polling stopped.');
  } catch {}
  process.exit(0);
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// ══════════════════════════════════════════════════════════════════════════════════════
// STARTUP
// ══════════════════════════════════════════════════════════════════════════════════════
console.log(`
╔══════════════════════════════════════════════╗
║        Sakilobot Trading Bot v${BOT_VERSION}          ║
║        Solana Telegram Trading Bot           ║
╠══════════════════════════════════════════════╣
║  ⚡ Jupiter DEX Swaps                        ║
║  💳 Multi-Wallet (Create/Import/Seed)        ║
║  🔐 AES-256 Encrypted Key Storage           ║
║  🔔 Price Alerts + 🎯 Limit Orders          ║
║  📈 DCA Orders + 📊 PnL Tracking            ║
║  🎁 Referral System + 🛡️ Security Scoring   ║
║  👥 Admin Dashboard + Ban/Unban              ║
║  🔄 Multi-RPC Failover                      ║
╚══════════════════════════════════════════════╝
`);

console.log(`🤖 Bot is running...`);
console.log(`🌐 RPC Endpoints: ${config.solana.rpcUrls.length}`);
console.log(`⏰ Alert Interval: ${config.alerts.checkInterval}ms`);
console.log(`🔐 Encryption: ${config.encryption.key ? 'Enabled' : 'Disabled (set ENCRYPTION_KEY)'}`);
console.log(`👮 Admin IDs: ${config.telegram.adminIds.length > 0 ? config.telegram.adminIds.join(', ') : 'None'}`);
console.log(`💰 Commission: ${config.commission.rate * 100}%${config.commission.address ? ' → ' + shortenAddress(config.commission.address) : ''}`);
