/**
 * SMVS Browser — cloud backend + admin dashboard (SINGLE FILE).
 *
 * Everything lives here on purpose: the whole server is three files at the
 * repository root, so deploying needs no folder structure and no build step.
 *
 *   npm install && npm start
 *
 * Environment variables (set these on your host):
 *   ADMIN_PASSWORD  dashboard password   (default: admin123 — change it!)
 *   ADMIN_USERNAME  dashboard username   (default: admin)
 *   JWT_SECRET      long random string
 *   DATA_DIR        writable folder for db.json
 */
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const https = require('https');
const http = require('http');
const zlib = require('zlib');
const dns = require('dns');

// ===================================================================
// SECTION 1 — storage
// ===================================================================
/**
 * Storage with two back-ends, chosen automatically at startup.
 *
 * ### Why this exists
 * The first version stored everything in `data/db.json`. That works locally,
 * but free hosts (Render, Railway, Fly) give every deploy a brand-new, empty
 * filesystem and wipe the old one. The symptom an administrator sees is
 * exactly this: create a user or a role, sign out, sign back in — and the
 * account is gone, with only the seeded demo profiles left. Nothing was
 * broken in the dashboard; the disk simply no longer existed.
 *
 * ### The fix
 *   DATABASE_URL set  ->  PostgreSQL (Neon, Supabase, Render PG, anything)
 *   DATABASE_URL unset ->  the original JSON file, byte-for-byte as before
 *
 * The rest of the server is untouched: it still calls `db()`, `save()` and
 * `flush()` and still works on one in-memory object. Postgres holds that
 * object in a single-row JSONB document, so there are no migrations to run
 * and no schema to keep in sync with the code — the record shape can keep
 * evolving exactly as it did with the file.
 *
 * Writes are debounced (50 ms) and, for Postgres, serialised through a
 * promise chain so two overlapping requests can never interleave and lose an
 * update. On boot, if the Postgres document is empty but a db.json exists,
 * the file is imported once so nobody loses data by switching.
 */

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const DATABASE_URL = (process.env.DATABASE_URL || '').trim();
const USE_PG = DATABASE_URL.length > 0;

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DEFAULT_DB = {
  admins: [],       // dashboard logins
  users: [],        // browser profiles (Qustodio "profiles")
  activity: [],     // blocked / alerted visits reported by devices
  devices: [],      // which phone last synced which user
  appVersion: null, // latest published build for the LIVE channel
  /*
    The BETA channel's published build.

    Kept as a second record rather than a `channel` field inside one record
    because the two must be able to disagree: that is the whole point of a
    beta. `appVersion` keeps its old name and old meaning so that every
    device already in the field, and every saved database, carries on working
    without a migration.
  */
  appVersionBeta: null,

  /*
    The BETA deployment this dashboard also publishes to.

    The beta app does not merely run a different build — it talks to a
    different server, with its own database. Writing a "beta" record into
    THIS database therefore reached nobody: beta devices never ask this
    server anything. So the record has to be carried across, and that needs
    somewhere to keep the address and the credentials to get in.

    { url, username, password, lastOk, lastPublishAt, lastError }
  */
  betaPeer: null,

  /*
    The address every device should be talking to.

    Set here, it travels down with the next policy the devices fetch, and
    they adopt it. That is how the organisation moves to a new host without
    reinstalling anything — and why a device must not be able to change its
    own address.
  */
  managedServerUrl: '',

  /*
    Browsing history reported by devices, for the administrator's emailed
    report. Capped and pruned — see recordHistory().

    { id, userId, deviceId, deviceName, url, title, at, seconds }
  */
  history: [],

  /* SMTP credentials for sending those reports. { host, port, secure, user, pass, from } */
  mail: null,

  /*
    Who gets a report, how often, and for which devices.
    { id, email, everyDays, devices: [] (empty = all), enabled, lastSentAt, createdAt, label }
  */
  reports: [],
  roles: []         // custom roles created by the administrator
};

let cache = null;
let pgPool = null;

/** Where the data actually lives — shown on the dashboard and /api/health. */
function storageKind() {
  return USE_PG ? 'postgres' : 'file';
}

// ---------------------------------------------------------------- Postgres

/**
 * Opens the pool and makes sure the table exists.
 *
 * Neon and Supabase both require TLS but present a certificate chain Node does
 * not ship a root for, hence `rejectUnauthorized: false` — the connection is
 * still encrypted. A plain local `postgres://localhost/...` gets no TLS at all.
 */
async function pgInit() {
  const { Pool } = require('pg');
  const local = /localhost|127\.0\.0\.1/.test(DATABASE_URL);
  pgPool = new Pool({
    connectionString: DATABASE_URL,
    ssl: local ? false : { rejectUnauthorized: false },
    max: 4,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 15000
  });

  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS smvs_state (
      id   INTEGER PRIMARY KEY DEFAULT 1,
      data JSONB   NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT smvs_state_single_row CHECK (id = 1)
    )
  `);

  const { rows } = await pgPool.query('SELECT data FROM smvs_state WHERE id = 1');

  if (rows.length && rows[0].data) {
    cache = { ...DEFAULT_DB, ...rows[0].data };
    console.log(`[db] postgres loaded — ${cache.users.length} user(s), ${cache.roles.length} role(s)`);
    return;
  }

  // First run against this database. Import an existing db.json if there is
  // one so a server that used to run on the file back-end keeps its data.
  let initial = { ...DEFAULT_DB };
  if (fs.existsSync(DB_FILE)) {
    try {
      initial = { ...DEFAULT_DB, ...JSON.parse(fs.readFileSync(DB_FILE, 'utf8')) };
      console.log(`[db] imported existing db.json into postgres (${initial.users.length} user(s))`);
    } catch (e) {
      console.error('[db] db.json unreadable, starting empty:', e.message);
    }
  }
  cache = initial;
  await pgPool.query(
    'INSERT INTO smvs_state (id, data) VALUES (1, $1) ON CONFLICT (id) DO NOTHING',
    [JSON.stringify(cache)]
  );
  console.log('[db] postgres initialised');
}

// Serialises writes: each write waits for the previous one to finish, so two
// requests in the same tick cannot race and clobber each other.
let pgChain = Promise.resolve();
let pgPending = false;

function pgWrite() {
  pgChain = pgChain.then(async () => {
    try {
      await pgPool.query(
        `INSERT INTO smvs_state (id, data, updated_at) VALUES (1, $1, NOW())
         ON CONFLICT (id) DO UPDATE SET data = $1, updated_at = NOW()`,
        [JSON.stringify(cache)]
      );
    } catch (e) {
      console.error('[db] postgres write failed:', e.message);
    }
  });
  return pgChain;
}

// ---------------------------------------------------------------- public API

/**
 * Returns the in-memory state. Synchronous on purpose: every route already
 * assumes it, and the whole dataset is loaded once at startup.
 */
function load() {
  if (cache) return cache;
  ensureDir();
  if (fs.existsSync(DB_FILE)) {
    try {
      cache = { ...DEFAULT_DB, ...JSON.parse(fs.readFileSync(DB_FILE, 'utf8')) };
    } catch (e) {
      console.error('[db] corrupt db.json, starting fresh:', e.message);
      cache = { ...DEFAULT_DB };
    }
  } else {
    cache = { ...DEFAULT_DB };
  }
  return cache;
}

let writeTimer = null;

/** Persist soon. Debounced so one request causes at most one write. */
function save() {
  if (USE_PG) {
    if (pgPending) return;
    pgPending = true;
    setTimeout(() => { pgPending = false; pgWrite(); }, 50);
    return;
  }
  ensureDir();
  clearTimeout(writeTimer);
  writeTimer = setTimeout(() => {
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(cache, null, 2));
    } catch (e) {
      console.error('[db] write failed:', e.message);
    }
  }, 50);
}

/** Persist right now. Returns a promise on Postgres, undefined on file. */
function flush() {
  if (USE_PG) return pgWrite();
  clearTimeout(writeTimer);
  ensureDir();
  fs.writeFileSync(DB_FILE, JSON.stringify(cache, null, 2));
}


// ===================================================================
// SECTION 2 — content categories (must match the Android app)
// ===================================================================
/**
 * Category list — MUST stay in sync with the Android app's ContentCategory.kt.
 * The `id` strings are the contract between server and device.
 */
const CATEGORIES = [
  // Sensitive
  { id: 'pornography', label: 'Pornography', group: 'Sensitive Content', def: 'block' },
  { id: 'mature_content', label: 'Mature Content', group: 'Sensitive Content', def: 'block' },
  { id: 'violence', label: 'Violence', group: 'Sensitive Content', def: 'block' },
  { id: 'drugs', label: 'Drugs', group: 'Sensitive Content', def: 'block' },
  { id: 'alcohol_tobacco', label: 'Alcohol & Tobacco', group: 'Sensitive Content', def: 'block' },
  { id: 'gambling', label: 'Gambling', group: 'Sensitive Content', def: 'block' },
  { id: 'weapons', label: 'Weapons', group: 'Sensitive Content', def: 'block' },
  { id: 'hate', label: 'Hate & Intolerance', group: 'Sensitive Content', def: 'block' },
  { id: 'self_harm', label: 'Self-Harm', group: 'Sensitive Content', def: 'block' },
  { id: 'profanity', label: 'Profanity', group: 'Sensitive Content', def: 'block' },
  { id: 'dating', label: 'Dating', group: 'Sensitive Content', def: 'block' },
  // Social
  { id: 'social_networks', label: 'Social Networks', group: 'Social & Communication', def: 'block' },
  { id: 'chat_messaging', label: 'Chat & Messaging', group: 'Social & Communication', def: 'block' },
  { id: 'webmail', label: 'Web Mail', group: 'Social & Communication', def: 'alert' },
  { id: 'forums_blogs', label: 'Forums & Blogs', group: 'Social & Communication', def: 'alert' },
  { id: 'photo_video', label: 'Photo & Video Sharing', group: 'Social & Communication', def: 'alert' },
  // Leisure
  { id: 'entertainment', label: 'Entertainment', group: 'Leisure & Entertainment', def: 'alert' },
  { id: 'streaming', label: 'Streaming Media', group: 'Leisure & Entertainment', def: 'alert' },
  { id: 'games', label: 'Games', group: 'Leisure & Entertainment', def: 'block' },
  { id: 'sports', label: 'Sports', group: 'Leisure & Entertainment', def: 'allow' },
  { id: 'shopping', label: 'Shopping', group: 'Leisure & Entertainment', def: 'alert' },
  { id: 'travel', label: 'Travel', group: 'Leisure & Entertainment', def: 'allow' },
  // Productivity
  { id: 'education', label: 'Education', group: 'Productivity & Reference', def: 'allow' },
  { id: 'government', label: 'Government', group: 'Productivity & Reference', def: 'allow' },
  { id: 'news', label: 'News', group: 'Productivity & Reference', def: 'allow' },
  { id: 'health', label: 'Health & Medicine', group: 'Productivity & Reference', def: 'allow' },
  { id: 'business_finance', label: 'Business & Finance', group: 'Productivity & Reference', def: 'allow' },
  { id: 'job_search', label: 'Jobs & Careers', group: 'Productivity & Reference', def: 'allow' },
  { id: 'religion', label: 'Religion', group: 'Productivity & Reference', def: 'allow' },
  { id: 'reference', label: 'Reference', group: 'Productivity & Reference', def: 'allow' },
  // Technology
  { id: 'ai_tools', label: 'AI Tools', group: 'Technology', def: 'alert' },
  { id: 'technology', label: 'Technology', group: 'Technology', def: 'allow' },
  { id: 'search_engines', label: 'Search Engines', group: 'Technology', def: 'allow' },
  { id: 'file_sharing', label: 'File Sharing', group: 'Technology', def: 'block' },
  { id: 'proxies', label: 'Proxies & VPN', group: 'Technology', def: 'block' },
  { id: 'advertising', label: 'Advertising & Trackers', group: 'Technology', def: 'allow' },
  // Other
  // Default is BLOCK on purpose: an unknown site that only raises an alert
  // still loads, which lets any brand-new site bypass a restricted profile.
  { id: 'uncategorized', label: 'Unknown / Uncategorised', group: 'Other', def: 'block' }
];

const ROLE_TEMPLATES = {
  student: {
    allow: ['education', 'reference', 'government', 'search_engines', 'news',
            'health', 'technology', 'sports', 'religion'],
    // NOTE: 'uncategorized' is deliberately NOT in this list. An unknown site
    // that merely raises an alert still loads, so a restricted profile could
    // reach any brand-new site the classifier has not seen. Falling through to
    // `blockRest` means unknown = blocked for students.
    alert: ['ai_tools', 'webmail', 'entertainment', 'shopping'],
    homeUrl: 'https://www.wikipedia.org/'
  },
  staff: {
    allow: ['education', 'reference', 'government', 'search_engines', 'news',
            'health', 'technology', 'business_finance', 'job_search', 'webmail',
            'ai_tools', 'sports', 'travel', 'religion', 'forums_blogs', 'photo_video'],
    alert: ['shopping', 'entertainment', 'streaming', 'social_networks',
            'chat_messaging', 'file_sharing', 'uncategorized'],
    homeUrl: 'https://www.google.com/'
  },
  admin: {
    allowAllExcept: ['pornography', 'self_harm', 'hate'],
    homeUrl: 'https://www.google.com/'
  },
  guest: {
    // Strictest profile: anything not named here, including unknown sites,
    // is blocked.
    allow: ['reference', 'education', 'government', 'search_engines'],
    blockRest: true,
    homeUrl: 'https://www.wikipedia.org/'
  }
};

/** Builds a full categoryRules map for a role. */
/**
 * The four roles every installation starts with.
 *
 * They are seeded into the database as ordinary records, so an administrator
 * can rename them, change their rules, or ignore them entirely and build their
 * own. `builtIn` only prevents deletion — everything else is editable.
 */
function builtInRoles() {
  return ['admin', 'staff', 'student', 'guest'].map(id => {
    const t = templateFor(id);
    return {
      id,
      label: id.charAt(0).toUpperCase() + id.slice(1),
      description: {
        admin: 'Full access, can manage users from the dashboard',
        staff: 'Work and research sites, most leisure content is watched',
        student: 'Education and reference only',
        guest: 'Reference sites only'
      }[id] || '',
      builtIn: true,
      categoryRules: completeCategoryRules(t.rules, t.rules),
      uncategorizedAction: t.rules.uncategorized || 'alert',
      features: defaultFeatures(),
      homeUrl: t.homeUrl,
      createdAt: Date.now()
    };
  });
}

/** Looks up a role record by id. Returns null when unknown. */
function findRole(id) {
  return db().roles.find(r => r.id === String(id)) || null;
}

/**
 * Rules to apply to a newly created user of this role.
 * Falls back to the legacy template when the role has no record yet.
 */
function rulesForRole(id) {
  const role = findRole(id);
  if (role) {
    return {
      rules: role.categoryRules || {},
      homeUrl: role.homeUrl || 'https://www.wikipedia.org/',
      features: { ...defaultFeatures(), ...(role.features || {}) },
      uncategorizedAction: role.uncategorizedAction || 'alert'
    };
  }
  const t = templateFor(id);
  return {
    rules: t.rules, homeUrl: t.homeUrl,
    features: defaultFeatures(),
    uncategorizedAction: t.rules.uncategorized || 'alert'
  };
}

/** A role id must be safe to use as an object key and in a URL. */
function normaliseRoleId(raw) {
  return String(raw || '')
    .toLowerCase().trim()
    .replace(/[^a-z0-9_-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 40);
}

function templateFor(role) {
  const t = ROLE_TEMPLATES[role] || ROLE_TEMPLATES.student;
  const rules = {};

  for (const c of CATEGORIES) {
    if (t.allowAllExcept) {
      rules[c.id] = t.allowAllExcept.includes(c.id) ? 'block' : 'allow';
    } else if (t.allow && t.allow.includes(c.id)) {
      rules[c.id] = 'allow';
    } else if (t.alert && t.alert.includes(c.id)) {
      rules[c.id] = 'alert';
    } else if (t.blockRest) {
      rules[c.id] = 'block';
    } else {
      rules[c.id] = c.def === 'allow' ? 'allow' : c.def === 'alert' ? 'alert' : 'block';
    }
  }
  return { rules, homeUrl: t.homeUrl };
}


// ===================================================================
// SECTION 3 — time-window rules
// ===================================================================
/**
 * Time-window rules — "allow this site only between 16:00 and 18:00 on weekdays".
 *
 * A rule looks like:
 * {
 *   id: "tr_123",
 *   pattern: "youtube.com",     // same syntax as the allow/block lists
 *   days: [1,2,3,4,5],          // 0=Sunday .. 6=Saturday
 *   startMinute: 960,           // 16:00  (minutes since midnight, local time)
 *   endMinute: 1080,            // 18:00
 *   enabled: true
 * }
 *
 * Semantics (kept deliberately simple and predictable):
 *   - INSIDE the window  -> the site is ALLOWED, overriding category rules.
 *   - OUTSIDE the window -> the site is BLOCKED, even if its category is allowed.
 *
 * So a time rule is a complete statement about that site: "only at these times,
 * never otherwise". That is what "particular time purti j access" means, and it
 * avoids the ambiguity of a rule that only half-applies.
 *
 * Evaluation happens ON THE DEVICE using the device clock, so it keeps working
 * with no network. The server only stores and distributes the rules.
 */

function minutesToLabel(m) {
  const h = Math.floor(m / 60);
  const min = m % 60;
  const ampm = h < 12 ? 'AM' : 'PM';
  const h12 = h % 12 === 0 ? 12 : h % 12;
  return `${h12}:${String(min).padStart(2, '0')} ${ampm}`;
}

const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

function describe(rule) {
  const days = (rule.days || []).length === 7
    ? 'Every day'
    : (rule.days || []).map(d => DAY_NAMES[d]).join(', ');
  return `${days} · ${minutesToLabel(rule.startMinute)} – ${minutesToLabel(rule.endMinute)}`;
}

function validate(rule) {
  const errors = [];
  if (!rule.pattern || !String(rule.pattern).trim()) {
    errors.push('Website is required');
  }
  const s = Number(rule.startMinute);
  const e = Number(rule.endMinute);
  if (!Number.isInteger(s) || s < 0 || s > 1439) errors.push('Invalid start time');
  if (!Number.isInteger(e) || e < 0 || e > 1440) errors.push('Invalid end time');
  if (Number.isInteger(s) && Number.isInteger(e) && e <= s) {
    errors.push('End time must be after start time');
  }
  if (!Array.isArray(rule.days) || rule.days.length === 0) {
    errors.push('Pick at least one day');
  }
  return errors;
}

function normalise(rule) {
  return {
    id: rule.id || `tr_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    pattern: String(rule.pattern).trim().toLowerCase(),
    days: (rule.days || []).map(Number).filter(d => d >= 0 && d <= 6).sort(),
    startMinute: Number(rule.startMinute),
    endMinute: Number(rule.endMinute),
    enabled: rule.enabled !== false
  };
}

const scheduleUtil = { describe, validate, normalise, minutesToLabel, DAY_NAMES };


// ===================================================================
// SECTION 4 — admin dashboard (served from memory)
// ===================================================================
const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SMVS Browser — Admin Dashboard</title>
<style>
  :root{
    --primary:#1B4965; --primary-dark:#123449; --accent:#5FA8D3;
    --bg:#F1F4F8; --card:#fff; --text:#1A1C1E; --muted:#5F6B7A;
    --border:#D8E0E8; --danger:#B3261E; --warn:#B8860B; --ok:#1B7F4B;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       background:var(--bg);color:var(--text)}
  header{background:var(--primary);color:#fff;padding:14px 20px;display:flex;
         align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
  header h1{margin:0;font-size:18px}
  .wrap{max-width:1150px;margin:0 auto;padding:18px}
  .card{background:var(--card);border-radius:12px;padding:18px;margin-bottom:16px;
        box-shadow:0 1px 3px rgba(0,0,0,.08)}
  button{font:inherit;cursor:pointer;border-radius:8px;border:1px solid var(--border);
         background:#fff;padding:9px 14px}
  button.primary{background:var(--primary);color:#fff;border-color:var(--primary)}
  button.danger{background:var(--danger);color:#fff;border-color:var(--danger)}
  button:hover{filter:brightness(.96)}
  input,select{font:inherit;padding:9px 11px;border:1px solid var(--border);
               border-radius:8px;width:100%;background:#fff}
  label{display:block;font-size:12px;color:var(--muted);margin:10px 0 4px;font-weight:600}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .row>div{flex:1;min-width:190px}
  .stats{display:flex;gap:14px;flex-wrap:wrap}
  .stat{flex:1;min-width:120px;text-align:center;padding:14px;background:var(--bg);border-radius:10px}
  .stat b{display:block;font-size:28px;color:var(--primary)}
  .stat span{font-size:12px;color:var(--muted)}
  table{width:100%;border-collapse:collapse}
  th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--border);font-size:14px}
  th{font-size:11px;text-transform:uppercase;color:var(--muted);letter-spacing:.04em}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;
         font-weight:700;color:#fff}
  .b-ok{background:var(--ok)} .b-off{background:var(--danger)}
  .b-alert{background:var(--warn)} .b-neutral{background:var(--muted)}
  .hidden{display:none!important}
  .modal{position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;
         align-items:flex-start;justify-content:center;padding:20px;overflow:auto;z-index:50}
  .modal .card{max-width:780px;width:100%;margin:20px 0}
  .cat-group{margin-top:16px}
  .cat-group h4{margin:0 0 8px;font-size:12px;color:var(--primary);
                text-transform:uppercase;letter-spacing:.04em}
  .cat{display:flex;align-items:center;justify-content:space-between;gap:10px;
       padding:8px 10px;border:1px solid var(--border);border-radius:8px;margin-bottom:6px}
  .cat-name{font-size:13px;font-weight:600}
  .seg{display:flex;border:1px solid var(--border);border-radius:7px;overflow:hidden;flex-shrink:0}
  .seg button{border:0;border-radius:0;padding:6px 12px;font-size:11px;background:#fff}
  .seg button.on-allow{background:var(--ok);color:#fff}
  .seg button.on-alert{background:var(--warn);color:#fff}
  .seg button.on-block{background:var(--danger);color:#fff}
  .tabs{display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap}
  .tabs button{border-radius:20px;font-size:13px}
  .tabs button.active{background:var(--primary);color:#fff;border-color:var(--primary)}
  .muted{color:var(--muted);font-size:12px}
  .time-rule{border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:10px;
             background:var(--bg)}
  .days{display:flex;gap:5px;flex-wrap:wrap;margin-top:6px}
  .days button{padding:5px 10px;font-size:11px;border-radius:6px}
  .days button.on{background:var(--primary);color:#fff;border-color:var(--primary)}
  .banner{background:#FFF3CD;color:#6B5500;padding:10px 14px;border-radius:8px;
          font-size:13px;margin-bottom:14px}
  textarea{font:13px monospace;padding:9px;border:1px solid var(--border);
           border-radius:8px;width:100%;min-height:80px}
  .toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);
         background:var(--primary);color:#fff;padding:12px 22px;border-radius:8px;
         z-index:99;box-shadow:0 3px 12px rgba(0,0,0,.25)}

  /* ===== redesigned rules editor ===== */
  .modal .card{max-width:920px;padding:0;overflow:hidden}
  .sheet-head{position:sticky;top:0;z-index:5;background:var(--primary);color:#fff;
              padding:18px 24px;display:flex;align-items:center;justify-content:space-between}
  .sheet-head h3{margin:0;font-size:18px;color:#fff}
  .sheet-head .close{background:rgba(255,255,255,.15);border:0;color:#fff;
                     width:32px;height:32px;border-radius:8px;font-size:18px;line-height:1}
  .sheet-body{padding:22px 24px;max-height:calc(100vh - 230px);overflow-y:auto}
  .sheet-foot{position:sticky;bottom:0;background:#fff;border-top:1px solid var(--border);
              padding:14px 24px;display:flex;gap:10px;justify-content:flex-end}

  .steps{display:flex;gap:6px;margin:0 0 20px;border-bottom:1px solid var(--border)}
  .steps button{border:0;border-radius:0;background:none;padding:11px 16px;
                font-size:13px;color:var(--muted);border-bottom:2px solid transparent}
  .steps button.on{color:var(--primary);border-bottom-color:var(--primary);font-weight:600}
  .step-panel{display:none}
  .step-panel.on{display:block}

  .cat-toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;
               position:sticky;top:0;background:#fff;padding:10px 0;z-index:2;
               border-bottom:1px solid var(--border);margin-bottom:6px}
  .cat-search{flex:1;min-width:180px}
  .quick{display:flex;gap:6px}
  .quick button{font-size:11px;padding:7px 12px;border-radius:20px}
  .quick button.allow-all:hover{background:#E8F5EC;border-color:var(--ok);color:var(--ok)}
  .quick button.block-all:hover{background:#FDECEA;border-color:var(--danger);color:var(--danger)}

  .cat-group h4{display:flex;align-items:center;gap:8px;margin:18px 0 8px;
                font-size:11px;color:var(--primary);text-transform:uppercase;letter-spacing:.05em}
  .cat-group h4::after{content:'';flex:1;height:1px;background:var(--border)}

  .cat{display:flex;align-items:center;justify-content:space-between;gap:12px;
       padding:11px 14px;border:1px solid var(--border);border-radius:10px;margin-bottom:7px;
       transition:border-color .15s,box-shadow .15s;background:#fff}
  .cat:hover{border-color:#B9C6DA;box-shadow:0 1px 4px rgba(0,0,0,.05)}
  .cat.is-block{border-left:3px solid var(--danger)}
  .cat.is-alert{border-left:3px solid var(--warn)}
  .cat.is-allow{border-left:3px solid var(--ok)}
  .cat-info{min-width:0}
  .cat-name{font-size:13.5px;font-weight:600}
  .cat-desc{font-size:11.5px;color:var(--muted);margin-top:2px}

  .seg{display:flex;border:1px solid var(--border);border-radius:8px;overflow:hidden;flex-shrink:0}
  .seg button{border:0;border-radius:0;padding:7px 14px;font-size:11.5px;background:#fff;
              color:var(--muted);font-weight:600;transition:background .12s}
  .seg button:hover{background:var(--bg)}
  .seg button.on-allow{background:var(--ok);color:#fff}
  .seg button.on-alert{background:var(--warn);color:#fff}
  .seg button.on-block{background:var(--danger);color:#fff}

  .summary-bar{display:flex;gap:8px;margin-bottom:4px}
  .pill{font-size:11px;padding:5px 11px;border-radius:20px;font-weight:600}
  .pill.a{background:#E8F5EC;color:var(--ok)}
  .pill.w{background:#FFF6E5;color:#8A6D00}
  .pill.b{background:#FDECEA;color:var(--danger)}

  .switch-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  .switch-card{display:flex;align-items:flex-start;gap:10px;padding:12px;
               border:1px solid var(--border);border-radius:10px}
  .switch-card input{width:auto;margin-top:2px}
  .switch-card b{font-size:13px;display:block}
  .switch-card span{font-size:11.5px;color:var(--muted)}

  .role-card{border:1px solid var(--border);border-radius:12px;padding:16px;
             display:flex;justify-content:space-between;align-items:flex-start;gap:14px;
             margin-bottom:10px;transition:box-shadow .15s}
  .role-card:hover{box-shadow:0 2px 10px rgba(0,0,0,.07)}
  .role-title{font-size:15px;font-weight:700;display:flex;align-items:center;gap:8px}
  .role-desc{font-size:12.5px;color:var(--muted);margin-top:3px}
  .role-meta{font-size:11.5px;color:var(--muted);margin-top:8px;display:flex;gap:10px;flex-wrap:wrap}
  .tag{font-size:10px;padding:2px 8px;border-radius:10px;background:var(--bg);color:var(--muted);
       font-weight:700;text-transform:uppercase;letter-spacing:.04em}
  .tag.built{background:#E8EEFB;color:var(--primary)}
</style>
</head>
<body>

<!-- ============ LOGIN ============ -->
<div id="loginView" class="wrap" style="max-width:400px;margin-top:8vh">
  <div class="card">
    <h2 style="margin-top:0;color:var(--primary)">SMVS Browser</h2>
    <p class="muted">Admin Dashboard — manage users and rules from anywhere.</p>
    <label>Username</label>
    <input id="admUser" value="admin" autocomplete="username">
    <label>Password</label>
    <input id="admPass" type="password" placeholder="admin123" autocomplete="current-password">
    <p id="loginErr" class="hidden" style="color:var(--danger);font-size:13px"></p>
    <button class="primary" style="width:100%;margin-top:14px" onclick="doLogin()">Sign In</button>
  </div>
</div>

<!-- ============ DASHBOARD ============ -->
<div id="appView" class="hidden">
  <header>
    <h1>SMVS Browser — Admin Dashboard</h1>
    <div>
      <span id="whoami" class="muted" style="color:#cfe3ef;margin-right:10px"></span>
      <button onclick="logout()">Sign Out</button>
    </div>
  </header>

  <div class="wrap">
    <div class="banner">
      Changes you save here reach the phone automatically — the app re-checks
      its rules every time the user opens or returns to it.
    </div>

    <div class="card">
      <div class="stats">
        <div class="stat"><b id="stTotal">0</b><span>Total Users</span></div>
        <div class="stat"><b id="stActive" style="color:var(--ok)">0</b><span>Active</span></div>
        <div class="stat"><b id="stDisabled" style="color:var(--danger)">0</b><span>Disabled</span></div>
        <div class="stat"><b id="stAlerts" style="color:var(--warn)">0</b><span>Alerts logged</span></div>
      </div>
    </div>

    <div id="storageWarn" class="hidden"
         style="background:#FDECEA;border:1px solid #F5C2BC;color:#8B1F17;
                padding:12px 16px;border-radius:10px;margin-bottom:14px;font-size:13.5px">
      <b>⚠ Data is not being saved permanently.</b>
      <div id="storageWarnText" style="margin-top:4px"></div>
    </div>

    <div class="tabs">
      <button id="tabUsersBtn" class="active" onclick="showTab('users')">Users</button>
      <button id="tabRolesBtn" onclick="showTab('roles')">Roles</button>
      <button id="tabActivityBtn" onclick="showTab('activity')">Activity Log</button>
      <button id="tabDevicesBtn" onclick="showTab('devices')">Devices</button>
      <button id="tabAdminsBtn" onclick="showTab('admins')">Administrators</button>
      <button id="tabUpdateBtn" onclick="showTab('update')">App Update</button>
      <button id="tabReportsBtn" onclick="showTab('reports')">History Reports</button>
      <button class="primary" style="margin-left:auto" onclick="openEditor(null)">+ Add User</button>
    </div>

    <div id="tabUsers" class="card">
      <table>
        <thead><tr>
          <th>User</th><th>Role</th><th>Rules</th><th>Time rules</th>
          <th>Login sync</th><th>Status</th><th>Last sync</th><th></th>
        </tr></thead>
        <tbody id="userRows"></tbody>
      </table>
      <p id="noUsers" class="muted hidden">No users yet — click "Add User".</p>
    </div>

    <div id="tabRoles" class="card hidden">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <div>
          <h3 style="margin:0;color:var(--primary)">Roles</h3>
          <p class="muted" style="margin:4px 0 0">
            A role is a reusable set of rules. Create your own to match how your
            organisation actually works.
          </p>
        </div>
        <button class="primary" onclick="openRoleEditor(null)">+ New Role</button>
      </div>
      <div id="roleList" style="margin-top:16px"></div>
    </div>

    <div id="tabUpdate" class="card hidden">
      <h3 style="margin-top:0;color:var(--primary)">App update</h3>

      <!-- ============ STEP 1 ============ -->
      <div style="background:var(--bg);border-radius:10px;padding:14px;margin-bottom:16px">
        <b>&#9312; &nbsp;Where every device connects</b>
        <p class="muted" style="margin:6px 0 10px">
          Change this and every phone and computer moves to the new address by
          itself, within a second. Nobody has to reinstall anything, and users
          cannot change it themselves.
        </p>
        <input id="srvUrl" placeholder="https://smvs-browser.onrender.com">
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px">
          <button class="primary" style="font-size:13px" onclick="saveServerUrl()">Save &amp; send to all devices</button>
        </div>
        <p id="srvStatus" class="muted" style="margin-top:10px"></p>
      </div>

      <!-- ============ STEP 2 ============ -->
      <div style="background:var(--bg);border-radius:10px;padding:14px;margin-bottom:16px">
        <b>&#9313; &nbsp;Publish a new version</b>
        <p class="muted" style="margin:6px 0 10px">
          Put the files on a GitHub Release first, then paste their links here.
          <b>Leave the version number empty</b> — it is read out of the APK
          itself, which is what stops the "update again and again" loop.
        </p>

        <label>Version name (what people see, e.g. 8.2)</label>
        <input id="uVersionName" placeholder="8.2">
        <input id="uVersionCode" type="hidden">

        <!-- ---- one click ---- -->
        <div style="background:var(--surface);border-radius:10px;padding:14px;margin-top:14px;
                    border:2px solid var(--primary)">
          <b>&#9889; The easy way &mdash; one button</b>
          <p class="muted" style="margin:6px 0 10px">
            Attach all four files to the same GitHub Release, publish to LIVE once,
            then press this. It finds the beta-built files on that release by
            itself, checks they really are the beta build, and publishes them.
            Nothing is guessed: if a file is missing it tells you which name it
            looked for.
          </p>
          <div style="display:flex;gap:10px;flex-wrap:wrap">
            <button class="primary" style="font-size:13px" onclick="promote('live','beta')">
              Publish LIVE &rarr; BETA
            </button>
            <button class="secondary" style="font-size:13px" onclick="promote('beta','live')">
              Publish BETA &rarr; LIVE
            </button>
          </div>
          <p id="promoteStatus" class="muted" style="margin-top:10px"></p>
        </div>

        <p class="muted" style="margin:16px 0 0"><b>Or paste the links by hand:</b></p>

        <div class="row" style="margin-top:8px">
          <!-- ---- live ---- -->
          <div style="background:var(--surface);border-radius:10px;padding:12px">
            <b>&#128994; For everyone (LIVE)</b>
            <label style="margin-top:8px">Android APK link</label>
            <input id="uApkUrl" placeholder=".../SMVS-Browser-v8.2.apk">
            <label style="margin-top:8px">Windows installer link</label>
            <input id="uDesktopUrl" placeholder=".../SMVS-Browser-Setup-3.9.0.exe">
            <label style="margin-top:8px">Windows version</label>
            <input id="uDesktopVersion" placeholder="3.9.0">
            <button class="primary" style="width:100%;margin-top:12px;font-size:13px"
                    onclick="publishTo('live')">Publish to LIVE</button>
          </div>

          <!-- ---- beta ---- -->
          <div style="background:var(--surface);border-radius:10px;padding:12px">
            <b>&#128309; For test devices (BETA)</b>
            <label style="margin-top:8px">Android APK link <span class="muted">(the BETA file)</span></label>
            <input id="bApkUrl" placeholder=".../SMVS-Browser-BETA-v8.2.apk">
            <label style="margin-top:8px">Windows installer link <span class="muted">(the Beta file)</span></label>
            <input id="bDesktopUrl" placeholder=".../SMVS-Browser-Beta-Setup-3.9.0.exe">
            <label style="margin-top:8px">Windows version</label>
            <input id="bDesktopVersion" placeholder="3.9.0">
            <button class="primary" style="width:100%;margin-top:12px;font-size:13px"
                    onclick="publishTo('beta')">Publish to BETA</button>
          </div>
        </div>

        <label style="margin-top:14px">What changed (optional)</label>
        <input id="uNotes" placeholder="Fixed the logo and the update loop">
        <label style="display:flex;align-items:center;gap:8px;margin-top:12px">
          <input type="checkbox" id="uMandatory" checked style="width:auto">
          <span style="color:var(--text);font-size:14px">
            Required &mdash; block browsing until it is installed
          </span>
        </label>
        <p id="updateErr" class="hidden" style="color:var(--danger);font-size:13px"></p>

        <div class="banner" style="margin-top:14px">
          <b>Why two sets of links?</b> The beta app is a different app as far as
          Android and Windows are concerned, so it needs its own file built from
          the same code. Handing beta the live file would look like it worked
          and update nobody. Nothing is ever sent from one channel to the other
          on its own &mdash; only when you press one of these buttons.
        </div>
      </div>

      <!-- ============ STEP 3 ============ -->
      <div style="background:var(--bg);border-radius:10px;padding:14px;margin-bottom:16px">
        <b>&#9314; &nbsp;What each channel is offering right now</b>
        <div class="row" style="margin-top:10px">
          <div style="background:var(--surface);border-radius:10px;padding:12px">
            <b>&#128994; Live</b>
            <div id="liveVersionText" class="muted" style="margin-top:6px">Nothing published yet.</div>
            <button class="danger" style="margin-top:10px;font-size:12px"
                    onclick="unpublishVersion('live')">Stop offering it</button>
          </div>
          <div style="background:var(--surface);border-radius:10px;padding:12px">
            <b>&#128309; Beta</b>
            <div id="betaVersionText" class="muted" style="margin-top:6px">Nothing published yet.</div>
            <button class="danger" style="margin-top:10px;font-size:12px"
                    onclick="unpublishVersion('beta')">Stop offering it</button>
          </div>
        </div>
      </div>

      <!-- ============ beta server, set once ============ -->
      <details style="background:var(--bg);border-radius:10px;padding:14px">
        <summary style="cursor:pointer;font-weight:600">
          Beta server connection &mdash; set once, then forget
        </summary>
        <p class="muted" style="margin:10px 0">
          The beta app talks to its own server with its own database. Give this
          dashboard the address and login once, and "Publish to BETA" reaches it.
          <br>Only the version and the links are sent &mdash; never users,
          bookmarks or history.
        </p>
        <div class="row">
          <div><label>Beta server address</label>
            <input id="peerUrl" placeholder="https://smvs-browser-beta.onrender.com"></div>
          <div><label>Beta dashboard username</label>
            <input id="peerUser" placeholder="admin"></div>
        </div>
        <label style="margin-top:10px">Beta dashboard password</label>
        <input id="peerPass" type="password" placeholder="leave blank to keep the saved one">
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px">
          <button class="primary" style="font-size:13px" onclick="savePeer()">Save</button>
          <button class="secondary" style="font-size:13px" onclick="testPeer()">Test connection</button>
          <button class="danger" style="font-size:13px" onclick="forgetPeer()">Forget</button>
        </div>
        <p id="peerStatus" class="muted" style="margin-top:10px">Not configured yet.</p>
      </details>
    </div>

    <div id="tabReports" class="card hidden">
      <h3 style="margin-top:0;color:var(--primary)">History reports by email</h3>
      <p class="muted">
        Devices send their browsing history here — including pages the user
        deleted from the browser, because that delete is only a soft delete.
        A schedule then emails it as a table: Serial No, Date, Device Name,
        URL, Time spent.
      </p>

      <div style="background:var(--bg);border-radius:10px;padding:14px;margin-bottom:14px">
        <b>&#9993; How the reports are emailed</b>
        <p class="muted" style="margin:6px 0 10px">
          <b>Render's free plan blocks SMTP</b> (ports 25, 465 and 587), so Gmail
          and the like cannot work from there — that is what
          "Could not reach the mail server" means. <b>Brevo</b> sends over
          ordinary HTTPS instead: free, no card, and set up in two minutes.
        </p>

        <label>How to send</label>
        <select id="mailProvider" onchange="paintMailProvider()">
          <option value="brevo">Brevo &mdash; free, works on Render (recommended)</option>
          <option value="resend">Resend &mdash; free, works on Render</option>
          <option value="smtp">SMTP / Gmail &mdash; only on a paid host</option>
        </select>

        <label style="margin-top:10px">Email address the reports come from</label>
        <input id="mailFrom" placeholder="principal@school.org" oninput="suggestMail()">

        <div id="mailKeyBox">
          <label style="margin-top:10px">API key</label>
          <input id="mailKey" type="password" placeholder="leave blank to keep the saved one">
          <p id="mailKeyHelp" class="muted" style="margin:8px 0 0"></p>
        </div>

        <div id="mailSmtpBox" class="hidden">
          <p id="mailAuto" class="muted" style="margin:8px 0 0">
            Type the address and the server settings fill themselves in.
          </p>
          <div class="row" style="margin-top:8px">
            <div><label>SMTP host</label><input id="mailHost" placeholder="filled in automatically"></div>
            <div><label>Port</label><input id="mailPort" placeholder="587"></div>
          </div>
          <label style="margin-top:10px">Password / App Password</label>
          <input id="mailPass" type="password" placeholder="leave blank to keep the saved one">
          <label style="display:flex;align-items:center;gap:8px;margin-top:10px">
            <input type="checkbox" id="mailSecure" style="width:auto">
            <span style="color:var(--text);font-size:14px">Use SSL (port 465)</span>
          </label>
          <input id="mailUser" type="hidden">
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px">
          <button class="primary" style="font-size:13px" onclick="saveMail()">Save</button>
          <button class="secondary" style="font-size:13px" onclick="testMail()">Send a test email</button>
        </div>
        <p id="mailStatus" class="muted" style="margin-top:10px">Not set up yet.</p>
      </div>

      <div style="background:var(--bg);border-radius:10px;padding:14px;margin-bottom:14px">
        <b>Add a schedule</b>
        <p class="muted" style="margin:6px 0 10px">
          Leave the device box empty to cover every device. To send only a few,
          type their names separated by commas.
        </p>
        <div class="row">
          <div><label>Send to</label><input id="repEmail" placeholder="principal@school.org"></div>
          <div><label>Every (days)</label><input id="repDays" value="15"></div>
        </div>
        <div class="row">
          <div><label>Label (optional)</label><input id="repLabel" placeholder="Principal — fortnightly"></div>
          <div><label>Devices (optional)</label><input id="repDevices" placeholder="Lab PC 3, Library PC 1"></div>
        </div>
        <p id="repErr" class="hidden" style="color:var(--danger);font-size:13px"></p>
        <button class="primary" style="margin-top:12px;font-size:13px" onclick="addReport()">Add schedule</button>
      </div>

      <div id="reportList"></div>
      <p id="reportFoot" class="muted" style="margin-top:12px"></p>
    </div>

    <div id="tabActivity" class="card hidden">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
        <div>
          <h3 style="margin:0;color:var(--primary)">Activity Log</h3>
          <p class="muted" style="margin:4px 0 0">Blocked and alerted visits reported by devices.</p>
        </div>
        <button class="danger" onclick="clearActivity()">Clear log</button>
      </div>

      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;
                  padding:12px;background:var(--bg);border-radius:10px;margin-bottom:12px">
        <div style="flex:2;min-width:200px">
          <label style="margin-top:0">Search</label>
          <input id="actSearch" placeholder="Website or category…" oninput="renderActivity()">
        </div>
        <div style="flex:1;min-width:140px">
          <label style="margin-top:0">User</label>
          <select id="actUser" onchange="renderActivity()">
            <option value="">All users</option>
          </select>
        </div>
        <div style="flex:1;min-width:120px">
          <label style="margin-top:0">Action</label>
          <select id="actAction" onchange="renderActivity()">
            <option value="">All</option>
            <option value="block">Blocked only</option>
            <option value="alert">Alerts only</option>
          </select>
        </div>
        <div style="flex:1;min-width:140px">
          <label style="margin-top:0">Device</label>
          <select id="actDevice" onchange="renderActivity()">
            <option value="">All devices</option>
          </select>
        </div>
        <div style="flex:1;min-width:120px">
          <label style="margin-top:0">When</label>
          <select id="actWhen" onchange="renderActivity()">
            <option value="">Any time</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
          </select>
        </div>
        <div style="flex:0 0 auto">
          <span id="actCount" class="muted"></span>
        </div>
      </div>

      <table>
        <thead><tr><th>Website</th><th>User</th><th>Device</th><th>Category</th><th>Action</th><th>When</th></tr></thead>
        <tbody id="activityRows"></tbody>
      </table>
      <p id="noActivity" class="muted hidden">No blocked or alerted visits reported yet.</p>
    </div>

    <div id="tabDevices" class="card hidden">
      <h3 style="margin:0;color:var(--primary)">Registered devices</h3>
      <p class="muted" style="margin:4px 0 14px">
        Every phone and computer that has signed in. Removing one only clears
        this record — it does not sign the device out.
      </p>
      <table>
        <thead><tr><th>Device</th><th>Profile</th><th>Last seen</th><th></th></tr></thead>
        <tbody id="deviceRows"></tbody>
      </table>
      <p id="noDevices" class="muted hidden">No devices have signed in yet.</p>
    </div>

    <div id="tabAdmins" class="card hidden">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <div>
          <h3 style="margin:0;color:var(--primary)">Administrators</h3>
          <p class="muted" style="margin:4px 0 0">
            People who can sign in to this dashboard. Change your own password here.
          </p>
        </div>
        <button class="primary" onclick="openAdminEditor(null)">+ Add administrator</button>
      </div>
      <table>
        <thead><tr><th>Username</th><th>Added</th><th></th></tr></thead>
        <tbody id="adminRows"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ============ USER EDITOR ============ -->
<div id="editorModal" class="modal hidden">
  <div class="card">
    <div class="sheet-head">
      <h3 id="editorTitle">Add User</h3>
      <button class="close" onclick="closeEditor()">&times;</button>
    </div>

    <div class="sheet-body">
      <div class="steps">
        <button type="button" class="on" data-step="account" onclick="showStep('account')">1 · Account</button>
        <button type="button" data-step="rules" onclick="showStep('rules')">2 · Website Rules</button>
        <button type="button" data-step="time" onclick="showStep('time')">3 · Time Limits</button>
        <button type="button" data-step="perms" onclick="showStep('perms')">4 · Permissions</button>
      </div>

      <!-- STEP 1 -->
      <div class="step-panel on" id="stepAccount">
        <div class="row">
          <div><label>Username (used to sign in)</label><input id="fUsername"></div>
          <div><label>Full name</label><input id="fDisplayName"></div>
        </div>
        <div class="row">
          <div><label>Email</label><input id="fEmail"></div>
          <div><label id="fPassLabel">Password</label><input id="fPassword" type="text" placeholder="min 4 characters"></div>
        </div>
        <div class="row">
          <div>
            <label>Role</label>
            <select id="fRole" onchange="onRoleChanged()"></select>
            <p class="muted" style="margin-top:6px">
              This user follows the role's rules automatically. Anything you change
              below becomes an exception just for them.
            </p>
          </div>
          <div><label>Home page</label><input id="fHome" value="https://www.google.com/"></div>
        </div>
        <div class="row">
          <div>
            <label>Search engine</label>
            <select id="fSearchEngine">
              <option value="google">Google</option>
              <option value="bing">Bing</option>
              <option value="duckduckgo">DuckDuckGo</option>
              <option value="yahoo">Yahoo</option>
              <option value="ecosia">Ecosia</option>
            </select>
            <p class="muted" style="margin-top:6px">
              SafeSearch is forced on for whichever engine you choose.
            </p>
          </div>
          <div>
            <label>Maximum tabs</label>
            <input id="fMaxTabs" type="number" min="1" max="20" value="8">
            <p class="muted" style="margin-top:6px">
              Each tab uses memory. 8 is comfortable on a basic phone.
            </p>
          </div>
        </div>
        <label style="display:flex;align-items:center;gap:8px;margin-top:14px">
          <input type="checkbox" id="fEnabled" checked style="width:auto">
          <span style="color:var(--text);font-size:14px">Account enabled (can sign in)</span>
        </label>

        <div style="margin-top:14px;padding:12px;border:1px solid var(--border);border-radius:10px;background:var(--bg)">
          <label style="display:flex;align-items:flex-start;gap:8px;margin:0">
            <input type="checkbox" id="fSyncSessions" style="width:auto;margin-top:3px">
            <span style="color:var(--text);font-size:14px">
              <b>Share website logins across this profile's devices</b><br>
              <span class="muted">Sign in on one device and the others are signed in too.</span>
            </span>
          </label>
          <p class="muted" style="margin:8px 0 0;color:#8A6D00">
            &#9888; These are live login sessions. Turn this on only for profiles you trust.
          </p>
          <button id="btnClearSessions" class="danger hidden"
                  style="margin-top:10px;font-size:12px" onclick="clearSessions()">
            Clear saved website logins
          </button>
        </div>
      </div>

      <!-- STEP 2 -->
      <div class="step-panel" id="stepRules">
        <div class="cat-toolbar">
          <input id="catSearch" class="cat-search" placeholder="Search categories…" oninput="renderCats()">
          <div class="quick">
            <button class="allow-all" onclick="setAllCats('allow')">Allow all</button>
            <button onclick="setAllCats('alert')">Alert all</button>
            <button class="block-all" onclick="setAllCats('block')">Block all</button>
          </div>
        </div>
        <div class="summary-bar" id="catSummary"></div>
        <div id="catList"></div>

        <h4 style="margin:22px 0 6px;color:var(--primary);font-size:13px">Specific site overrides</h4>
        <p class="muted" style="margin:0 0 8px">One per line. These beat the category rules above.</p>

        <div style="background:#EEF4FA;border:1px solid #CFE0F0;border-radius:10px;
                    padding:12px 14px;margin-bottom:12px">
          <b style="font-size:12.5px;color:var(--primary)">How sub-domains work</b>
          <table style="margin-top:8px;font-size:12.5px">
            <tr><td style="padding:3px 10px 3px 0"><code>google.com</code></td>
                <td class="muted">Only google.com — <b>Gmail and Maps still work</b></td></tr>
            <tr><td style="padding:3px 10px 3px 0"><code>*.google.com</code></td>
                <td class="muted">Sub-domains only (mail., maps.) — google.com itself still works</td></tr>
            <tr><td style="padding:3px 10px 3px 0"><code>**.google.com</code></td>
                <td class="muted">Everything Google — the site and every sub-domain</td></tr>
            <tr><td style="padding:3px 10px 3px 0"><code>google.com/maps</code></td>
                <td class="muted">Just that section of the site</td></tr>
          </table>
          <p class="muted" style="margin:8px 0 0">
            Tick the box below to add <code>**.</code> automatically to every line.
          </p>
        </div>

        <label>Always ALLOW</label>
        <textarea id="fAllowed" placeholder="wikipedia.org&#10;khanacademy.org"></textarea>
        <label style="display:flex;align-items:center;gap:8px;margin-top:6px">
          <input type="checkbox" id="fAllowSubs" style="width:auto">
          <span style="color:var(--text);font-size:13px">Include sub-domains of the sites above</span>
        </label>

        <label style="margin-top:14px">Always BLOCK (highest priority)</label>
        <textarea id="fBlocked" placeholder="facebook.com"></textarea>
        <label style="display:flex;align-items:center;gap:8px;margin-top:6px">
          <input type="checkbox" id="fBlockSubs" style="width:auto">
          <span style="color:var(--text);font-size:13px">Include sub-domains of the sites above</span>
        </label>
      </div>

      <!-- STEP 3 -->
      <div class="step-panel" id="stepTime">
        <p class="muted" style="margin-bottom:12px">
          Allow a site <b>only</b> during these hours. Outside the window it is blocked,
          even if its category is allowed.
        </p>
        <div id="timeRules"></div>
        <button onclick="addTimeRule()" style="font-size:13px;margin-top:6px">+ Add time rule</button>
      </div>

      <!-- STEP 4 -->
      <div class="step-panel" id="stepPerms">
        <div class="switch-grid" id="permGrid"></div>
      </div>

      <p id="editorErr" class="hidden" style="color:var(--danger);font-size:13px;margin-top:14px"></p>
    </div>

    <div class="sheet-foot">
      <button onclick="closeEditor()">Cancel</button>
      <button class="primary" onclick="saveUser()">Save User</button>
    </div>
  </div>
</div>

<!-- ============ ADMINISTRATOR EDITOR ============ -->
<div id="adminModal" class="modal hidden">
  <div class="card" style="max-width:480px">
    <div class="sheet-head">
      <h3 id="adminTitle">Add administrator</h3>
      <button class="close" onclick="closeAdminEditor()">&times;</button>
    </div>
    <div class="sheet-body">
      <label>Username</label>
      <input id="aUsername" autocomplete="off">

      <div id="aCurrentWrap" class="hidden">
        <label>Your current password</label>
        <input id="aCurrent" type="password" autocomplete="off"
               placeholder="required to change your own password">
      </div>

      <label id="aPassLabel">Password (at least 6 characters)</label>
      <input id="aPassword" type="text" autocomplete="off">

      <p id="adminErr" class="hidden" style="color:var(--danger);font-size:13px;margin-top:12px"></p>
    </div>
    <div class="sheet-foot">
      <button onclick="closeAdminEditor()">Cancel</button>
      <button class="primary" onclick="saveAdmin()">Save</button>
    </div>
  </div>
</div>

<!-- ============ DUPLICATE USER ============ -->
<div id="dupModal" class="modal hidden">
  <div class="card" style="max-width:480px">
    <div class="sheet-head">
      <h3>Copy profile</h3>
      <button class="close" onclick="closeDup()">&times;</button>
    </div>
    <div class="sheet-body">
      <p class="muted" id="dupFrom" style="margin-top:0"></p>
      <label>New username</label>
      <input id="dUsername" autocomplete="off">
      <label>Full name</label>
      <input id="dDisplayName" autocomplete="off">
      <label>Password</label>
      <input id="dPassword" type="text" autocomplete="off" placeholder="min 4 characters">
      <p id="dupErr" class="hidden" style="color:var(--danger);font-size:13px;margin-top:12px"></p>
    </div>
    <div class="sheet-foot">
      <button onclick="closeDup()">Cancel</button>
      <button class="primary" onclick="saveDuplicate()">Create copy</button>
    </div>
  </div>
</div>

<!-- ============ ROLE EDITOR ============ -->
<div id="roleModal" class="modal hidden">
  <div class="card">
    <div class="sheet-head">
      <h3 id="roleTitle">New Role</h3>
      <button class="close" onclick="closeRoleEditor()">&times;</button>
    </div>

    <div class="sheet-body">
      <div class="row">
        <div><label>Role name</label><input id="rLabel" placeholder="e.g. Teacher, Class 10, Accounts"></div>
        <div><label>Home page</label><input id="rHome" value="https://www.wikipedia.org/"></div>
      </div>
      <label>Description (optional)</label>
      <input id="rDesc" placeholder="Who is this role for?">

      <div id="rCopyWrap">
        <label>Start from an existing role</label>
        <select id="rCopyFrom"></select>
      </div>

      <h4 style="margin:20px 0 6px;color:var(--primary);font-size:13px">Default website rules</h4>
      <p class="muted" style="margin:0 0 10px">
        New users given this role start with these rules.
      </p>
      <div class="cat-toolbar">
        <input id="rCatSearch" class="cat-search" placeholder="Search categories…" oninput="renderRoleCats()">
        <div class="quick">
          <button class="allow-all" onclick="setAllRoleCats('allow')">Allow all</button>
          <button onclick="setAllRoleCats('alert')">Alert all</button>
          <button class="block-all" onclick="setAllRoleCats('block')">Block all</button>
        </div>
      </div>
      <div class="summary-bar" id="rCatSummary"></div>
      <div id="rCatList"></div>

      <div style="margin-top:18px;padding:13px 14px;border-radius:10px;
                  background:#E8F5EC;border:1px solid #BFE3CB">
        <b style="font-size:13.5px;color:#0B6B3A">Changes apply to everyone with this role</b>
        <p class="muted" style="margin:4px 0 0;color:#2E6B48">
          Saving updates every user who has this role — on phones and computers —
          the next time they open the browser. Rules you customised for one
          person individually are kept.
        </p>
        <input type="checkbox" id="rApplyExisting" checked style="display:none">
      </div>

      <p id="roleErr" class="hidden" style="color:var(--danger);font-size:13px;margin-top:14px"></p>
    </div>

    <div class="sheet-foot">
      <button onclick="closeRoleEditor()">Cancel</button>
      <button class="primary" onclick="saveRole()">Save Role</button>
    </div>
  </div>
</div>

<script src="app.js"></script>
</body>
</html>
`;

const DASHBOARD_JS = `/* SMVS Browser — admin dashboard front-end (vanilla JS, no build step) */

const API = '';                       // same origin
let token = localStorage.getItem('smvs_token') || null;
let CATEGORIES = [];
let USERS = [];
let editing = null;                   // user being edited, or null for "new"
let catState = {};                    // categoryId -> allow|alert|block
let timeRules = [];
let permState = {};                   // feature flag -> bool
let ROLES = [];                       // role records from the server
let editingRole = null;               // role being edited, or null for "new"
let roleCatState = {};

const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

// ------------------------------------------------------------------ utils

function $(id) { return document.getElementById(id); }

function toast(msg) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2600);
}

async function api(pathname, options = {}) {
  const res = await fetch(API + pathname, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: 'Bearer ' + token } : {}),
      ...(options.headers || {})
    }
  });
  if (res.status === 401) { logout(); throw new Error('Session expired'); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || \`Request failed (\${res.status})\`);
  return data;
}

function hhmm(mins) {
  const h = Math.floor(mins / 60), m = mins % 60;
  return \`\${String(h).padStart(2, '0')}:\${String(m).padStart(2, '0')}\`;
}
function toMins(str) {
  const [h, m] = String(str || '00:00').split(':').map(Number);
  return (h || 0) * 60 + (m || 0);
}

// ------------------------------------------------------------------ auth

async function doLogin() {
  const err = $('loginErr');
  err.classList.add('hidden');
  try {
    const data = await api('/api/admin/login', {
      method: 'POST',
      body: JSON.stringify({ username: $('admUser').value, password: $('admPass').value })
    });
    token = data.token;
    localStorage.setItem('smvs_token', token);
    $('whoami').textContent = 'Signed in as ' + data.username;
    await boot();
  } catch (e) {
    err.textContent = e.message;
    err.classList.remove('hidden');
  }
}

function logout() {
  token = null;
  localStorage.removeItem('smvs_token');
  $('appView').classList.add('hidden');
  $('loginView').classList.remove('hidden');
}

async function boot() {
  $('loginView').classList.add('hidden');
  $('appView').classList.remove('hidden');
  const cats = await api('/api/admin/categories');
  CATEGORIES = cats.categories;
  await refresh();
}

// ------------------------------------------------------------------ data

/**
 * Warns when the server is running on a disk that will be wiped.
 *
 * This is the single most confusing failure mode of the whole system: users and
 * roles are created successfully, then vanish after the host restarts. Saying
 * so on screen turns a mystery into a one-line instruction.
 */
async function checkStorage() {
  try {
    const res = await fetch(API + '/api/storage');
    const info = await res.json();
    const box = $('storageWarn');
    if (!box) return;
    box.classList.toggle('hidden', !!info.durable);
    if (!info.durable) $('storageWarnText').textContent = info.message;
  } catch { /* older server without the endpoint — stay quiet */ }
}

async function refresh() {
  checkStorage();
  try {
    ROLES = (await api('/api/admin/roles')).roles;
  } catch { ROLES = []; }
  fillRoleSelects();

  const data = await api('/api/admin/users');
  USERS = data.users;
  $('stTotal').textContent = data.stats.total;
  $('stActive').textContent = data.stats.active;
  $('stDisabled').textContent = data.stats.disabled;
  renderUsers();

  const act = await api('/api/admin/activity');
  $('stAlerts').textContent = act.activity.length;
  renderActivity(act.activity);
  fillActivityFilters();
}

function renderUsers() {
  const tbody = $('userRows');
  tbody.innerHTML = '';
  $('noUsers').classList.toggle('hidden', USERS.length > 0);

  for (const u of USERS) {
    const rules = u.categoryRules || {};
    const blocked = Object.values(rules).filter(v => v === 'block').length;
    const alerted = Object.values(rules).filter(v => v === 'alert').length;
    const tr = document.createElement('tr');
    tr.innerHTML = \`
      <td><b>\${esc(u.username)}</b><br><span class="muted">\${esc(u.displayName || '')}</span></td>
      <td><span class="badge b-neutral">\${esc((roleById(u.role) || {}).label || u.role)}</span></td>
      <td class="muted">\${blocked} blocked · \${alerted} alert</td>
      <td class="muted">\${(u.timeRules || []).length}</td>
      <td>\${syncBadge(u)}</td>
      <td><span class="badge \${u.enabled ? 'b-ok' : 'b-off'}">\${u.enabled ? 'ACTIVE' : 'DISABLED'}</span></td>
      <td class="muted">\${u.lastSyncAt ? new Date(u.lastSyncAt).toLocaleString() : 'never'}</td>
      <td style="text-align:right;white-space:nowrap">
        <button onclick="openEditor('\${u.id}')">Edit</button>
        <button onclick="openDup('\${u.id}')" title="Create another profile with the same rules">Copy</button>
        <button onclick="toggleEnabled('\${u.id}', \${u.enabled ? 'false' : 'true'})">
          \${u.enabled ? 'Disable' : 'Enable'}
        </button>
        <button class="danger" onclick="removeUser('\${u.id}','\${esc(u.username)}')">Delete</button>
      </td>\`;
    tbody.appendChild(tr);
  }
}

/** The "Login sync" column the table header promises. */
function syncBadge(u) {
  if (!u.syncWebSessions) return '<span class="badge b-neutral">OFF</span>';
  return u.hasSyncedSession
    ? '<span class="badge b-ok">SYNCED</span>'
    : '<span class="badge b-alert">ON</span>';
}

async function toggleEnabled(id, enabled) {
  try {
    await api('/api/admin/users/' + id + '/enabled', {
      method: 'POST',
      body: JSON.stringify({ enabled: enabled === true || enabled === 'true' })
    });
    await refresh();
    toast(enabled === true || enabled === 'true' ? 'Account enabled' : 'Account disabled');
  } catch (e) { alert(e.message); }
}

// ------------------------------------------------------------ duplicate user

let dupSource = null;

function openDup(id) {
  dupSource = USERS.find(u => u.id === id);
  if (!dupSource) return;
  $('dupFrom').textContent =
    'Every rule, time limit and permission from "' + (dupSource.displayName || dupSource.username) +
    '" is copied. Website logins are not.';
  $('dUsername').value = '';
  $('dDisplayName').value = '';
  $('dPassword').value = '';
  $('dupErr').classList.add('hidden');
  $('dupModal').classList.remove('hidden');
}

function closeDup() { $('dupModal').classList.add('hidden'); }

async function saveDuplicate() {
  const err = $('dupErr');
  err.classList.add('hidden');
  try {
    await api('/api/admin/users/' + dupSource.id + '/duplicate', {
      method: 'POST',
      body: JSON.stringify({
        username: $('dUsername').value.trim(),
        displayName: $('dDisplayName').value.trim(),
        password: $('dPassword').value
      })
    });
    closeDup();
    await refresh();
    toast('Profile copied');
  } catch (e) {
    err.textContent = e.message;
    err.classList.remove('hidden');
  }
}

// ---------------------------------------------------------------- devices

async function loadDevices() {
  const tbody = $('deviceRows');
  tbody.innerHTML = '';
  let list = [];
  try { list = (await api('/api/admin/devices')).devices; } catch { list = []; }

  $('noDevices').classList.toggle('hidden', list.length > 0);
  for (const d of list) {
    const tr = document.createElement('tr');
    tr.innerHTML = \`
      <td><b>\${esc(d.name || 'Unnamed device')}</b></td>
      <td>\${esc(d.username)}</td>
      <td class="muted">\${d.lastSeen ? new Date(d.lastSeen).toLocaleString() : 'unknown'}</td>
      <td style="text-align:right">
        <button class="ghost"
          onclick="renameDevice('\${encodeURIComponent(d.userId)}','\${encodeURIComponent(d.deviceId || '')}','\${esc(d.name || '')}')">
          Rename
        </button>
        <button class="danger"
          onclick="removeDevice('\${encodeURIComponent(d.userId)}','\${encodeURIComponent(d.name || '')}')">
          Remove
        </button>
      </td>\`;
    tbody.appendChild(tr);
  }
}

/**
 * Renames a device.
 *
 * The apps refuse to let a user rename their own machine — an activity log is
 * only worth reading if the names in it are trustworthy — so this is the only
 * place a name can change. The device adopts it at its next sign-in.
 */
async function renameDevice(userId, deviceId, current) {
  const name = prompt('New name for this device:', current || '');
  if (name === null) return;                       // cancelled
  if (!name.trim()) return alert('Device name cannot be empty.');

  try {
    await api('/api/admin/devices/rename', {
      method: 'PUT',
      body: {
        userId: decodeURIComponent(userId),
        deviceId: decodeURIComponent(deviceId),
        oldName: current,
        name: name.trim()
      }
    });
    await loadDevices();
    toast('Device renamed. It will update the next time it signs in.');
  } catch (e) { alert(e.message); }
}

async function removeDevice(userId, name) {
  if (!confirm('Remove this device from the list?')) return;
  try {
    await api('/api/admin/devices?userId=' + userId + '&name=' + name, { method: 'DELETE' });
    await loadDevices();
    toast('Device removed');
  } catch (e) { alert(e.message); }
}

// ---------------------------------------------------------- administrators

let ADMINS = [];
let myAdminId = null;
let editingAdmin = null;

async function loadAdmins() {
  const tbody = $('adminRows');
  tbody.innerHTML = '';
  try {
    const data = await api('/api/admin/admins');
    ADMINS = data.admins;
    myAdminId = data.me;
  } catch { ADMINS = []; }

  for (const a of ADMINS) {
    const isMe = a.id === myAdminId;
    const tr = document.createElement('tr');
    tr.innerHTML = \`
      <td><b>\${esc(a.username)}</b>\${isMe ? ' <span class="badge b-ok">YOU</span>' : ''}</td>
      <td class="muted">\${a.createdAt ? new Date(a.createdAt).toLocaleDateString() : ''}</td>
      <td style="text-align:right;white-space:nowrap">
        <button onclick="openAdminEditor('\${a.id}')">\${isMe ? 'Change password' : 'Edit'}</button>
        \${isMe || ADMINS.length <= 1 ? '' :
          '<button class="danger" onclick="removeAdmin(\\'' + a.id + '\\',\\'' +
          esc(a.username) + '\\')">Delete</button>'}
      </td>\`;
    tbody.appendChild(tr);
  }
}

function openAdminEditor(id) {
  editingAdmin = id ? ADMINS.find(a => a.id === id) : null;
  const isMe = editingAdmin && editingAdmin.id === myAdminId;

  $('adminTitle').textContent = editingAdmin
    ? (isMe ? 'Change your password' : 'Edit administrator')
    : 'Add administrator';
  $('aUsername').value = editingAdmin ? editingAdmin.username : '';
  $('aPassword').value = '';
  $('aCurrent').value = '';
  $('aCurrentWrap').classList.toggle('hidden', !isMe);
  $('aPassLabel').textContent = editingAdmin
    ? 'New password (leave blank to keep current)'
    : 'Password (at least 6 characters)';
  $('adminErr').classList.add('hidden');
  $('adminModal').classList.remove('hidden');
}

function closeAdminEditor() { $('adminModal').classList.add('hidden'); }

async function saveAdmin() {
  const err = $('adminErr');
  err.classList.add('hidden');

  const body = { username: $('aUsername').value.trim() };
  const pw = $('aPassword').value;
  if (pw) body.password = pw;
  if (editingAdmin && editingAdmin.id === myAdminId) {
    body.currentPassword = $('aCurrent').value;
  }

  try {
    if (editingAdmin) {
      await api('/api/admin/admins/' + editingAdmin.id, {
        method: 'PUT', body: JSON.stringify(body)
      });
    } else {
      if (!body.password) throw new Error('A password is required.');
      await api('/api/admin/admins', { method: 'POST', body: JSON.stringify(body) });
    }
    closeAdminEditor();
    await loadAdmins();
    toast('Saved');
  } catch (e) {
    err.textContent = e.message;
    err.classList.remove('hidden');
  }
}

async function removeAdmin(id, name) {
  if (!confirm('Delete administrator "' + name + '"?')) return;
  try {
    await api('/api/admin/admins/' + id, { method: 'DELETE' });
    await loadAdmins();
    toast('Administrator deleted');
  } catch (e) { alert(e.message); }
}

// ------------------------------------------------------------ activity log

async function clearActivity() {
  if (!confirm('Delete every entry in the activity log?')) return;
  try {
    await api('/api/admin/activity', { method: 'DELETE' });
    await refresh();
    toast('Activity log cleared');
  } catch (e) { alert(e.message); }
}

let ACTIVITY = [];

/**
 * Draws the activity log, honouring the filter controls.
 *
 * The log now shows WHY something happened, not just the category's own label.
 * A site stopped by the block list or a time window used to be printed as
 * "ALERT" because that was its category's action, which made the log actively
 * misleading.
 */
function renderActivity(list) {
  if (list) ACTIVITY = list;

  const q = ($('actSearch') && $('actSearch').value || '').trim().toLowerCase();
  const who = ($('actUser') && $('actUser').value) || '';
  const what = ($('actAction') && $('actAction').value) || '';
  const dev = ($('actDevice') && $('actDevice').value) || '';
  const when = ($('actWhen') && $('actWhen').value) || '';

  const cutoff = when === '24h' ? Date.now() - 864e5
    : when === '7d' ? Date.now() - 7 * 864e5
      : when === '30d' ? Date.now() - 30 * 864e5 : 0;

  const rows = ACTIVITY.filter(a =>
    (!q || (a.host || '').toLowerCase().includes(q) ||
           (a.url || '').toLowerCase().includes(q) ||
           (a.category || '').toLowerCase().includes(q)) &&
    (!who || a.userId === who) &&
    (!what || a.action === what) &&
    (!dev || a.device === dev) &&
    (!cutoff || a.timestamp >= cutoff));

  const tbody = $('activityRows');
  tbody.innerHTML = '';
  $('noActivity').classList.toggle('hidden', rows.length > 0);

  if ($('actCount')) {
    $('actCount').textContent =
      rows.length === ACTIVITY.length
        ? \`\${ACTIVITY.length} entries\`
        : \`\${rows.length} of \${ACTIVITY.length} entries\`;
  }

  for (const a of rows.slice(0, 500)) {
    const tr = document.createElement('tr');
    tr.innerHTML = \`
      <td title="\${esc(a.url || '')}">\${esc(a.host || a.url)}</td>
      <td>\${esc(a.username)}</td>
      <td class="muted">\${esc(a.device || '\u2014')}</td>
      <td class="muted">\${esc(a.category)}</td>
      <td>
        <span class="badge \${a.action === 'block' ? 'b-off' : 'b-alert'}">\${a.action.toUpperCase()}</span>
        \${a.reason ? \`<div class="muted" style="margin-top:3px">\${esc(a.reason)}</div>\` : ''}
      </td>
      <td class="muted">\${new Date(a.timestamp).toLocaleString()}</td>\`;
    tbody.appendChild(tr);
  }
}

/** Fills the "user" filter from whoever actually appears in the log. */
function fillActivityFilters() {
  const sel = $('actUser');
  if (!sel) return;
  const keep = sel.value;
  const seen = new Map();
  for (const a of ACTIVITY) if (!seen.has(a.userId)) seen.set(a.userId, a.username);
  sel.innerHTML = '<option value="">All users</option>' +
    [...seen.entries()].map(([id, name]) =>
      \`<option value="\${esc(id)}">\${esc(name)}</option>\`).join('');
  sel.value = keep;

  // Device list, built from whatever actually appears in the log rather than
  // from the registered-devices table: a device that has reported nothing
  // would only be noise in a filter.
  const dsel = $('actDevice');
  if (dsel) {
    const keepDev = dsel.value;
    const devices = [...new Set(ACTIVITY.map(a => a.device).filter(Boolean))].sort();
    dsel.innerHTML = '<option value="">All devices</option>' +
      devices.map(d => \`<option value="\${esc(d)}">\${esc(d)}</option>\`).join('');
    dsel.value = keepDev;
  }
}

// ---------------- roles ----------------

function fillRoleSelects() {
  const sel = $('fRole');
  if (sel) {
    const keep = sel.value;
    sel.innerHTML = ROLES.map(r =>
      \`<option value="\${esc(r.id)}">\${esc(r.label)}</option>\`).join('');
    if (keep && ROLES.some(r => r.id === keep)) sel.value = keep;
  }
  const copy = $('rCopyFrom');
  if (copy) {
    copy.innerHTML = '<option value="">Blank (recommended defaults)</option>' +
      ROLES.map(r => \`<option value="\${esc(r.id)}">\${esc(r.label)}</option>\`).join('');
  }
}

function roleById(id) { return ROLES.find(r => r.id === id) || null; }

function renderRoles() {
  const host = $('roleList');
  if (!host) return;
  if (!ROLES.length) { host.innerHTML = '<p class="muted">No roles yet.</p>'; return; }

  host.innerHTML = ROLES.map(r => {
    const vals = Object.values(r.categoryRules || {});
    const a = vals.filter(v => v === 'allow').length;
    const w = vals.filter(v => v === 'alert').length;
    const b = vals.filter(v => v === 'block').length;
    return \`
      <div class="role-card">
        <div style="min-width:0">
          <div class="role-title">\${esc(r.label)}
            \${r.builtIn ? '<span class="tag built">built-in</span>' : '<span class="tag">custom</span>'}
          </div>
          \${r.description ? \`<div class="role-desc">\${esc(r.description)}</div>\` : ''}
          <div class="role-meta">
            <span class="pill a">\${a} allowed</span>
            <span class="pill w">\${w} alert</span>
            <span class="pill b">\${b} blocked</span>
            <span>· \${r.userCount} user(s)</span>
          </div>
        </div>
        <div style="white-space:nowrap;display:flex;gap:6px">
          <button onclick="openRoleEditor('\${esc(r.id)}')">Edit</button>
          <button onclick="duplicateRole('\${esc(r.id)}','\${esc(r.label)}')"
                  title="Create an editable copy of this role">Copy</button>
          \${r.builtIn ? '' :
            \`<button class="danger" onclick="deleteRole('\${esc(r.id)}','\${esc(r.label)}')">Delete</button>\`}
        </div>
      </div>\`;
  }).join('');
}

function openRoleEditor(id) {
  editingRole = id ? roleById(id) : null;
  $('roleTitle').textContent = editingRole ? \`Edit Role — \${editingRole.label}\` : 'New Role';
  $('roleErr').classList.add('hidden');

  $('rLabel').value = editingRole ? editingRole.label : '';
  $('rDesc').value = editingRole ? (editingRole.description || '') : '';
  $('rHome').value = editingRole ? (editingRole.homeUrl || '') : 'https://www.wikipedia.org/';
  $('rApplyExisting').checked = false;
  $('rCopyWrap').classList.toggle('hidden', !!editingRole);

  if (editingRole && editingRole.categoryRules && Object.keys(editingRole.categoryRules).length) {
    roleCatState = { ...editingRole.categoryRules };
  } else {
    roleCatState = {};
    CATEGORIES.forEach(c => { roleCatState[c.id] = c.def; });
  }
  renderRoleCats();
  $('roleModal').classList.remove('hidden');
}

function closeRoleEditor() { $('roleModal').classList.add('hidden'); }

$('rCopyFrom') && $('rCopyFrom').addEventListener('change', e => {
  const src = roleById(e.target.value);
  if (!src) {
    roleCatState = {};
    CATEGORIES.forEach(c => { roleCatState[c.id] = c.def; });
  } else {
    roleCatState = { ...src.categoryRules };
    $('rHome').value = src.homeUrl || '';
  }
  renderRoleCats();
});

function renderRoleCats() {
  paintCats($('rCatList'), $('rCatSummary'), roleCatState,
            ($('rCatSearch') || {}).value || '',
            (id, action) => { roleCatState[id] = action; renderRoleCats(); });
}

function setAllRoleCats(action) {
  CATEGORIES.forEach(c => { roleCatState[c.id] = action; });
  renderRoleCats();
}

async function saveRole() {
  const err = $('roleErr');
  err.classList.add('hidden');
  const label = $('rLabel').value.trim();
  if (!label) { err.textContent = 'Please enter a role name.'; err.classList.remove('hidden'); return; }

  const body = {
    label,
    description: $('rDesc').value.trim(),
    homeUrl: $('rHome').value.trim(),
    categoryRules: roleCatState,
    uncategorizedAction: roleCatState['uncategorized'] || 'alert'
  };

  try {
    if (editingRole) {
      body.applyToExistingUsers = $('rApplyExisting').checked;
      const r = await api('/api/admin/roles/' + editingRole.id,
        { method: 'PUT', body: JSON.stringify(body) });
      toast(r.usersUpdated ? \`Saved — \${r.usersUpdated} user(s) updated\` : 'Role saved');
    } else {
      body.copyFrom = $('rCopyFrom').value || null;
      await api('/api/admin/roles', { method: 'POST', body: JSON.stringify(body) });
      toast('Role created');
    }
    closeRoleEditor();
    await refresh();
    renderRoles();
  } catch (e) {
    err.textContent = e.message;
    err.classList.remove('hidden');
  }
}

/**
 * Copies a role. Built-in roles cannot be deleted or renamed, so cloning is
 * the only way to build "Student, but with YouTube" without touching all 37
 * categories by hand.
 */
async function duplicateRole(id, label) {
  const name = prompt('Name for the copy:', label + ' copy');
  if (!name || !name.trim()) return;
  try {
    await api('/api/admin/roles/' + id + '/duplicate', {
      method: 'POST',
      body: JSON.stringify({ label: name.trim() })
    });
    await refresh();
    renderRoles();
    toast('Role copied');
  } catch (e) { alert(e.message); }
}

async function deleteRole(id, label) {
  if (!confirm(\`Delete the role "\${label}"?\`)) return;
  try {
    await api('/api/admin/roles/' + id, { method: 'DELETE' });
    toast('Role deleted');
    await refresh();
    renderRoles();
  } catch (e) { alert(e.message); }
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function showTab(which) {
  ['users','activity','roles','devices','admins','update','reports'].forEach(t => {
    const panel = $('tab' + t.charAt(0).toUpperCase() + t.slice(1));
    const btn = $('tab' + t.charAt(0).toUpperCase() + t.slice(1) + 'Btn');
    if (panel) panel.classList.toggle('hidden', which !== t);
    if (btn) btn.classList.toggle('active', which === t);
  });
  if (which === 'update') { loadServerUrl(); loadVersion(); loadPeer(); }
  if (which === 'roles') renderRoles();
  if (which === 'devices') loadDevices();
  if (which === 'admins') loadAdmins();
  if (which === 'reports') { loadMail(); loadReports(); }
}

/* ------------------------------------------------ step 1: server address */

async function loadServerUrl() {
  try {
    const d = await api('/api/admin/server-url');
    $('srvUrl').value = d.serverUrl || '';
    $('srvStatus').textContent = d.serverUrl
      ? d.devices + ' device(s) registered, ' + d.seen + ' seen in the last week.'
      : 'Not set — devices keep using the address built into the app.';
  } catch (e) { /* non-fatal */ }
}

async function saveServerUrl() {
  const url = $('srvUrl').value.trim();
  if (url && !confirm('Send this address to every device?\\n\\n' + url +
      '\\n\\nThey will move to it within a second. Make sure it is correct.')) return;
  try {
    const r = await api('/api/admin/server-url', {
      method: 'PUT', body: JSON.stringify({ serverUrl: url })
    });
    $('srvStatus').textContent = 'Sent to ' + r.devicesNotified + ' device(s).';
    toast('Address sent to all devices');
  } catch (e) { alert(e.message); }
}

/* ------------------------------------------------ step 2 and 3: versions */

function describeVersion(v) {
  if (!v) return 'Nothing published yet.';
  const lines = [];
  if (v.apkUrl) {
    lines.push('&#128241; <b>Android</b> ' + esc(v.versionName || String(v.versionCode)) +
      ' (code ' + v.versionCode + ')' +
      (v.apkPackage ? '<br><span class="muted">' + esc(v.apkPackage) + '</span>' : ''));
  }
  if (v.desktopUrl) {
    lines.push('&#128187; <b>Windows</b> ' + esc(v.desktopVersion));
  }
  lines.push((v.mandatory ? 'Required' : 'Optional') +
    ' &middot; ' + new Date(v.publishedAt).toLocaleString());
  return lines.join('<br>');
}

async function loadVersion() {
  try {
    const d = await api('/api/admin/app/version');
    $('liveVersionText').innerHTML = describeVersion(d.appVersion);
    $('betaVersionText').innerHTML = describeVersion(d.appVersionBeta);

    // Pre-fill each side with what it is already carrying, so a small change
    // does not mean retyping four links.
    if (d.appVersion) {
      $('uApkUrl').value = d.appVersion.apkUrl || '';
      $('uDesktopUrl').value = d.appVersion.desktopUrl || '';
      $('uDesktopVersion').value = d.appVersion.desktopVersion || '';
      $('uMandatory').checked = d.appVersion.mandatory !== false;
    }
    if (d.appVersionBeta) {
      $('bApkUrl').value = d.appVersionBeta.apkUrl || '';
      $('bDesktopUrl').value = d.appVersionBeta.desktopUrl || '';
      $('bDesktopVersion').value = d.appVersionBeta.desktopVersion || '';
    }
  } catch (e) { /* non-fatal */ }
}

/**
 * One button per channel, each with its own files.
 *
 * This replaced a "copy live to beta" button. Copying could only ever move
 * the live FILE onto the beta channel, and Android will not install that over
 * the beta app — so it looked like it had worked and updated nobody. Naming
 * the beta file explicitly is the only honest version of the same action.
 */
/**
 * Sends the build already on one channel across to the other.
 *
 * The server does the finding and the proving; this only reports it. The
 * manual boxes below are still there for a release that does not follow the
 * usual naming.
 */
async function promote(from, to) {
  const el = $('promoteStatus');
  el.style.color = '';
  el.textContent = 'Looking for the ' + to.toUpperCase() + ' files on that release…';
  try {
    const r = await api('/api/admin/app/version/promote', {
      method: 'POST', body: JSON.stringify({ from: from, to: to })
    });
    const bits = [];
    if (r.found.apkUrl) bits.push('Android ' + r.found.apkUrl.split('/').pop());
    if (r.found.desktopUrl) bits.push('Windows ' + r.found.desktopUrl.split('/').pop());
    let msg = 'Published to ' + to.toUpperCase() + ': ' + bits.join(' · ');
    if (r.peer) msg += r.peer.ok ? ' — and sent to the beta server.' : ' — ' + r.peer.message;
    el.textContent = msg;
    toast('Sent ' + from + ' to ' + to);
    await loadVersion();
    if (to === 'beta') await loadPeer();
  } catch (e) {
    el.style.color = 'var(--danger)';
    el.textContent = e.message;
  }
}

async function publishTo(channel) {
  const err = $('updateErr');
  err.classList.add('hidden');
  const beta = channel === 'beta';

  const body = {
    channel: channel,
    versionCode: '',                       // read from the APK by the server
    versionName: $('uVersionName').value.trim(),
    apkUrl: (beta ? $('bApkUrl') : $('uApkUrl')).value.trim(),
    desktopUrl: (beta ? $('bDesktopUrl') : $('uDesktopUrl')).value.trim(),
    desktopVersion: (beta ? $('bDesktopVersion') : $('uDesktopVersion')).value.trim(),
    desktopMandatory: $('uMandatory').checked,
    mandatory: $('uMandatory').checked,
    notes: $('uNotes').value.trim()
  };

  if (!body.apkUrl && !body.desktopUrl) {
    err.textContent = 'Add at least one link for the ' + channel + ' side.';
    err.classList.remove('hidden');
    return;
  }

  try {
    const r = await api('/api/admin/app/version', { method: 'POST', body: JSON.stringify(body) });
    let msg = 'Published to ' + channel.toUpperCase();
    if (r.verifiedVersionCode) msg += ' (version code ' + r.verifiedVersionCode + ')';
    if (beta && r.peer) msg += r.peer.ok ? ' and sent to the beta server' : ' — ' + r.peer.message;
    toast(msg);
    await loadVersion();
    if (beta) await loadPeer();
  } catch (e) {
    err.textContent = e.message;
    err.classList.remove('hidden');
  }
}

/* ------------------------------------------------ the email account ---- */

const MAIL_HELP = {
  brevo:
    '1. Open <b>brevo.com</b> and sign up (free, no card). ' +
    '2. <b>Senders &amp; IP</b> &rarr; add the address above &rarr; type the code it emails you. ' +
    '3. <b>SMTP &amp; API</b> &rarr; <b>API keys</b> &rarr; Generate a new API key &rarr; paste it here.',
  resend:
    '1. Open <b>resend.com</b> and sign up (free). ' +
    '2. <b>API Keys</b> &rarr; Create API Key &rarr; paste it here. ' +
    '3. Until you verify a domain, Resend only lets you send to your own address.',
  smtp:
    'Only choose this if your server is on a paid plan. On the free Render plan ' +
    'the SMTP ports are blocked and this will always time out.'
};

function paintMailProvider() {
  const p = $('mailProvider').value;
  $('mailKeyBox').classList.toggle('hidden', p === 'smtp');
  $('mailSmtpBox').classList.toggle('hidden', p !== 'smtp');
  $('mailKeyHelp').innerHTML = MAIL_HELP[p] || '';
  if (p === 'smtp') doSuggestMail();
}

async function loadMail() {
  try {
    const m = await api('/api/admin/mail');
    $('mailProvider').value = m.provider || 'brevo';
    $('mailFrom').value = m.from || '';
    $('mailHost').value = m.host || '';
    $('mailPort').value = m.port || 587;
    $('mailSecure').checked = !!m.secure;
    $('mailKey').placeholder = m.hasKey
      ? 'a key is saved — leave blank to keep it'
      : 'paste the API key here';
    paintMailProvider();
    $('mailStatus').textContent = m.configured
      ? 'Ready — sending as ' + (m.from || '') + ' through ' + (m.provider || 'brevo')
      : 'Not set up yet.';
  } catch (e) { /* non-fatal */ }
}

async function saveMail() {
  const provider = $('mailProvider').value;
  const payload = { provider: provider, from: $('mailFrom').value.trim() };
  if (provider === 'smtp') {
    payload.host = $('mailHost').value.trim();
    payload.port = parseInt($('mailPort').value, 10) || 587;
    payload.user = $('mailFrom').value.trim();
    payload.pass = $('mailPass').value;
    payload.secure = $('mailSecure').checked;
  } else {
    payload.apiKey = $('mailKey').value.trim();
  }
  try {
    await api('/api/admin/mail', { method: 'PUT', body: JSON.stringify(payload) });
    $('mailPass').value = ''; $('mailKey').value = '';
    toast('Email settings saved');
    await loadMail();
  } catch (e) { alert(e.message); }
}

async function testMail() {
  const to = prompt('Send a test email to which address?', $('mailFrom').value || '');
  if (!to) return;
  $('mailStatus').textContent = 'Sending…';
  try {
    const r = await api('/api/admin/mail/test', { method: 'POST', body: JSON.stringify({ to: to }) });
    $('mailStatus').textContent = r.message;
  } catch (e) {
    $('mailStatus').innerHTML = '<span style="color:var(--danger)">' + esc(e.message) + '</span>';
  }
}

/* ---- SMTP host worked out from the address (only used by the SMTP option) ---- */

var mailSuggestTimer = null;

function setServerFieldsLocked(locked) {
  for (const id of ['mailHost', 'mailPort']) {
    const el = $(id);
    if (!el) continue;
    el.readOnly = locked;
    el.style.background = locked ? 'var(--bg)' : '';
  }
  if ($('mailSecure')) $('mailSecure').disabled = locked;
}

function suggestMail() {
  clearTimeout(mailSuggestTimer);
  mailSuggestTimer = setTimeout(doSuggestMail, 450);
}

async function doSuggestMail() {
  if ($('mailProvider') && $('mailProvider').value !== 'smtp') return;
  const email = $('mailFrom').value.trim();
  if (email.indexOf('@') < 1) {
    $('mailAuto').textContent = 'Type the address and the server settings fill themselves in.';
    setServerFieldsLocked(false);
    return;
  }
  $('mailAuto').textContent = 'Looking up ' + email.split('@')[1] + '…';
  try {
    const r = await api('/api/admin/mail/suggest?email=' + encodeURIComponent(email));
    if (r.known) {
      $('mailHost').value = r.host;
      $('mailPort').value = r.port;
      $('mailSecure').checked = !!r.secure;
      setServerFieldsLocked(true);
      $('mailAuto').innerHTML = '&#10003; ' + esc(r.label) + ' recognised — settings filled in' +
        (r.note ? '. <b>' + esc(r.note) + '</b>' : '.');
    } else {
      if (r.guessHost && !$('mailHost').value) {
        $('mailHost').value = r.guessHost;
        $('mailPort').value = r.guessPort || 587;
      }
      setServerFieldsLocked(false);
      $('mailAuto').textContent = (r.reason || 'Provider not recognised.') +
        ' Please enter the SMTP host and port yourself' +
        (r.mx && r.mx.length ? ' (its mail servers: ' + r.mx.join(', ') + ').' : '.');
    }
  } catch (e) {
    setServerFieldsLocked(false);
    $('mailAuto').textContent = 'Could not look that up — enter the host and port yourself.';
  }
}

/* ------------------------------------------------ report schedules ----- */

async function loadReports() {
  try {
    const d = await api('/api/admin/reports');
    const list = $('reportList');
    if (!d.reports.length) {
      list.innerHTML = '<p class="muted">No schedules yet.</p>';
    } else {
      list.innerHTML = d.reports.map(function (r) {
        const last = r.lastSentAt ? new Date(r.lastSentAt).toLocaleString() : 'not yet';
        const next = r.lastSentAt
          ? new Date(r.lastSentAt + r.everyDays * 86400000).toLocaleDateString()
          : 'after the first period';
        return '<div style="background:var(--bg);border-radius:10px;padding:14px;margin-bottom:10px">' +
          '<b>' + esc(r.email) + '</b>' +
          (r.enabled === false ? ' <span class="muted">(disabled)</span>' : '') +
          (r.label ? '<br><span class="muted">' + esc(r.label) + '</span>' : '') +
          '<div class="muted" style="margin-top:6px">Every ' + r.everyDays + ' days &middot; ' +
          (r.devices && r.devices.length ? esc(r.devices.join(', ')) : 'all devices') +
          '<br>Last sent: ' + esc(last) + ' &middot; next: ' + esc(next) + '</div>' +
          (r.lastError ? '<div style="color:var(--danger);font-size:12px;margin-top:6px">' +
            esc(r.lastError) + '</div>' : '') +
          '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px">' +
          '<button class="secondary" style="font-size:12px" onclick="previewReport(\\'' + r.id + '\\')">Preview</button>' +
          '<button class="secondary" style="font-size:12px" onclick="sendReport(\\'' + r.id + '\\')">Send now</button>' +
          '<button class="secondary" style="font-size:12px" onclick="toggleReport(\\'' + r.id + '\\',' +
            (r.enabled === false) + ')">' + (r.enabled === false ? 'Enable' : 'Disable') + '</button>' +
          '<button class="danger" style="font-size:12px" onclick="deleteReport(\\'' + r.id + '\\')">Delete</button>' +
          '</div></div>';
      }).join('');
    }
    $('reportFoot').textContent = d.historyRows + ' visits stored' +
      (d.knownDevices.length ? ' from: ' + d.knownDevices.join(', ') : '') +
      (d.mailConfigured ? '' : ' — email is not set up yet, so nothing can be sent.');
  } catch (e) { /* non-fatal */ }
}

async function addReport() {
  const err = $('repErr');
  err.classList.add('hidden');
  try {
    await api('/api/admin/reports', {
      method: 'POST',
      body: JSON.stringify({
        email: $('repEmail').value.trim(),
        everyDays: parseInt($('repDays').value, 10) || 15,
        label: $('repLabel').value.trim(),
        devices: $('repDevices').value.split(',').map(function (v) { return v.trim(); }).filter(Boolean)
      })
    });
    $('repEmail').value = ''; $('repLabel').value = ''; $('repDevices').value = '';
    toast('Schedule added');
    await loadReports();
  } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
}

async function toggleReport(id, enable) {
  try {
    await api('/api/admin/reports/' + id, { method: 'PUT', body: JSON.stringify({ enabled: enable }) });
    await loadReports();
  } catch (e) { alert(e.message); }
}

async function deleteReport(id) {
  if (!confirm('Delete this schedule?')) return;
  try {
    await api('/api/admin/reports/' + id, { method: 'DELETE' });
    await loadReports();
  } catch (e) { alert(e.message); }
}

async function sendReport(id) {
  try {
    const r = await api('/api/admin/reports/' + id + '/send', { method: 'POST' });
    toast(r.message + ' (' + r.rows + ' visits)');
    await loadReports();
  } catch (e) { alert(e.message); }
}

function previewReport(id) {
  window.open('/api/admin/reports/' + id + '/preview?token=' + encodeURIComponent(token), '_blank');
}

/* ------------------------------------------------ the beta server ------ */

async function loadPeer() {
  try {
    const p = await api('/api/admin/peer/beta');
    $('peerUrl').value = p.url || '';
    $('peerUser').value = p.username || 'admin';
    const el = $('peerStatus');
    if (!p.configured) { el.textContent = 'Not configured yet.'; return; }
    const when = p.lastPublishAt ? new Date(p.lastPublishAt).toLocaleString() : 'never';
    el.innerHTML = p.lastError
      ? '<span style="color:var(--danger)">Last attempt failed: ' + esc(p.lastError) + '</span>'
      : 'Connected to ' + esc(p.url) + ' &middot; last sent: ' + esc(when);
  } catch (e) { /* non-fatal */ }
}

async function savePeer() {
  try {
    await api('/api/admin/peer/beta', {
      method: 'PUT',
      body: JSON.stringify({
        url: $('peerUrl').value.trim(),
        username: $('peerUser').value.trim(),
        password: $('peerPass').value
      })
    });
    $('peerPass').value = '';
    toast('Beta server saved');
    await loadPeer();
  } catch (e) { alert(e.message); }
}

async function testPeer() {
  $('peerStatus').textContent = 'Testing… a sleeping free server can take up to a minute.';
  try {
    const r = await api('/api/admin/peer/beta/test', { method: 'POST' });
    $('peerStatus').textContent = r.message +
      (r.durable ? ' Its database is durable.' : ' WARNING: its database is NOT durable.');
  } catch (e) {
    $('peerStatus').innerHTML = '<span style="color:var(--danger)">' + esc(e.message) + '</span>';
  }
}

async function forgetPeer() {
  if (!confirm('Forget the beta server connection?')) return;
  try {
    await api('/api/admin/peer/beta', { method: 'DELETE' });
    $('peerUrl').value = ''; $('peerPass').value = '';
    $('peerStatus').textContent = 'Not configured yet.';
    toast('Forgotten');
  } catch (e) { alert(e.message); }
}

async function unpublishVersion(channel) {
  const ch = (channel === 'beta') ? 'beta' : 'live';
  if (!confirm('Stop offering the ' + ch + ' update?')) return;
  try {
    await api('/api/admin/app/version?channel=' + ch, { method: 'DELETE' });
    toast('Unpublished ' + ch);
    await loadVersion();
  } catch (e) { alert(e.message); }
}

// ------------------------------------------------------------------ editor

function openEditor(id) {
  editing = id ? USERS.find(u => u.id === id) : null;
  $('editorTitle').textContent = editing ? 'Edit User' : 'Add User';
  $('editorErr').classList.add('hidden');

  // Renaming used to be impossible — the field was disabled, so a typo meant
  // deleting the profile and rebuilding every rule. The server now accepts a
  // new username and checks it for clashes.
  $('fUsername').value = editing ? editing.username : '';
  $('fUsername').disabled = false;
  $('fDisplayName').value = editing ? (editing.displayName || '') : '';
  $('fEmail').value = editing ? (editing.email || '') : '';
  $('fPassword').value = '';
  $('fPassLabel').textContent = editing
    ? 'New password (leave blank to keep current)' : 'Password';
  fillRoleSelects();
  $('fRole').value = editing ? editing.role : (ROLES[0] ? ROLES[0].id : 'student');
  $('fHome').value = editing ? (editing.homeUrl || '') : 'https://www.google.com/';
  $('fSearchEngine').value = editing ? (editing.searchEngine || 'google') : 'google';
  $('fMaxTabs').value = editing ? (editing.maxTabs || 8) : 8;
  $('fEnabled').checked = editing ? !!editing.enabled : true;
  $('fSyncSessions').checked = editing ? !!editing.syncWebSessions : false;
  $('btnClearSessions').classList.toggle(
    'hidden', !(editing && editing.hasSyncedSession));
  // Patterns are stored with an explicit "**." prefix when sub-domains are
  // included. The textarea shows the bare host and the checkbox carries that
  // meaning, so an administrator never has to type the syntax.
  const strip = list => (list || []).map(p => String(p).replace(/^\\*\\*\\./, ''));
  const allSubs = list =>
    (list || []).length > 0 && (list || []).every(p => String(p).startsWith('**.'));

  $('fAllowed').value = editing ? strip(editing.allowedPatterns).join('\\n') : '';
  $('fBlocked').value = editing ? strip(editing.blockedPatterns).join('\\n') : '';
  $('fAllowSubs').checked = editing ? allSubs(editing.allowedPatterns) : false;
  $('fBlockSubs').checked = editing ? allSubs(editing.blockedPatterns) : false;

  timeRules = editing ? JSON.parse(JSON.stringify(editing.timeRules || [])) : [];
  renderTimeRules();

  // Feature switches: the user's own, or the chosen role's defaults.
  const roleForPerms = roleById($('fRole').value);
  permState = editing
    ? { ...(editing.features || {}) }
    : { ...(roleForPerms ? roleForPerms.features : {}) };
  renderPerms();

  if ($('catSearch')) $('catSearch').value = '';
  showStep('account');

  if (editing && editing.categoryRules && Object.keys(editing.categoryRules).length) {
    catState = { ...editing.categoryRules };
  } else {
    catState = {};
    CATEGORIES.forEach(c => { catState[c.id] = c.def; });
  }
  renderCats();

  $('editorModal').classList.remove('hidden');
}

function closeEditor() { $('editorModal').classList.add('hidden'); }


/**
 * Shared category renderer used by BOTH the user editor and the role editor.
 *
 * Draws each category as a card with a colour-coded left edge and an
 * Allow/Alert/Block segmented control, grouped by theme and filterable.
 */
function paintCats(host, summaryHost, stateMap, filterText, onChange) {
  if (!host) return;
  const q = String(filterText || '').trim().toLowerCase();

  const groups = {};
  for (const c of CATEGORIES) {
    if (q && !(c.label.toLowerCase().includes(q) || (c.group || '').toLowerCase().includes(q))) {
      continue;
    }
    (groups[c.group] ||= []).push(c);
  }

  host.innerHTML = '';
  const entries = Object.entries(groups);
  if (!entries.length) {
    host.innerHTML = '<p class="muted" style="padding:14px 0">No categories match that search.</p>';
  }

  for (const [group, cats] of entries) {
    const g = document.createElement('div');
    g.className = 'cat-group';
    g.innerHTML = '<h4>' + esc(group) + '</h4>';

    for (const c of cats) {
      const cur = stateMap[c.id] || c.def;
      const row = document.createElement('div');
      row.className = 'cat is-' + cur;
      row.innerHTML =
        '<div class="cat-info">' +
          '<div class="cat-name">' + esc(c.label) + '</div>' +
          (c.description ? '<div class="cat-desc">' + esc(c.description) + '</div>' : '') +
        '</div>' +
        '<span class="seg">' +
          '<button data-c="' + c.id + '" data-a="allow" class="' + (cur === 'allow' ? 'on-allow' : '') + '">Allow</button>' +
          '<button data-c="' + c.id + '" data-a="alert" class="' + (cur === 'alert' ? 'on-alert' : '') + '">Alert</button>' +
          '<button data-c="' + c.id + '" data-a="block" class="' + (cur === 'block' ? 'on-block' : '') + '">Block</button>' +
        '</span>';
      g.appendChild(row);
    }
    host.appendChild(g);
  }

  host.querySelectorAll('button[data-c]').forEach(btn => {
    btn.onclick = () => onChange(btn.dataset.c, btn.dataset.a);
  });

  if (summaryHost) {
    const v = Object.values(stateMap);
    summaryHost.innerHTML =
      '<span class="pill a">' + v.filter(x => x === 'allow').length + ' allowed</span>' +
      '<span class="pill w">' + v.filter(x => x === 'alert').length + ' alert</span>' +
      '<span class="pill b">' + v.filter(x => x === 'block').length + ' blocked</span>';
  }
}

function renderCats() {
  paintCats($('catList'), $('catSummary'), catState,
            ($('catSearch') || {}).value || '',
            (id, action) => { catState[id] = action; renderCats(); });
}

/** Step navigation inside the user editor. */
function showStep(name) {
  ['account', 'rules', 'time', 'perms'].forEach(sn => {
    const panel = $('step' + sn.charAt(0).toUpperCase() + sn.slice(1));
    if (panel) panel.classList.toggle('on', sn === name);
  });
  document.querySelectorAll('.steps button').forEach(b =>
    b.classList.toggle('on', b.dataset.step === name));
}

/** Feature switches, rendered from one definition list. */
const PERMS = [
  ['forceHttps', 'Force HTTPS', 'Insecure http:// pages are upgraded to https://'],
  ['allowAddressBar', 'Allow typing addresses', 'Otherwise only links can be followed'],
  ['allowDownloads', 'Allow downloads', 'Save files from websites'],
  ['allowFileUpload', 'Allow file uploads', 'Send files to websites'],
  ['allowJavaScript', 'Allow JavaScript', 'Most sites need this'],
  ['allowThirdPartyCookies', 'Allow third-party cookies', 'Required for Google and other sign-ins'],
  ['allowOpenInExternalApp', 'Allow opening other apps', 'mailto:, tel: links'],
  ['safeBrowsingEnabled', 'Safe Browsing protection', 'Warns about malware and phishing'],
  ['allowTabs', 'Allow multiple tabs', 'Open more than one page at a time'],
  ['allowHistory', 'Allow browsing history', 'The user can see and search their own history'],
  ['allowCamera', 'Allow camera', 'Sites may ask permission to use the camera'],
  ['allowMicrophone', 'Allow microphone', 'Sites may ask permission to use the microphone'],
  ['allowDesktopMode', 'Allow desktop-site switch', 'Request the desktop version of a site'],
  ['lockSearchEngine', 'Lock the search engine', 'Only the engine chosen below may be used'],
  ['forceSafeSearch', 'Force SafeSearch', 'SafeSearch is always on and cannot be turned off']
];

function renderPerms() {
  const host = $('permGrid');
  if (!host) return;
  host.innerHTML = PERMS.map(([key, title, desc]) =>
    '<label class="switch-card">' +
      '<input type="checkbox" data-perm="' + key + '"' + (permState[key] ? ' checked' : '') + '>' +
      '<span><b>' + esc(title) + '</b><span>' + esc(desc) + '</span></span>' +
    '</label>').join('');
  host.querySelectorAll('input[data-perm]').forEach(cb => {
    cb.onchange = () => { permState[cb.dataset.perm] = cb.checked; };
  });
}

/** Applying a role fills the rule fields with that role's defaults. */
function onRoleChanged() {
  if (editing) return;              // never stomp an existing user's own rules
  const role = roleById($('fRole').value);
  if (!role) return;
  catState = { ...role.categoryRules };
  permState = { ...role.features };
  $('fHome').value = role.homeUrl || '';
  renderCats();
  renderPerms();
}

function setAllCats(action) {
  CATEGORIES.forEach(c => { catState[c.id] = action; });
  renderCats();
}

// ---------------- time rules ----------------

function addTimeRule() {
  timeRules.push({
    pattern: '', days: [1,2,3,4,5], startMinute: 960, endMinute: 1080, enabled: true
  });
  renderTimeRules();
}

function renderTimeRules() {
  const host = $('timeRules');
  host.innerHTML = '';
  if (!timeRules.length) {
    host.innerHTML = '<p class="muted">No time rules. The site list and categories apply at all hours.</p>';
    return;
  }
  timeRules.forEach((r, i) => {
    const el = document.createElement('div');
    el.className = 'time-rule';
    el.innerHTML = \`
      <div class="row">
        <div style="flex:2">
          <label>Website</label>
          <input value="\${esc(r.pattern)}" onchange="timeRules[\${i}].pattern=this.value">
        </div>
        <div>
          <label>From</label>
          <input type="time" value="\${hhmm(r.startMinute)}"
                 onchange="timeRules[\${i}].startMinute=toMins(this.value)">
        </div>
        <div>
          <label>To</label>
          <input type="time" value="\${hhmm(r.endMinute)}"
                 onchange="timeRules[\${i}].endMinute=toMins(this.value)">
        </div>
      </div>
      <label>Days</label>
      <div class="days">
        \${DAY_NAMES.map((d, idx) => \`
          <button class="\${r.days.includes(idx) ? 'on' : ''}"
                  onclick="toggleDay(\${i},\${idx})">\${d}</button>\`).join('')}
        <button class="danger" style="margin-left:auto"
                onclick="timeRules.splice(\${i},1);renderTimeRules()">Remove</button>
      </div>\`;
    host.appendChild(el);
  });
}

function toggleDay(ruleIdx, day) {
  const r = timeRules[ruleIdx];
  const pos = r.days.indexOf(day);
  if (pos >= 0) r.days.splice(pos, 1); else r.days.push(day);
  r.days.sort();
  renderTimeRules();
}

// ---------------- save ----------------

async function saveUser() {
  const err = $('editorErr');
  err.classList.add('hidden');

  const lines = v => v.split('\\n').map(s => s.trim()).filter(Boolean);

  /** Applies the "include sub-domains" checkbox to a list of hosts. */
  const withSubs = (list, include) => list.map(p => {
    const bare = p.replace(/^\\*+\\./, '');
    if (!include) return bare;
    // A path rule cannot take the prefix; leave those alone.
    return bare.includes('/') ? bare : '**.' + bare;
  });

  for (const r of timeRules) {
    if (!r.pattern.trim()) { return showErr('Every time rule needs a website.'); }
    if (r.endMinute <= r.startMinute) {
      return showErr(\`Time rule for "\${r.pattern}": end time must be after start time.\`);
    }
    if (!r.days.length) { return showErr(\`Time rule for "\${r.pattern}": pick at least one day.\`); }
  }

  const body = {
    username: $('fUsername').value.trim(),
    displayName: $('fDisplayName').value.trim(),
    email: $('fEmail').value.trim(),
    role: $('fRole').value,
    enabled: $('fEnabled').checked,
    syncWebSessions: $('fSyncSessions').checked,
    mode: 'category',
    // Add the "**." prefix here, once, so the stored pattern says exactly what
    // it means and the device needs no extra flag to interpret it.
    allowedPatterns: withSubs(lines($('fAllowed').value), $('fAllowSubs').checked),
    blockedPatterns: withSubs(lines($('fBlocked').value), $('fBlockSubs').checked),
    searchEngine: $('fSearchEngine').value,
    maxTabs: parseInt($('fMaxTabs').value, 10) || 8,
    categoryRules: catState,
    uncategorizedAction: catState['uncategorized'] || 'alert',
    timeRules,
    features: permState,
    homeUrl: $('fHome').value.trim()
  };
  const pw = $('fPassword').value;
  if (pw) body.password = pw;

  try {
    if (editing) {
      await api('/api/admin/users/' + editing.id, { method: 'PUT', body: JSON.stringify(body) });
    } else {
      if (!body.password) return showErr('Password is required for a new user.');
      await api('/api/admin/users', { method: 'POST', body: JSON.stringify(body) });
    }
    closeEditor();
    await refresh();
    toast('Saved — phones will pick this up automatically');
  } catch (e) {
    showErr(e.message);
  }

  function showErr(m) { err.textContent = m; err.classList.remove('hidden'); }
}

async function clearSessions() {
  if (!editing) return;
  if (!confirm('Sign this profile out of every website on all its phones?')) return;
  try {
    await api('/api/admin/users/' + editing.id + '/sessions/clear', { method: 'POST' });
    $('btnClearSessions').classList.add('hidden');
    toast('Website logins cleared');
    await refresh();
  } catch (e) { alert(e.message); }
}

async function removeUser(id, name) {
  if (!confirm(\`Delete "\${name}"? This cannot be undone.\`)) return;
  try {
    await api('/api/admin/users/' + id, { method: 'DELETE' });
    await refresh();
    toast('User deleted');
  } catch (e) { alert(e.message); }
}

// ------------------------------------------------------------------ start

if (token) {
  boot().catch(() => logout());
}
`;

// ===================================================================
// SECTION 5 — API + routes
// ===================================================================
/**
 * SMVS Browser — cloud backend + admin dashboard.
 *
 * Two audiences:
 *   1. The admin website (public/index.html) — a person managing users.
 *   2. The Android app  — devices fetching their rules.
 *
 * Endpoints used by the DEVICE:
 *   POST /api/auth/login     -> sign in, returns session + policy
 *   GET  /api/me/policy      -> re-fetch policy (called on every app resume)
 *   POST /api/auth/logout
 *   POST /api/activity       -> report blocked/alerted visits
 *
 * Endpoints used by the WEBSITE (all require an admin token):
 *   POST   /api/admin/login
 *   GET    /api/admin/users
 *   POST   /api/admin/users
 *   PUT    /api/admin/users/:id
 *   DELETE /api/admin/users/:id
 *   GET    /api/admin/activity
 *   GET    /api/admin/categories
 */


const app = express();
const PORT = process.env.PORT || 3000;

// A stable secret keeps sessions valid across restarts. Set JWT_SECRET in the
// host's environment variables for production.
const JWT_SECRET = process.env.JWT_SECRET || 'smvs-browser-dev-secret-change-me';

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.get('/app.js', (_req, res) => {
  res.type('application/javascript').send(DASHBOARD_JS);
});

// ---------------------------------------------------------------- helpers

function db() { return load(); }

function publicUser(u) {
  // Never send the password hash or the encrypted cookie jar to the browser.
  const { passwordHash, sessionBlob, ...rest } = u;
  return { ...rest, hasSyncedSession: !!u.sessionBlob };
}

/**
 * Builds the policy sent to a device.
 *
 * IMPORTANT: `features` is merged over `defaultFeatures()` rather than used
 * as-is. Profiles created by older builds were stored with
 * `allowThirdPartyCookies: false`, and federated sign-in (Google, Microsoft,
 * most SSO) cannot work without third-party cookies — the browser is bounced
 * back to the login page and Google reports "CookieMismatch".
 *
 * Simply changing the default was not enough: existing records still carried
 * the old value. Merging repairs them on read, and `migrateFeatures()` below
 * repairs them on disk.
 */
/**
 * Builds the policy a device receives.
 *
 * ### Roles are LIVE, not a one-time copy
 * The first version of the role feature copied a role's rules onto a user at
 * creation time. Editing the role afterwards changed nothing for people who
 * already had it — an administrator would block Entertainment on the "Mukto"
 * role and the "stk" account would carry on browsing it. That is the opposite
 * of what a role is for.
 *
 * Now the role is resolved on every read and layered underneath the user:
 *
 *     defaults  <  role  <  per-user overrides
 *
 * So a role edit reaches every holder immediately, while a deliberate
 * per-user exception still wins. `userOverrides` records which keys were set
 * for this specific person, so "student may use YouTube" survives a role edit
 * but everything untouched keeps following the role.
 */
/**
 * Works out which parts of a submitted user differ from their role.
 *
 * Only these are treated as per-user exceptions; everything else keeps
 * following the role, so a later role edit reaches this account.
 */
function diffOverrides(body, roleRules) {
  const ov = { categoryRules: [] };

  if (body.categoryRules && roleRules && roleRules.rules) {
    for (const [key, val] of Object.entries(body.categoryRules)) {
      if (roleRules.rules[key] !== val) ov.categoryRules.push(key);
    }
  }
  if (body.homeUrl !== undefined && body.homeUrl !== roleRules.homeUrl) {
    ov.homeUrl = true;
  }
  if (body.uncategorizedAction !== undefined &&
      body.uncategorizedAction !== roleRules.uncategorizedAction) {
    ov.uncategorizedAction = true;
  }
  if (body.features) {
    const base = roleRules.features || defaultFeatures();
    if (Object.entries(body.features).some(([k, v]) => base[k] !== v)) {
      ov.features = true;
    }
  }
  return ov;
}

function policyOf(u) {
  const role = findRole(u.role);
  const ov = u.userOverrides || {};

  // --- category rules: role first, then only the keys pinned to this user ---
  const roleCats = (role && role.categoryRules) || {};
  const userCats = u.categoryRules || {};
  let categoryRules;

  if (ov.categoryRules && ov.categoryRules.length) {
    // Selected categories were customised for this user; keep just those.
    categoryRules = { ...roleCats };
    for (const key of ov.categoryRules) {
      if (key in userCats) categoryRules[key] = userCats[key];
    }
  } else if (role) {
    categoryRules = { ...roleCats };
  } else {
    // No role record (legacy data) — fall back to whatever the user has.
    categoryRules = { ...userCats };
  }

  const pick = (field, fallback) => {
    if (ov[field] && u[field] !== undefined) return u[field];      // user pinned
    if (role && role[field] !== undefined) return role[field];      // role value
    return u[field] !== undefined ? u[field] : fallback;
  };

  // Last line of defence: a category missing from the map would be treated as
  // "allow" on the device. Fill any gap with the category's own default so a
  // partial record can never silently unblock content.
  for (const c of CATEGORIES) {
    if (!categoryRules[c.id]) categoryRules[c.id] = c.def;
  }

  return {
    mode: u.mode || 'category',

    /*
      The address every device should be using.

      Travels with the policy rather than in its own call: devices already
      fetch this on every launch and hold a long poll for changes, so a new
      address lands within a second of the admin saving it — with no extra
      request and nothing new to keep working.
    */
    serverUrl: db().managedServerUrl || '',

    // Site lists and time rules are always per-user: they name specific
    // websites, which is not something a shared role should dictate.
    allowedPatterns: u.allowedPatterns || [],
    blockedPatterns: u.blockedPatterns || [],
    timeRules: u.timeRules || [],
    categoryRules,
    uncategorizedAction: pick('uncategorizedAction', 'alert'),
    features: {
      ...defaultFeatures(),
      ...((role && role.features) || {}),
      ...(ov.features ? (u.features || {}) : {})
    },
    homeUrl: pick('homeUrl', 'https://www.google.com/'),
    // Which search engine the browser may use. Locked by default, so a
    // student cannot switch to an engine that has no SafeSearch.
    searchEngine: validSearchEngine(pick('searchEngine', 'google')),
    maxTabs: Number(pick('maxTabs', 8)) || 8
  };
}

function defaultFeatures() {
  return {
    allowDownloads: false,
    allowFileUpload: false,
    allowIncognito: false,
    allowJavaScript: true,
    allowThirdPartyCookies: true,   // required for Google / SSO sign-in
    forceHttps: true,
    allowAddressBar: true,
    allowOpenInExternalApp: false,
    safeBrowsingEnabled: true,

    // --- browser features (added with the Chrome-style rebuild) ---
    allowTabs: true,                // multiple tabs
    allowHistory: true,             // the History screen
    allowCamera: false,             // sites may ask; off means never
    allowMicrophone: false,
    allowDesktopMode: true,         // the desktop/mobile view switch
    lockSearchEngine: true,         // only the chosen engine may be used
    forceSafeSearch: true           // SafeSearch cannot be turned off
  };
}

/**
 * Search engines an administrator can choose from.
 *
 * Locking this down is only meaningful if every option supports a SafeSearch
 * parameter the browser can force on, so the list is deliberately short.
 */
const SEARCH_ENGINES = [
  { id: 'google', label: 'Google', url: 'https://www.google.com/search?q=%s&safe=active' },
  { id: 'bing', label: 'Bing', url: 'https://www.bing.com/search?q=%s&adlt=strict' },
  { id: 'duckduckgo', label: 'DuckDuckGo', url: 'https://duckduckgo.com/?q=%s&kp=1' },
  { id: 'yahoo', label: 'Yahoo', url: 'https://search.yahoo.com/search?p=%s&vm=r' },
  { id: 'ecosia', label: 'Ecosia', url: 'https://www.ecosia.org/search?q=%s&safesearch=1' }
];

function validSearchEngine(id) {
  return SEARCH_ENGINES.some(e => e.id === id) ? id : 'google';
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  /*
    A header is the normal way in. The one exception is a link opened in a
    new browser tab — the report preview — which cannot carry one, so a
    ?token= is accepted as well. It is the same signed admin token with the
    same expiry; nothing is loosened except where it may travel.
  */
  const token = header.startsWith('Bearer ')
    ? header.slice(7)
    : (typeof req.query.token === 'string' && req.query.token ? req.query.token : null);
  if (!token) return res.status(401).json({ message: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.kind !== 'admin') throw new Error('not admin');
    req.admin = payload;
    next();
  } catch {
    res.status(401).json({ message: 'Session expired. Please sign in again.' });
  }
}

function deviceAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.kind !== 'device') throw new Error('not device');
    req.device = payload;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid session' });
  }
}

// ---------------------------------------------------------------- seeding

/**
 * One-time repair of profiles written by older builds.
 *
 * Third-party cookies were originally defaulted to false. That silently broke
 * every federated sign-in (Google/Microsoft/SSO) for profiles created before
 * the default changed. Flip only that flag, and only where it is still false,
 * so an administrator who deliberately disables it later is not overridden on
 * every restart.
 */
function migrateFeatures() {
  const d = db();
  let changed = 0;

  for (const u of d.users) {
    u.features = { ...defaultFeatures(), ...(u.features || {}) };
    if (u.features.allowThirdPartyCookies === false && !u.thirdPartyCookiesMigrated) {
      u.features.allowThirdPartyCookies = true;
      u.thirdPartyCookiesMigrated = true;   // never force it again
      changed++;
    }
  }

  if (changed) {
    console.log(`[migrate] enabled third-party cookies for ${changed} profile(s) so sign-in works`);
    flush();
  }
}

function seed() {
  const d = db();
  let changed = false;

  if (d.admins.length === 0) {
    const pw = process.env.ADMIN_PASSWORD || 'admin123';
    d.admins.push({
      id: 'adm-1',
      username: process.env.ADMIN_USERNAME || 'admin',
      passwordHash: bcrypt.hashSync(pw, 10),
      createdAt: Date.now()
    });
    console.log(`[seed] dashboard admin created (user: ${d.admins[0].username})`);
    changed = true;
  }

  if (!Array.isArray(d.roles) || d.roles.length === 0) {
    d.roles = builtInRoles();
    console.log('[seed] created 4 built-in roles');
    changed = true;
  }

  if (d.users.length === 0) {
    for (const role of ['student', 'staff']) {
      const t = templateFor(role);
      d.users.push({
        id: `u-${role}`,
        username: role,
        displayName: role.charAt(0).toUpperCase() + role.slice(1) + ' User',
        email: `${role}@smvs.local`,
        role,
        passwordHash: bcrypt.hashSync(role, 10),
        enabled: true,
        mode: 'category',
        allowedPatterns: [],
        blockedPatterns: [],
        categoryRules: t.rules,
        uncategorizedAction: t.rules.uncategorized || 'alert',
        timeRules: [],
        syncWebSessions: false,
        sessionBlob: null,
        sessionVersion: 0,
        sessionUpdatedAt: 0,
        features: defaultFeatures(),
        homeUrl: t.homeUrl,
        createdAt: Date.now(),
        lastLoginAt: 0,
        lastSyncAt: 0
      });
    }
    console.log('[seed] demo profiles created: student / staff');
    changed = true;
  }

  if (changed) flush();
}

// ---------------------------------------------------------------- device API

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  const d = db();
  const user = d.users.find(
    u => u.username.toLowerCase() === String(username).trim().toLowerCase()
  );
  if (!user) return res.status(401).json({ message: 'Invalid username or password.' });
  if (!user.enabled) {
    return res.status(403).json({ message: 'This account has been disabled by your administrator.' });
  }
  if (!bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ message: 'Invalid username or password.' });
  }

  user.lastLoginAt = Date.now();

  /*
    Device registration.

    Apps now send a stable `deviceId` chosen at install time, so a computer
    that is reinstalled updates its existing row instead of appearing twice.
    The id is matched first; the name is only a fallback for older apps.

    The administrator is the sole authority on a device's name: if the row
    already carries one, the server keeps it and tells the app, which adopts
    it. That is what stops a user renaming their own machine.
  */
  let deviceRow = null;
  const sentId = String(req.body.deviceId || '').slice(0, 64);
  const sentName = String(req.body.deviceName || '').slice(0, 60);

  if (sentId) {
    deviceRow = d.devices.find(x => x.userId === user.id && x.deviceId === sentId) || null;
  }
  if (!deviceRow && sentName) {
    deviceRow = d.devices.find(x => x.userId === user.id && x.name === sentName) || null;
    // Adopt the id so the next reinstall is recognised.
    if (deviceRow && sentId) deviceRow.deviceId = sentId;
  }

  if (deviceRow) {
    deviceRow.lastSeen = Date.now();
    if (req.body.platform) deviceRow.platform = String(req.body.platform).slice(0, 20);
  } else if (sentName || sentId) {
    deviceRow = {
      userId: user.id,
      deviceId: sentId,
      name: sentName || 'Unnamed device',
      platform: String(req.body.platform || '').slice(0, 20),
      lastSeen: Date.now(),
      createdAt: Date.now()
    };
    d.devices.push(deviceRow);
  }

  // The name the DASHBOARD holds wins, so an admin rename reaches the device.
  const deviceName = (deviceRow && deviceRow.name) || sentName;
  save();

  // No expiry: the app stays signed in until the user taps Log Out.
  // `dev` rides along so /api/activity knows the source without the app
  // having to send it — and without a device being able to claim to be
  // another one, since the token is signed.
  const token = jwt.sign({ kind: 'device', sub: user.id, dev: deviceName }, JWT_SECRET);

  res.json({
    accessToken: token,
    // Echoed so the app can adopt an administrator's rename.
    device: deviceRow ? { name: deviceRow.name, deviceId: deviceRow.deviceId || '' } : null,
    expiresAtMillis: 0,
    user: {
      id: user.id,
      displayName: user.displayName,
      email: user.email,
      role: user.role
    },
    policy: policyOf(user)
  });
});

app.get('/api/me/policy', deviceAuth, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.device.sub);
  if (!user) return res.status(404).json({ message: 'Account no longer exists.' });
  if (!user.enabled) return res.status(403).json({ message: 'Account disabled.' });

  user.lastSyncAt = Date.now();
  save();
  res.json({ policy: policyOf(user), rev: revisionFor(user) });
});

/* ------------------------------------------------------------------ *
 *  Instant rule delivery (long polling)
 *
 *  Devices used to poll every 60 s (Android) or 5 min (desktop), so an
 *  administrator could change a rule and watch nothing happen for minutes.
 *  Polling faster would mean 50 devices hammering a free Render dyno.
 *
 *  Instead the device asks "tell me when revision X changes" and the server
 *  simply does not answer until it does. The reply then arrives within
 *  milliseconds of the admin pressing Save. If nothing changes the request
 *  returns `changed:false` after 25 s and the device asks again — one open
 *  connection per device, near-zero traffic, and no WebSocket support needed
 *  (Render's free tier proxies these fine).
 * ------------------------------------------------------------------ */

/** Everyone currently parked on /api/me/policy/wait, keyed by user id. */
const policyWaiters = new Map();

/**
 * A number that changes whenever anything affecting this user's rules changes.
 * Derived from the user record and their role, so no extra bookkeeping is
 * needed at each of the many places that edit rules.
 */
function revisionFor(user) {
  const role = findRole(user.role);
  return Math.max(
    Number(user.rulesUpdatedAt) || 0,
    Number(user.updatedAt) || 0,
    (role && Number(role.updatedAt)) || 0,
    user.enabled === false ? 1 : 0
  );
}

/**
 * Wakes every device belonging to `userIds` (or all devices when omitted).
 * Called from the admin endpoints right after a rule is saved.
 */
function notifyPolicyChanged(userIds) {
  const ids = userIds && userIds.length
    ? userIds
    : Array.from(policyWaiters.keys());

  for (const id of ids) {
    const waiters = policyWaiters.get(id);
    if (!waiters) continue;
    policyWaiters.delete(id);
    for (const w of waiters) {
      clearTimeout(w.timer);
      try { w.send(); } catch { /* client vanished */ }
    }
  }
}

/** Marks a user's rules as changed and pushes to their devices at once. */
function bumpUser(user) {
  if (!user) return;
  user.rulesUpdatedAt = Date.now();
  notifyPolicyChanged([user.id]);
}

/** Same, for every user holding a given role. */
function bumpRole(roleId) {
  const d = db();
  const now = Date.now();
  const role = (d.roles || []).find(r => r.id === roleId || r.name === roleId);
  if (role) role.updatedAt = now;
  const affected = (d.users || [])
    .filter(u => u.role === roleId || (role && u.role === role.id))
    .map(u => { u.rulesUpdatedAt = now; return u.id; });
  notifyPolicyChanged(affected);
}

app.get('/api/me/policy/wait', deviceAuth, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.device.sub);
  if (!user) return res.status(404).json({ message: 'Account no longer exists.' });
  if (!user.enabled) return res.status(403).json({ message: 'Account disabled.' });

  const since = Number(req.query.rev) || 0;
  const current = revisionFor(user);

  // Already stale — answer immediately, no waiting.
  if (current > since) {
    return res.json({ changed: true, rev: current, policy: policyOf(user) });
  }

  let done = false;
  const send = () => {
    if (done) return;
    done = true;
    // Re-read the database rather than closing over the snapshot taken when
    // the request arrived: by the time this runs, the admin has just written
    // to it, and that write is the whole reason we are replying.
    const fresh = db().users.find(u => u.id === req.device.sub);
    if (!fresh) return res.json({ changed: true, revoked: true });
    if (!fresh.enabled) return res.json({ changed: true, revoked: true });
    res.json({ changed: true, rev: revisionFor(fresh), policy: policyOf(fresh) });
  };

  // Nothing happened in 25 s: reply so the proxy never times the socket out.
  const timer = setTimeout(() => {
    if (done) return;
    done = true;
    const list = policyWaiters.get(user.id);
    if (list) {
      const i = list.indexOf(entry);
      if (i >= 0) list.splice(i, 1);
      if (!list.length) policyWaiters.delete(user.id);
    }
    res.json({ changed: false, rev: current });
  }, 25000);

  const entry = { send, timer };
  if (!policyWaiters.has(user.id)) policyWaiters.set(user.id, []);
  policyWaiters.get(user.id).push(entry);

  // Client hung up (app closed, laptop slept) — stop tracking it.
  req.on('close', () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    const list = policyWaiters.get(user.id);
    if (list) {
      const i = list.indexOf(entry);
      if (i >= 0) list.splice(i, 1);
      if (!list.length) policyWaiters.delete(user.id);
    }
  });
});

app.post('/api/auth/logout', deviceAuth, (_req, res) => res.json({ ok: true }));

app.post('/api/activity', deviceAuth, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.device.sub);
  if (!user) return res.status(404).json({ message: 'Unknown user' });

  const entries = Array.isArray(req.body.entries) ? req.body.entries : [];
  for (const e of entries.slice(0, 100)) {
    d.activity.unshift({
      userId: user.id,
      username: user.username,
      host: String(e.host || '').slice(0, 200),
      url: String(e.url || '').slice(0, 500),
      category: String(e.category || 'uncategorized'),
      action: e.action === 'block' ? 'block' : 'alert',
      // Why it happened — "time window", "block list", "search" and so on.
      // Without this the log could only show the category, which is what made
      // a blocked site appear as merely alerted.
      reason: String(e.reason || '').slice(0, 120),
      // Which device reported this. Read from the signed token rather than
      // the request body, so it cannot be spoofed.
      device: req.device.dev || '',
      timestamp: Number(e.timestamp) || Date.now()
    });
  }
  d.activity = d.activity.slice(0, 1000);
  save();
  res.json({ ok: true, stored: entries.length });
});

// ---------------------------------------------------------------- admin API

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  const d = db();
  const admin = d.admins.find(
    a => a.username.toLowerCase() === String(username || '').trim().toLowerCase()
  );
  if (!admin || !bcrypt.compareSync(String(password || ''), admin.passwordHash)) {
    return res.status(401).json({ message: 'Invalid credentials.' });
  }
  const token = jwt.sign({ kind: 'admin', sub: admin.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: admin.username });
});

app.get('/api/admin/categories', requireAdmin, (_req, res) => {
  res.json({ categories: CATEGORIES });
});

app.get('/api/admin/users', requireAdmin, (_req, res) => {
  const d = db();
  res.json({
    users: d.users.map(publicUser),
    stats: {
      total: d.users.length,
      active: d.users.filter(u => u.enabled).length,
      disabled: d.users.filter(u => !u.enabled).length
    }
  });
});

app.post('/api/admin/users', requireAdmin, (req, res) => {
  const d = db();
  const b = req.body || {};
  const username = String(b.username || '').trim();

  if (!username) return res.status(400).json({ message: 'Username is required.' });
  if (!b.password || String(b.password).length < 4) {
    return res.status(400).json({ message: 'Password must be at least 4 characters.' });
  }
  if (d.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ message: `Username "${username}" already exists.` });
  }

  const role = findRole(b.role) ? String(b.role) : 'student';
  const t = rulesForRole(role);

  const user = {
    id: `u-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    username,
    displayName: String(b.displayName || username).trim(),
    email: String(b.email || '').trim(),
    role,
    passwordHash: bcrypt.hashSync(String(b.password), 10),
    enabled: b.enabled !== false,
    mode: b.mode || 'category',
    allowedPatterns: b.allowedPatterns || [],
    blockedPatterns: b.blockedPatterns || [],
    // Rules are resolved from the role at read time (see policyOf). We store
    // whatever was sent so a deliberate per-user exception can be kept, and
    // record in `userOverrides` which fields were actually customised.
    categoryRules: b.categoryRules || t.rules,
    uncategorizedAction: b.uncategorizedAction || t.uncategorizedAction,
    userOverrides: diffOverrides(b, t),
    timeRules: (b.timeRules || []).map(scheduleUtil.normalise),
    syncWebSessions: b.syncWebSessions === true,
    sessionBlob: null,
    sessionVersion: 0,
    sessionUpdatedAt: 0,
    features: { ...defaultFeatures(), ...t.features, ...(b.features || {}) },
    homeUrl: b.homeUrl || t.homeUrl,
    searchEngine: validSearchEngine(b.searchEngine || t.searchEngine),
    maxTabs: Math.max(1, Math.min(20, parseInt(b.maxTabs, 10) || 8)),
    createdAt: Date.now(),
    lastLoginAt: 0,
    lastSyncAt: 0
  };

  d.users.push(user);
  save();
  res.status(201).json({ user: publicUser(user) });
});

app.put('/api/admin/users/:id', requireAdmin, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ message: 'User not found.' });

  const b = req.body || {};

  // Renaming was impossible before: the field was disabled in the dashboard
  // and ignored here, so a typo in a username could only be fixed by deleting
  // the account and building it again from scratch.
  if (b.username !== undefined) {
    const username = String(b.username).trim();
    if (!username) return res.status(400).json({ message: 'Username cannot be empty.' });
    const clash = d.users.some(
      u => u.id !== user.id && u.username.toLowerCase() === username.toLowerCase()
    );
    if (clash) {
      return res.status(409).json({ message: `Username "${username}" already exists.` });
    }
    user.username = username;
  }

  if (b.displayName !== undefined) user.displayName = String(b.displayName).trim();
  if (b.email !== undefined) user.email = String(b.email).trim();
  if (b.role !== undefined && findRole(b.role)) {
    const changed = user.role !== String(b.role);
    user.role = String(b.role);
    if (changed) {
      // Overrides were relative to the OLD role; carrying them across would
      // silently re-apply rules the admin never chose for the new role.
      user.userOverrides = { categoryRules: [] };
    }
  }
  if (b.enabled !== undefined) user.enabled = !!b.enabled;
  if (b.password) {
    if (String(b.password).length < 4) {
      return res.status(400).json({ message: 'Password must be at least 4 characters.' });
    }
    user.passwordHash = bcrypt.hashSync(String(b.password), 10);
  }
  if (b.mode !== undefined) user.mode = b.mode;
  if (b.allowedPatterns !== undefined) user.allowedPatterns = b.allowedPatterns;
  if (b.blockedPatterns !== undefined) user.blockedPatterns = b.blockedPatterns;
  if (b.categoryRules !== undefined) {
    /*
      Merge, never replace.

      The dashboard posts the full set of 37 categories, but anything else
      talking to this API — a script, a future screen, a partial save — may
      send only the categories it means to change. Assigning the body
      wholesale silently dropped the other 36, and because the missing keys
      then fell back to the role, an administrator's change appeared to be
      accepted (HTTP 200) and yet never reached the device.

      Merging keeps untouched categories exactly as they were, and
      `completeCategoryRules` fills any gap from the role/defaults so the
      stored map is always whole.
    */
    user.categoryRules = completeCategoryRules(
      { ...(user.categoryRules || {}), ...b.categoryRules },
      user.categoryRules
    );
  }
  if (b.uncategorizedAction !== undefined) user.uncategorizedAction = b.uncategorizedAction;
  if (b.features !== undefined) user.features = { ...defaultFeatures(), ...b.features };
  if (b.homeUrl !== undefined) user.homeUrl = b.homeUrl;
  if (b.searchEngine !== undefined) user.searchEngine = validSearchEngine(b.searchEngine);
  if (b.maxTabs !== undefined) user.maxTabs = Math.max(1, Math.min(20, parseInt(b.maxTabs, 10) || 8));
  if (b.syncWebSessions !== undefined) {
    const turningOff = user.syncWebSessions && !b.syncWebSessions;
    user.syncWebSessions = !!b.syncWebSessions;
    // Turning it off must not leave a copy of the cookies on the server.
    if (turningOff) {
      user.sessionBlob = null;
      user.sessionVersion = (user.sessionVersion || 0) + 1;
      user.sessionUpdatedAt = Date.now();
    }
  }

  if (b.timeRules !== undefined) {
    const cleaned = [];
    for (const r of b.timeRules) {
      const errors = scheduleUtil.validate(r);
      if (errors.length) return res.status(400).json({ message: errors[0] });
      cleaned.push(scheduleUtil.normalise(r));
    }
    user.timeRules = cleaned;
  }

  // Re-derive which fields are genuine per-user exceptions. Anything now
  // matching the role stops being an override, so future role edits reach it.
  const roleRules = rulesForRole(user.role);
  user.userOverrides = diffOverrides(
    {
      // Compare the user's FULL stored map against the role, not just the
      // keys this request happened to mention. Passing only the body meant a
      // partial save wiped out overrides the admin had set earlier.
      categoryRules: b.categoryRules !== undefined ? user.categoryRules : undefined,
      homeUrl: b.homeUrl !== undefined ? b.homeUrl : undefined,
      uncategorizedAction:
        b.uncategorizedAction !== undefined ? b.uncategorizedAction : undefined,
      features: b.features !== undefined ? b.features : undefined
    },
    roleRules
  );

  bumpUser(user);          // wake this user's devices immediately
  save();
  res.json({ user: publicUser(user) });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const d = db();
  const idx = d.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'User not found.' });

  const [removed] = d.users.splice(idx, 1);
  // The profile is gone; its device registrations and log entries would
  // otherwise linger as orphans in the dashboard.
  d.devices = d.devices.filter(dev => dev.userId !== removed.id);
  d.activity = d.activity.filter(a => a.userId !== removed.id);

  save();
  res.json({ ok: true });
});

/**
 * Copies an existing profile.
 *
 * Setting up a class means creating twenty accounts with identical rules. Doing
 * that through the four-step editor twenty times is the sort of thing that
 * makes an administrator give up, so one click clones everything except the
 * identity and the saved cookies.
 */
app.post('/api/admin/users/:id/duplicate', requireAdmin, (req, res) => {
  const d = db();
  const source = d.users.find(u => u.id === req.params.id);
  if (!source) return res.status(404).json({ message: 'User not found.' });

  const b = req.body || {};
  const username = String(b.username || '').trim();
  if (!username) return res.status(400).json({ message: 'A username for the copy is required.' });
  if (!b.password || String(b.password).length < 4) {
    return res.status(400).json({ message: 'Password must be at least 4 characters.' });
  }
  if (d.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ message: `Username "${username}" already exists.` });
  }

  const copy = {
    ...JSON.parse(JSON.stringify(source)),
    id: `u-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    username,
    displayName: String(b.displayName || username).trim(),
    email: String(b.email || '').trim(),
    passwordHash: bcrypt.hashSync(String(b.password), 10),
    // Never carry a login session across to a different person.
    sessionBlob: null,
    sessionVersion: 0,
    sessionUpdatedAt: 0,
    createdAt: Date.now(),
    lastLoginAt: 0,
    lastSyncAt: 0
  };

  d.users.push(copy);
  save();
  res.status(201).json({ user: publicUser(copy) });
});

/**
 * Enable or disable in one call, so the dashboard can offer a switch in the
 * user list without opening the whole editor.
 */
app.post('/api/admin/users/:id/enabled', requireAdmin, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ message: 'User not found.' });

  user.enabled = req.body.enabled !== false;
  bumpUser(user);          // a disabled account must be cut off at once
  save();
  res.json({ user: publicUser(user) });
});

// ---------------- roles ----------------
//
// Roles are records, not constants. An administrator can create "Teacher",
// "Class 10", "Accounts" — whatever matches their organisation — and give each
// one its own category rules, feature switches and home page. Creating a user
// with that role copies those rules as the starting point.

app.get('/api/admin/roles', requireAdmin, (_req, res) => {
  const d = db();
  const counts = {};
  for (const u of d.users) counts[u.role] = (counts[u.role] || 0) + 1;
  res.json({
    roles: d.roles.map(r => ({ ...r, userCount: counts[r.id] || 0 }))
  });
});

/**
 * Ensures a rule map covers every known category.
 *
 * A partial map is dangerous: any category the device does not find falls back
 * to "allow", so a half-filled role silently unblocks things. The dashboard
 * always sends all 37, but the API is public to the admin token and an
 * incomplete PUT must not create a hole.
 */
function completeCategoryRules(partial, fallback) {
  const base = fallback || {};
  const out = {};
  for (const c of CATEGORIES) {
    out[c.id] = (partial && partial[c.id]) || base[c.id] || c.def;
  }
  return out;
}

app.post('/api/admin/roles', requireAdmin, (req, res) => {
  const b = req.body || {};
  const label = String(b.label || '').trim();
  if (!label) return res.status(400).json({ message: 'Role name is required.' });

  const id = normaliseRoleId(b.id || label);
  if (!id) {
    return res.status(400).json({ message: 'Role name must contain letters or numbers.' });
  }

  const d = db();
  if (d.roles.some(r => r.id === id)) {
    return res.status(409).json({ message: `A role called "${label}" already exists.` });
  }

  // Start from an existing role when asked, so building a variant is quick.
  const basis = b.copyFrom ? findRole(b.copyFrom) : null;

  const role = {
    id,
    label,
    description: String(b.description || '').trim().slice(0, 200),
    builtIn: false,
    categoryRules: completeCategoryRules(
      b.categoryRules,
      basis ? basis.categoryRules : templateFor('student').rules
    ),
    uncategorizedAction: b.uncategorizedAction || (basis ? basis.uncategorizedAction : 'alert'),
    features: { ...defaultFeatures(), ...(basis ? basis.features : {}), ...(b.features || {}) },
    homeUrl: b.homeUrl || (basis ? basis.homeUrl : 'https://www.wikipedia.org/'),
    createdAt: Date.now()
  };

  d.roles.push(role);
  save();
  res.status(201).json({ role });
});

app.put('/api/admin/roles/:id', requireAdmin, (req, res) => {
  const role = findRole(req.params.id);
  if (!role) return res.status(404).json({ message: 'Role not found.' });

  const b = req.body || {};
  if (b.label !== undefined) {
    const label = String(b.label).trim();
    if (!label) return res.status(400).json({ message: 'Role name cannot be empty.' });
    role.label = label;
  }
  if (b.description !== undefined) role.description = String(b.description).trim().slice(0, 200);
  if (b.categoryRules !== undefined) {
    role.categoryRules = completeCategoryRules(b.categoryRules, role.categoryRules);
  }
  if (b.uncategorizedAction !== undefined) role.uncategorizedAction = b.uncategorizedAction;
  if (b.features !== undefined) role.features = { ...defaultFeatures(), ...b.features };
  if (b.homeUrl !== undefined) role.homeUrl = b.homeUrl;
  if (b.searchEngine !== undefined) role.searchEngine = validSearchEngine(b.searchEngine);
  if (b.maxTabs !== undefined) role.maxTabs = Math.max(1, Math.min(20, parseInt(b.maxTabs, 10) || 8));

  // Optionally push the new rules onto everyone already holding this role.
  let updated = 0;
  if (b.applyToExistingUsers) {
    for (const u of db().users) {
      if (u.role !== role.id) continue;
      u.categoryRules = { ...role.categoryRules };
      u.uncategorizedAction = role.uncategorizedAction;
      u.features = { ...defaultFeatures(), ...role.features };
      u.homeUrl = role.homeUrl;
      updated++;
    }
  }

  bumpRole(role.id);       // every device on this role refreshes at once
  save();
  res.json({ role, usersUpdated: updated });
});

/**
 * Copies a role, including the built-in ones.
 *
 * The four supplied roles cannot be deleted, but an administrator often wants
 * "Student, but with YouTube" — cloning gives them an editable starting point
 * instead of setting all 37 categories by hand.
 */
app.post('/api/admin/roles/:id/duplicate', requireAdmin, (req, res) => {
  const source = findRole(req.params.id);
  if (!source) return res.status(404).json({ message: 'Role not found.' });

  const b = req.body || {};
  const label = String(b.label || `${source.label} copy`).trim();
  const id = normaliseRoleId(b.id || label);
  if (!id) return res.status(400).json({ message: 'Role name must contain letters or numbers.' });

  const d = db();
  if (d.roles.some(r => r.id === id)) {
    return res.status(409).json({ message: `A role called "${label}" already exists.` });
  }

  const copy = {
    ...JSON.parse(JSON.stringify(source)),
    id,
    label,
    builtIn: false,           // a copy is always editable and deletable
    createdAt: Date.now()
  };

  d.roles.push(copy);
  save();
  res.status(201).json({ role: copy });
});

app.delete('/api/admin/roles/:id', requireAdmin, (req, res) => {
  const d = db();
  const idx = d.roles.findIndex(r => r.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'Role not found.' });

  const role = d.roles[idx];
  if (role.builtIn) {
    return res.status(400).json({
      message: 'Built-in roles cannot be deleted. You can rename them or change their rules.'
    });
  }

  // Refuse rather than silently orphaning accounts.
  const inUse = d.users.filter(u => u.role === role.id).length;
  if (inUse > 0) {
    return res.status(409).json({
      message: `${inUse} user(s) still have this role. Move them to another role first.`
    });
  }

  d.roles.splice(idx, 1);
  save();
  res.json({ ok: true });
});

app.get('/api/admin/activity', requireAdmin, (req, res) => {
  const d = db();
  const userId = req.query.userId;
  const list = userId ? d.activity.filter(a => a.userId === userId) : d.activity;
  res.json({ activity: list.slice(0, 300), total: list.length });
});

/**
 * Clears the activity log — all of it, or one profile's entries.
 *
 * The log is the one table that grows on its own, so an administrator needs a
 * way to empty it without editing the database by hand.
 */
app.delete('/api/admin/activity', requireAdmin, (req, res) => {
  const d = db();
  const userId = req.query.userId;
  const before = d.activity.length;

  d.activity = userId ? d.activity.filter(a => a.userId !== userId) : [];
  save();
  res.json({ ok: true, removed: before - d.activity.length });
});

// ---------------- registered devices ----------------
//
// Every sign-in records the device name, so the administrator can see where a
// profile is in use and revoke a phone that has been lost.

app.get('/api/admin/devices', requireAdmin, (_req, res) => {
  const d = db();
  const byId = Object.fromEntries(d.users.map(u => [u.id, u]));
  res.json({
    devices: d.devices.map((dev, i) => ({
      index: i,
      userId: dev.userId,
      username: byId[dev.userId] ? byId[dev.userId].username : '(deleted user)',
      name: dev.name,
      // Needed so the dashboard can rename the right row even when two
      // machines happen to share a name.
      deviceId: dev.deviceId || '',
      platform: dev.platform || '',
      lastSeen: dev.lastSeen || 0
    }))
  });
});

app.delete('/api/admin/devices', requireAdmin, (req, res) => {
  const d = db();
  const { userId, name } = req.query;
  const before = d.devices.length;

  d.devices = d.devices.filter(dev => {
    if (userId && dev.userId !== userId) return true;
    if (name && dev.name !== name) return true;
    return false;
  });
  save();
  res.json({ ok: true, removed: before - d.devices.length });
});

/**
 * Renames a device.
 *
 * The apps deliberately refuse to let a user rename their own machine — an
 * activity log is only worth reading if the names in it are trustworthy. This
 * is the one route that can change a name, and it requires an administrator.
 * The device adopts the new name the next time it signs in.
 */
app.put('/api/admin/devices/rename', requireAdmin, (req, res) => {
  const d = db();
  const b = req.body || {};
  const userId = String(b.userId || '');
  const oldName = String(b.oldName || '');
  const deviceId = String(b.deviceId || '');
  const newName = String(b.name || '').trim().slice(0, 60);

  if (!newName) return res.status(400).json({ message: 'Device name cannot be empty.' });

  const dev = d.devices.find(x =>
    x.userId === userId &&
    (deviceId ? x.deviceId === deviceId : x.name === oldName));

  if (!dev) return res.status(404).json({ message: 'Device not found.' });

  const clash = d.devices.find(x =>
    x !== dev && x.userId === userId && x.name === newName);
  if (clash) {
    return res.status(409).json({ message: `This user already has a device called "${newName}".` });
  }

  dev.name = newName;
  dev.renamedAt = Date.now();
  save();
  res.json({ ok: true, device: dev });
});

// ---------------- dashboard administrators ----------------
//
// Previously the only administrator was the one created from ADMIN_PASSWORD at
// first start, and there was no way to change that password or add a colleague
// without redeploying. With the database now durable, these have to be
// editable from the dashboard like everything else.

function publicAdmin(a) {
  const { passwordHash, ...rest } = a;
  return rest;
}

app.get('/api/admin/admins', requireAdmin, (req, res) => {
  const d = db();
  res.json({ admins: d.admins.map(publicAdmin), me: req.admin.sub });
});

app.post('/api/admin/admins', requireAdmin, (req, res) => {
  const b = req.body || {};
  const username = String(b.username || '').trim();

  if (!username) return res.status(400).json({ message: 'Username is required.' });
  if (!b.password || String(b.password).length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters.' });
  }

  const d = db();
  if (d.admins.some(a => a.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ message: `An administrator called "${username}" already exists.` });
  }

  const admin = {
    id: `adm-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    username,
    passwordHash: bcrypt.hashSync(String(b.password), 10),
    createdAt: Date.now()
  };
  d.admins.push(admin);
  save();
  res.status(201).json({ admin: publicAdmin(admin) });
});

app.put('/api/admin/admins/:id', requireAdmin, (req, res) => {
  const d = db();
  const admin = d.admins.find(a => a.id === req.params.id);
  if (!admin) return res.status(404).json({ message: 'Administrator not found.' });

  const b = req.body || {};

  if (b.username !== undefined) {
    const username = String(b.username).trim();
    if (!username) return res.status(400).json({ message: 'Username cannot be empty.' });
    const clash = d.admins.some(
      a => a.id !== admin.id && a.username.toLowerCase() === username.toLowerCase()
    );
    if (clash) return res.status(409).json({ message: 'That username is already taken.' });
    admin.username = username;
  }

  if (b.password) {
    if (String(b.password).length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters.' });
    }
    // Changing your OWN password requires proving you know the current one.
    if (admin.id === req.admin.sub) {
      if (!bcrypt.compareSync(String(b.currentPassword || ''), admin.passwordHash)) {
        return res.status(403).json({ message: 'Your current password is not correct.' });
      }
    }
    admin.passwordHash = bcrypt.hashSync(String(b.password), 10);
  }

  save();
  res.json({ admin: publicAdmin(admin) });
});

app.delete('/api/admin/admins/:id', requireAdmin, (req, res) => {
  const d = db();
  const idx = d.admins.findIndex(a => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'Administrator not found.' });

  // Two guards that stop the dashboard being locked out for good.
  if (d.admins[idx].id === req.admin.sub) {
    return res.status(400).json({ message: 'You cannot delete the account you are signed in with.' });
  }
  if (d.admins.length <= 1) {
    return res.status(400).json({ message: 'At least one administrator must remain.' });
  }

  d.admins.splice(idx, 1);
  save();
  res.json({ ok: true });
});

// ---------------------------------------------------------------- misc

// ===================================================================
// SECTION 5b — web session sync (cookie jar per profile)
// ===================================================================
//
// Lets a profile's website logins follow them to another phone: sign in to a
// site on phone 1, and phone 2 running the same profile is already signed in.
//
// SECURITY NOTE — please read:
// These are live session cookies. Anyone who can read this database can take
// over those website accounts. Google Chrome deliberately does NOT sync
// cookies for exactly this reason (it syncs passwords instead). This feature
// is opt-in per profile (`syncWebSessions`) and defaults to OFF.
//
// Mitigations applied here:
//   - the blob is encrypted by the DEVICE before upload; the server stores
//     ciphertext it cannot read
//   - `sessionVersion` gives last-writer-wins without merge corruption
//   - a profile can be wiped remotely by the admin (POST .../sessions/clear)

/* ------------------------------------------------------------------ *
 *  Cloud bookmarks
 *
 *  Bookmarks follow the account, so a page saved on the library PC is there
 *  on the phone as well. Chrome Sync cannot be used for this — Google closed
 *  it to non-Google browsers in 2021 — so the rules server carries them, the
 *  same way it already carries the policy.
 *
 *  Delivery reuses the long-poll machinery built for instant rule sync, so a
 *  bookmark saved on one device shows up on the others in well under a second
 *  rather than on some later poll.
 *
 *  Conflicts are settled by a per-device sequence rather than a timestamp:
 *  a phone with a wrong clock must not be able to erase a laptop's work.
 * ------------------------------------------------------------------ */

/** Devices parked on /api/me/bookmarks/wait, keyed by user id. */
const bookmarkWaiters = new Map();

/** Wakes every device on this account except the one that just wrote. */
function notifyBookmarksChanged(userId, exceptDevice, profileId) {
  const waiters = bookmarkWaiters.get(userId);
  if (!waiters) return;

  const keep = [];
  for (const w of waiters) {
    // A device sitting in a different profile is not affected by this write;
    // waking it would hand it the wrong profile's bookmarks.
    if (profileId && w.profileId && w.profileId !== profileId) { keep.push(w); continue; }

    // The writer already has this state; waking it would bounce it straight
    // back for no reason.
    if (exceptDevice && w.device === exceptDevice) { keep.push(w); continue; }

    clearTimeout(w.timer);
    try { w.send(); } catch { /* client vanished */ }
  }

  if (keep.length) bookmarkWaiters.set(userId, keep);
  else bookmarkWaiters.delete(userId);
}

/*
  Bookmarks are stored PER PROFILE, not per account.

  THE BUG THIS FIXES: they used to live on the user record, one list per
  account. But every device keeps a separate bookmark tree for each profile,
  so opening "Personal" and pushing its (empty) tree overwrote everything
  "Work" had saved. Proven with two profiles on one account: after switching,
  the first profile's bookmarks were gone from the cloud.

  Keying by profile makes the cloud mirror what the devices actually hold.
  The profile id is the same string on every device, because it is generated
  once and travels with the profile, so "Work" on the Samsung and "Work" on
  the Oppo resolve to the same bucket.
*/

/** The per-profile bookmark record, created on first use. */
function bookmarkBucket(user, profileId) {
  if (!user.bookmarkSets || typeof user.bookmarkSets !== 'object') {
    user.bookmarkSets = {};

    // One-time migration: an account that synced before this change has a
    // single flat list. Hand it to the first profile that asks, so nobody
    // loses what they had.
    if (Array.isArray(user.bookmarks) && user.bookmarks.length) {
      user.bookmarkSets.__legacy = {
        nodes: user.bookmarks,
        version: user.bookmarkVersion || 0,
        updatedAt: user.bookmarksUpdatedAt || 0
      };
    }
  }

  const key = String(profileId || 'default');
  if (!user.bookmarkSets[key]) {
    // Adopt the legacy list once, then retire it.
    const legacy = user.bookmarkSets.__legacy;
    user.bookmarkSets[key] = legacy
      ? { nodes: legacy.nodes, version: legacy.version, updatedAt: legacy.updatedAt }
      : { nodes: [], version: 0, updatedAt: 0 };
    if (legacy) delete user.bookmarkSets.__legacy;
  }
  return user.bookmarkSets[key];
}

/** Which profile this request is about. */
function profileKey(req) {
  return String(req.query.profileId || req.body?.profileId || 'default').slice(0, 64);
}

/* ------------------------------------------------------------------ *
 *  Profile list
 *
 *  Profiles used to exist only on the machine that created them, so signing
 *  the same account into a second device showed none of them — the person had
 *  to recreate "Work" by hand, and because a new profile gets a new id, its
 *  bookmarks lived in a different bucket and never appeared.
 *
 *  The list travels with the account now. What travels is only the
 *  DESCRIPTION of a profile: its id, name, colour and whether it is shared.
 *  Website logins do NOT travel — see the note on cookie sync — and neither
 *  does a profile password, which stays on the machine that set it.
 * ------------------------------------------------------------------ */

app.get('/api/me/profiles', deviceAuth, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.device.sub);
  if (!user) return res.status(404).json({ message: 'Unknown user' });

  res.json({
    version: user.profileVersion || 0,
    profiles: user.profiles || []
  });
});

app.put('/api/me/profiles', deviceAuth, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.device.sub);
  if (!user) return res.status(404).json({ message: 'Unknown user' });

  const incoming = Array.isArray(req.body.profiles) ? req.body.profiles : null;
  if (!incoming) return res.status(400).json({ message: 'profiles must be an array' });
  if (incoming.length > 50) {
    return res.status(413).json({ message: 'Too many profiles (limit 50).' });
  }

  /*
    Merge by id rather than replace.

    A device that has been offline knows nothing of a profile created
    elsewhere; letting it overwrite the list would delete that profile for
    everyone. Union keeps both sides, and the newer name wins on a clash.
  */
  const byId = new Map();
  for (const p of user.profiles || []) byId.set(p.id, p);

  for (const raw of incoming) {
    const id = String(raw.id || '').slice(0, 64);
    if (!id) continue;

    const existing = byId.get(id);
    const updatedAt = Number(raw.updatedAt) || 0;

    // Keep only fields we understand, and never accept a password hash.
    const clean = {
      id,
      name: String(raw.name || 'Profile').slice(0, 40),
      colour: String(raw.colour || '').slice(0, 16),
      shared: raw.shared === true,
      createdAt: Number(raw.createdAt) || Date.now(),
      updatedAt: updatedAt || Date.now()
    };

    if (!existing || (Number(existing.updatedAt) || 0) <= clean.updatedAt) {
      byId.set(id, clean);
    }
  }

  user.profiles = [...byId.values()];
  user.profileVersion = (user.profileVersion || 0) + 1;
  save();

  res.json({ ok: true, version: user.profileVersion, profiles: user.profiles });
});

app.get('/api/me/bookmarks', deviceAuth, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.device.sub);
  if (!user) return res.status(404).json({ message: 'Unknown user' });

  const bucket = bookmarkBucket(user, profileKey(req));
  save();

  res.json({
    version: bucket.version || 0,
    nodes: bucket.nodes || [],
    updatedAt: bucket.updatedAt || 0
  });
});

app.put('/api/me/bookmarks', deviceAuth, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.device.sub);
  if (!user) return res.status(404).json({ message: 'Unknown user' });

  const nodes = Array.isArray(req.body.nodes) ? req.body.nodes : null;
  if (!nodes) return res.status(400).json({ message: 'nodes must be an array' });

  // A tree this large is a bug, not a person's bookmarks.
  if (nodes.length > 5000) {
    return res.status(413).json({ message: 'Too many bookmarks (limit 5000).' });
  }

  /*
    Reject a write built on a version we have already moved past.

    Without this, two devices saving at once would silently overwrite each
    other. The loser is told the current version and merges before retrying,
    so no bookmark is ever quietly lost.
  */
  const bucket = bookmarkBucket(user, profileKey(req));

  const base = Number(req.body.baseVersion);
  const current = bucket.version || 0;
  if (Number.isFinite(base) && base !== current) {
    return res.status(409).json({
      message: 'Bookmarks changed on another device.',
      version: current,
      nodes: bucket.nodes || []
    });
  }

  // Keep only the fields we understand, so a compromised client cannot
  // smuggle extra data into other devices through this route.
  bucket.nodes = nodes.slice(0, 5000).map(n => ({
    id: String(n.id || '').slice(0, 64),
    parentId: n.parentId === null ? null : String(n.parentId || '').slice(0, 64),
    type: n.type === 'folder' ? 'folder' : 'link',
    title: String(n.title || '').slice(0, 200),
    url: n.type === 'folder' ? undefined : String(n.url || '').slice(0, 2000),
    order: Number(n.order) || 0,
    added: Number(n.added) || Date.now()
  }));
  bucket.version = current + 1;
  bucket.updatedAt = Date.now();
  save();

  // Only devices looking at the SAME profile need waking.
  notifyBookmarksChanged(user.id, req.device.dev, profileKey(req));
  res.json({ ok: true, version: bucket.version });
});

app.get('/api/me/bookmarks/wait', deviceAuth, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.device.sub);
  if (!user) return res.status(404).json({ message: 'Unknown user' });

  const key = profileKey(req);
  const bucket = bookmarkBucket(user, key);
  const since = Number(req.query.version) || 0;
  const current = bucket.version || 0;

  // Already behind — answer at once, no waiting.
  if (current > since) {
    return res.json({ changed: true, version: current, nodes: bucket.nodes || [] });
  }

  let done = false;
  const send = () => {
    if (done) return;
    done = true;
    // Re-read: the write that woke us happened after this request arrived.
    const fresh = db().users.find(u => u.id === req.device.sub);
    if (!fresh) return res.json({ changed: false, version: since });
    const b = bookmarkBucket(fresh, key);
    res.json({
      changed: true,
      version: b.version || 0,
      nodes: b.nodes || []
    });
  };

  const drop = () => {
    const list = bookmarkWaiters.get(user.id);
    if (!list) return;
    const i = list.indexOf(entry);
    if (i >= 0) list.splice(i, 1);
    if (!list.length) bookmarkWaiters.delete(user.id);
  };

  const timer = setTimeout(() => {
    if (done) return;
    done = true;
    drop();
    res.json({ changed: false, version: current });
  }, 25000);

  const entry = { send, timer, device: req.device.dev, profileId: key };
  if (!bookmarkWaiters.has(user.id)) bookmarkWaiters.set(user.id, []);
  bookmarkWaiters.get(user.id).push(entry);

  req.on('close', () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    drop();
  });
});

app.get('/api/me/websession', deviceAuth, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.device.sub);
  if (!user) return res.status(404).json({ message: 'Unknown user' });
  if (!user.syncWebSessions) {
    return res.json({ enabled: false, version: 0, blob: null });
  }
  res.json({
    enabled: true,
    version: user.sessionVersion || 0,
    blob: user.sessionBlob || null,
    updatedAt: user.sessionUpdatedAt || 0
  });
});

app.put('/api/me/websession', deviceAuth, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.device.sub);
  if (!user) return res.status(404).json({ message: 'Unknown user' });
  if (!user.syncWebSessions) {
    return res.status(409).json({ message: 'Session sync is disabled for this profile.' });
  }

  const blob = typeof req.body.blob === 'string' ? req.body.blob : null;
  if (!blob) return res.status(400).json({ message: 'blob is required' });
  // ~1 MB ceiling: cookie jars are small; anything larger is a bug or abuse.
  if (blob.length > 1024 * 1024) {
    return res.status(413).json({ message: 'Session data too large' });
  }

  user.sessionBlob = blob;
  user.sessionVersion = (user.sessionVersion || 0) + 1;
  user.sessionUpdatedAt = Date.now();
  save();
  res.json({ ok: true, version: user.sessionVersion });
});

app.post('/api/admin/users/:id/sessions/clear', requireAdmin, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ message: 'User not found.' });
  user.sessionBlob = null;
  user.sessionVersion = (user.sessionVersion || 0) + 1;
  user.sessionUpdatedAt = Date.now();
  save();
  res.json({ ok: true });
});

// ===================================================================
// SECTION 5c — app auto-update
// ===================================================================
//
// The device polls /api/app/version on every launch and every resume. When the
// server advertises a higher versionCode, the app downloads the APK in the
// background and installs it.
//
// HONEST LIMITATION: Android does not allow a normally-installed (sideloaded)
// app to install an update with zero taps. Only system apps or a Device Owner
// can do that. The user therefore sees ONE system confirmation screen at the
// end. Everything before it — checking, downloading, verifying — is automatic,
// and the update can be made mandatory so the app is unusable until it is
// applied.
//
// Upload flow for the admin:
//   1. build the new APK
//   2. host it anywhere public (GitHub Release, Drive direct link, your server)
//   3. POST the versionCode / versionName / URL here

/*
  ---------------------------------------------------------------- channels

  Two release channels: `live` (everyone) and `beta` (the test build).

  A device says which one it is on with ?channel=beta. Anything else — a
  missing parameter, a typo, an older build that predates channels — is
  treated as `live`, because the alternative is an old device silently
  stopping updates.
*/
const CHANNELS = ['live', 'beta'];

function channelOf(value) {
  const c = String(value || '').trim().toLowerCase();
  return c === 'beta' ? 'beta' : 'live';
}

/** Reads the published record for a channel. */
function versionFor(channel) {
  const d = db();
  return channel === 'beta' ? (d.appVersionBeta || null) : (d.appVersion || null);
}

/** Writes the published record for a channel. */
function setVersionFor(channel, record) {
  const d = db();
  if (channel === 'beta') d.appVersionBeta = record;
  else d.appVersion = record;
}

app.get('/api/app/version', (req, res) => {
  const channel = channelOf(req.query.channel);
  const info = versionFor(channel);

  // "Available" means either platform has something published. Gating on
  // versionCode alone hid a desktop-only release from every laptop, because
  // a Windows installer has no Android version code.
  const hasAndroid = !!(info && info.versionCode && info.apkUrl);
  const hasDesktop = !!(info && info.desktopUrl && info.desktopVersion);

  if (!info || (!hasAndroid && !hasDesktop)) {
    return res.json({ available: false, channel });
  }

  res.json({
    available: true,
    channel,
    versionCode: info.versionCode || 0,
    versionName: info.versionName || '',
    apkUrl: info.apkUrl || '',
    desktopUrl: info.desktopUrl || '',
    desktopVersion: info.desktopVersion || '',
    desktopMandatory: info.desktopMandatory !== false,
    mandatory: info.mandatory !== false,
    notes: info.notes || '',
    publishedAt: info.publishedAt || 0
  });
});

app.get('/api/admin/app/version', requireAdmin, (_req, res) => {
  const d = db();
  // `appVersion` keeps its old name so the existing dashboard code and any
  // saved script that reads it carries on working unchanged.
  res.json({
    appVersion: d.appVersion || null,
    appVersionBeta: d.appVersionBeta || null
  });
});

/**
 * Actually fetches a download link to prove the file is there.
 *
 * Pattern-matching the URL is not enough. A link can look perfectly correct —
 * right host, right `/releases/download/` path — and still 404 because the tag
 * is wrong, the filename was misspelled, or the repository is private. That
 * failure only showed up later, on every device at once, as an unhelpful
 * "Server returned 404".
 *
 * Checking here costs one request at publish time and turns a fleet-wide
 * failure into a message the administrator sees before anything ships.
 *
 * Uses a ranged GET rather than HEAD: some CDNs (GitHub's asset host among
 * them) answer HEAD with 403 while the real download works fine.
 *
 * @returns {Promise<{ok: boolean, message?: string}>}
 */
function verifyDownloadLink(url, label, redirects = 0) {
  return new Promise(resolve => {
    if (redirects > 5) {
      return resolve({ ok: false, message: `The ${label} link redirects too many times.` });
    }

    let parsed;
    try { parsed = new URL(url); } catch {
      return resolve({ ok: false, message: `The ${label} link is not a valid address.` });
    }

    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.get(url, {
      timeout: 12000,
      // Ask for the first byte only: enough to learn the status and type
      // without pulling an 80 MB installer through the server.
      headers: { Range: 'bytes=0-0', 'User-Agent': 'SMVS-Browser-Admin' }
    }, res => {
      const code = res.statusCode;

      if (code >= 300 && code < 400 && res.headers.location) {
        res.resume();
        const next = new URL(res.headers.location, url).toString();
        return resolve(verifyDownloadLink(next, label, redirects + 1));
      }

      const type = String(res.headers['content-type'] || '').toLowerCase();
      res.resume();

      if (code === 404) {
        return resolve({
          ok: false,
          message: `That ${label} link returns "not found" (404). The file is not ` +
            'at that address — check the release tag and the exact file name, ' +
            'and make sure the upload finished.'
        });
      }
      if (code === 401 || code === 403) {
        return resolve({
          ok: false,
          message: `That ${label} link is not public (${code}). If the repository ` +
            'is private, devices cannot download from it — make the release public.'
        });
      }
      if (code !== 200 && code !== 206) {
        return resolve({
          ok: false,
          message: `That ${label} link returned HTTP ${code}. Devices will not be ` +
            'able to download it.'
        });
      }
      if (type.startsWith('text/html')) {
        return resolve({
          ok: false,
          message: `That ${label} link opens a web page, not the file. Right-click ` +
            'the file under Releases and choose "Copy link address".'
        });
      }
      resolve({ ok: true });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({
        ok: false,
        message: `The ${label} link did not respond in time. Check that the address ` +
          'is reachable from the internet.'
      });
    });

    req.on('error', e => resolve({
      ok: false,
      message: `The ${label} link could not be reached (${e.code || e.message}).`
    }));
  });
}

/*
  =======================================================================
  READING THE REAL versionCode OUT OF THE APK

  Why this exists — a bug that hit every phone in the school:

    The dashboard published versionCode 29 while the APK behind the link
    was really 28. Each phone installed the update, came back still on 28,
    was told 29 again, and asked to update on every single launch. Forever.

  Nothing in the old flow could catch it: the number was typed by hand and
  the file was never opened. So now the file is opened. An APK is a ZIP, and
  AndroidManifest.xml inside it is Android's binary XML; both are read here
  with nothing but zlib.

  If anything at all goes wrong the check is skipped rather than blocking a
  release — a publish that cannot happen is worse than one that is unchecked.
  =======================================================================
*/

/** Pulls one file out of a ZIP buffer. */
function zipEntry(buf, wanted) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 66000); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('not a zip');

  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);

  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('bad central directory');
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOff = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);

    if (name === wanted) {
      const lNameLen = buf.readUInt16LE(localOff + 26);
      const lExtraLen = buf.readUInt16LE(localOff + 28);
      const start = localOff + 30 + lNameLen + lExtraLen;
      const raw = buf.subarray(start, start + compSize);
      return method === 0 ? raw : zlib.inflateRawSync(raw);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  throw new Error(wanted + ' is not in the archive');
}

/** versionCode AND package name from a binary AndroidManifest.xml. */
function manifestInfo(axml) {
  if (axml.readUInt16LE(0) !== 0x0003) throw new Error('not an Android binary XML');
  let pos = 8;
  let strings = [];

  while (pos + 8 <= axml.length) {
    const type = axml.readUInt16LE(pos);
    const size = axml.readUInt32LE(pos + 4);
    if (size <= 0 || pos + size > axml.length) break;

    if (type === 0x0001) {                                  // string pool
      const count = axml.readUInt32LE(pos + 8);
      const flags = axml.readUInt32LE(pos + 16);
      const startAt = axml.readUInt32LE(pos + 20);
      const utf8 = (flags & (1 << 8)) !== 0;
      const base = pos + startAt;
      strings = new Array(count);
      for (let i = 0; i < count; i++) {
        let q = base + axml.readUInt32LE(pos + 28 + i * 4);
        if (utf8) {
          const varint = () => { let v = axml[q++]; if (v & 0x80) v = ((v & 0x7f) << 8) | axml[q++]; return v; };
          varint();                                          // characters
          const bytes = varint();
          strings[i] = axml.toString('utf8', q, q + bytes);
        } else {
          let len = axml.readUInt16LE(q); q += 2;
          if (len & 0x8000) { len = ((len & 0x7fff) << 16) | axml.readUInt16LE(q); q += 2; }
          strings[i] = axml.toString('utf16le', q, q + len * 2);
        }
      }
    } else if (type === 0x0102) {                            // START_TAG
      // attributeStart is measured from the ns field, which is 16 bytes in.
      if (strings[axml.readUInt32LE(pos + 20)] === 'manifest') {
        const attrStart = axml.readUInt16LE(pos + 24);
        const attrSize = axml.readUInt16LE(pos + 26);
        const attrCount = axml.readUInt16LE(pos + 28);
        const found = { versionCode: null, packageName: null };
        for (let a = 0; a < attrCount; a++) {
          const at = pos + 16 + attrStart + a * attrSize;
          const name = strings[axml.readUInt32LE(at + 4)];
          if (name === 'versionCode') found.versionCode = axml.readUInt32LE(at + 16);
          // A string attribute keeps its value in the raw-value slot.
          if (name === 'package') found.packageName = strings[axml.readUInt32LE(at + 8)] || null;
        }
        return found;
      }
    }
    pos += size;
  }
  return { versionCode: null, packageName: null };
}

/** Downloads an APK and reports what it really is. */
function apkIdentity(url, redirects = 0) {
  return new Promise(resolve => {
    if (redirects > 5) return resolve(null);
    let parsed;
    try { parsed = new URL(url); } catch { return resolve(null); }

    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.get(url, { headers: { 'User-Agent': 'SMVS-Server' }, timeout: 45000 }, response => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
        response.resume();
        return resolve(apkIdentity(new URL(response.headers.location, url).toString(), redirects + 1));
      }
      if (response.statusCode !== 200) { response.resume(); return resolve(null); }

      const chunks = [];
      let total = 0;
      response.on('data', c => {
        total += c.length;
        // A browser APK is a few MB. Anything enormous is not worth reading.
        if (total > 120 * 1024 * 1024) { req.destroy(); return resolve(null); }
        chunks.push(c);
      });
      response.on('end', () => {
        try {
          const buf = Buffer.concat(chunks);
          resolve(manifestInfo(zipEntry(buf, 'AndroidManifest.xml')));
        } catch { resolve(null); }
      });
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
  });
}

app.post('/api/admin/app/version', requireAdmin, async (req, res) => {
  const b = req.body || {};
  const channel = channelOf(b.channel);
  let code = parseInt(b.versionCode, 10);

  // Android and desktop are published together but validated apart: an
  // administrator may well have a new APK ready before the Windows installer,
  // and forcing both at once would block one platform on the other.
  const apkUrl = String(b.apkUrl || '').trim();
  const desktopUrl = String(b.desktopUrl || '').trim();
  const desktopVersion = String(b.desktopVersion || '').trim();

  if (!apkUrl && !desktopUrl) {
    return res.status(400).json({
      message: 'Provide at least one download link — Android APK or Windows installer.'
    });
  }

  /**
   * Rejects links that point at a WEB PAGE rather than the file.
   *
   * This is the failure people actually hit. GitHub answers a `/blob/` or
   * `/releases/tag/` link with HTTP 200 and an HTML body, so the device
   * downloads it happily and only fails at install time — with a message that
   * blames the network. Catching it at publish time is far kinder than
   * discovering it on fifty phones.
   */
  function linkProblem(url, extension, label) {
    if (!/^https?:\/\//i.test(url)) {
      return `The ${label} link must start with http:// or https://`;
    }
    if (/github\.com\/.+\/blob\//i.test(url)) {
      return `That ${label} link opens a GitHub page, not the file. ` +
        'Open Releases, right-click the file and choose "Copy link address" ' +
        '— it must contain /releases/download/';
    }
    if (/github\.com\/.+\/releases\/tag\//i.test(url)) {
      return `That ${label} link points at the release PAGE, not the file. ` +
        'Right-click the attached file itself and copy its address ' +
        '— it must contain /releases/download/';
    }
    if (/drive\.google\.com\/file\//i.test(url)) {
      return 'A Google Drive "share" link opens a preview page, not the file. ' +
        'Use a GitHub Release link instead.';
    }
    if (/dropbox\.com\/.+dl=0/i.test(url)) {
      return 'That Dropbox link opens a preview page. Change dl=0 to dl=1, ' +
        'or use a GitHub Release link.';
    }
    // Warn, do not block, on an odd extension: some hosts serve the right
    // file from a URL that does not end in .apk or .exe.
    return null;
  }

  /*
    The number the administrator typed is checked against the number inside
    the file. Getting these out of step is what made every phone ask to
    update on every launch, forever.
  */
  let identity = null;
  if (apkUrl && b.skipLinkCheck !== true) {
    identity = await apkIdentity(apkUrl);
  }
  const realCode = identity ? identity.versionCode : null;
  const realPackage = identity ? identity.packageName : null;

  /*
    The build must belong to the channel it is being published on.

    Android treats com.arena.securebrowser and com.arena.securebrowser.beta
    as two completely different apps. Putting the live APK on the beta
    channel therefore does nothing useful: a beta phone downloads it and
    Android refuses to install it over the beta app, because it is not the
    same app. Nothing fails loudly — the update simply never happens, which
    is the hardest kind of problem to find.
  */
  if (realPackage) {
    const isBetaBuild = realPackage.endsWith('.beta');
    if (channel === 'beta' && !isBetaBuild) {
      return res.status(400).json({
        message:
          'That APK is the LIVE build (' + realPackage + '). A beta device cannot ' +
          'install it — Android sees the two as different apps. Use the ' +
          '"Publish LIVE -> BETA" button instead: it finds the beta-built file on the ' +
          'same release for you. Or paste the link to the beta APK (package ' +
          realPackage + '.beta) here.'
      });
    }
    if (channel === 'live' && isBetaBuild) {
      return res.status(400).json({
        message:
          'That APK is the BETA build (' + realPackage + '). Publishing it to everyone ' +
          'would install a second app beside SMVS Browser rather than updating it. ' +
          'Publish the live-flavoured file on the live channel.'
      });
    }
  }

  if (apkUrl) {
    if (realCode && Number.isInteger(code) && code > 0 && code !== realCode) {
      return res.status(400).json({
        message:
          'That APK is really versionCode ' + realCode + ', but ' + code +
          ' was entered. Publishing a higher number than the file carries makes ' +
          'every phone install the update and then ask for it again on the next ' +
          'launch, over and over. Enter ' + realCode + ', or leave the box empty ' +
          'and it will be filled in from the file.'
      });
    }

    // Left blank, take it from the file — the safest value there is.
    if (realCode && (!Number.isInteger(code) || code < 1)) {
      code = realCode;
    }

    if (!Number.isInteger(code) || code < 1) {
      return res.status(400).json({
        message: 'versionCode must be a whole number when publishing an APK.'
      });
    }
    const problem = linkProblem(apkUrl, '.apk', 'APK');
    if (problem) return res.status(400).json({ message: problem });

    // Prove the file is really there, unless the caller opted out.
    if (b.skipLinkCheck !== true) {
      const reach = await verifyDownloadLink(apkUrl, 'APK');
      if (!reach.ok) return res.status(400).json({ message: reach.message });
    }
  }

  if (desktopUrl) {
    const problem = linkProblem(desktopUrl, '.exe', 'Windows installer');
    if (problem) return res.status(400).json({ message: problem });
    // The desktop updater compares dotted versions, so it needs one.
    if (!/^\d+(\.\d+)*$/.test(desktopVersion)) {
      return res.status(400).json({
        message: 'Desktop version must look like 2.1.0 when publishing a Windows installer.'
      });
    }

    if (b.skipLinkCheck !== true) {
      const reach = await verifyDownloadLink(desktopUrl, 'Windows installer');
      if (!reach.ok) return res.status(400).json({ message: reach.message });
    }
  }

  setVersionFor(channel, {
    versionCode: Number.isInteger(code) && code > 0 ? code : 0,
    versionName: String(b.versionName || '').trim(),
    apkUrl,
    desktopUrl,
    desktopVersion,
    desktopMandatory: b.desktopMandatory !== false,
    mandatory: b.mandatory !== false,
    notes: String(b.notes || '').trim().slice(0, 500),
    channel,
    apkPackage: realPackage || null,
    publishedAt: Date.now()
  });
  save();

  /*
    Publishing to "beta" has to leave this server. The beta app points at a
    different deployment with a different database, so a record written only
    here would be seen by nobody — which is exactly what was reported.
  */
  let peer = null;
  if (channel === 'beta') {
    peer = await publishToBetaPeer(versionFor('beta'));
  }

  res.json({ ok: true, channel, appVersion: versionFor(channel), peer, verifiedVersionCode: realCode });
});

/**
 * Copies one channel's published build onto the other.
 *
 * The administrator asked for this in both directions: beta -> live when a
 * test build is judged good, and live -> beta when the beta channel has
 * fallen behind and should simply carry what everyone else already has.
 *
 * It copies the RECORD, never the database — users, rules, bookmarks and
 * history stay where they are. Only "which build should this channel offer"
 * moves.
 */
/*
  ------------------------------------------------- talking to the beta server

  Minimal JSON client. `fetch` exists in Node 18+, but Render's free tier
  sleeps: a cold beta server can take the best part of a minute to answer its
  first request, so the timeout is deliberately generous and the failure
  message says so rather than just "failed".
*/
function peerRequest(baseUrl, path, { method = 'GET', token = null, body = null, timeoutMs = 60000 } = {}) {
  return new Promise(resolve => {
    let target;
    try {
      target = new URL(String(baseUrl).replace(/\/+$/, '') + path);
    } catch {
      return resolve({ ok: false, status: 0, message: 'The beta server address is not a valid URL.' });
    }
    if (!/^https?:$/.test(target.protocol)) {
      return resolve({ ok: false, status: 0, message: 'The beta server address must start with http:// or https://' });
    }

    const payload = body ? JSON.stringify(body) : null;
    const client = target.protocol === 'https:' ? https : http;
    const req = client.request(target, {
      method,
      headers: {
        Accept: 'application/json',
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...(token ? { Authorization: 'Bearer ' + token } : {})
      },
      timeout: timeoutMs
    }, response => {
      let raw = '';
      response.on('data', c => { raw += c; if (raw.length > 200000) req.destroy(); });
      response.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(raw); } catch { /* not JSON */ }
        resolve({
          ok: response.statusCode >= 200 && response.statusCode < 300,
          status: response.statusCode,
          body: parsed,
          raw: raw.slice(0, 400)
        });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({
        ok: false, status: 0,
        message: 'The beta server did not answer in time. Free Render services sleep when idle — ' +
          'open ' + baseUrl + ' in a browser tab, wait for it to load, then try again.'
      });
    });
    req.on('error', e => resolve({
      ok: false, status: 0,
      message: 'Could not reach the beta server (' + (e.code || e.message) + ').'
    }));

    if (payload) req.write(payload);
    req.end();
  });
}

/** Signs in to the beta server's dashboard API. */
async function peerLogin(peer) {
  const r = await peerRequest(peer.url, '/api/admin/login', {
    method: 'POST',
    body: { username: peer.username, password: peer.password }
  });
  if (r.message) return { ok: false, message: r.message };
  if (!r.ok || !r.body || !r.body.token) {
    return {
      ok: false,
      message: r.status === 401
        ? 'The beta server refused that username or password.'
        : 'The beta server answered ' + r.status + ' when signing in.'
    };
  }
  return { ok: true, token: r.body.token };
}

/**
 * Copies a published build onto the beta server.
 *
 * It is written into BOTH of the peer's channels on purpose. A beta build
 * that predates release channels sends no channel at all and is therefore
 * answered from the peer's live record; a newer one asks for `beta`. Since
 * that server exists only to serve beta devices, filling both means every
 * beta build — old or new — is offered the same thing, instead of the older
 * ones silently never updating again.
 */
async function publishToBetaPeer(record) {
  const d = db();
  const peer = d.betaPeer;
  if (!peer || !peer.url || !peer.username) {
    return { ok: false, message: 'No beta server is configured yet.' };
  }
  if (!record) return { ok: false, message: 'Nothing is published on the beta channel to send.' };

  const auth = await peerLogin(peer);
  if (!auth.ok) {
    peer.lastOk = false; peer.lastError = auth.message; save();
    return auth;
  }

  const payload = {
    versionCode: record.versionCode || 0,
    versionName: record.versionName || '',
    apkUrl: record.apkUrl || '',
    desktopUrl: record.desktopUrl || '',
    desktopVersion: record.desktopVersion || '',
    desktopMandatory: record.desktopMandatory !== false,
    mandatory: record.mandatory !== false,
    notes: record.notes || '',
    // The peer re-checks the links otherwise, which doubles the wait and can
    // fail on a cold GitHub CDN even though this server just verified them.
    skipLinkCheck: true
  };

  const results = [];
  for (const channel of ['live', 'beta']) {
    const r = await peerRequest(peer.url, '/api/admin/app/version', {
      method: 'POST', token: auth.token, body: { ...payload, channel }
    });
    results.push({ channel, ok: r.ok, status: r.status, message: r.message || (r.body && r.body.message) });
  }

  const good = results.filter(r => r.ok).length;
  peer.lastPublishAt = Date.now();
  peer.lastOk = good > 0;
  peer.lastError = good > 0 ? null : (results[0].message || 'The beta server rejected the update.');
  save();

  if (!good) return { ok: false, message: peer.lastError };
  return {
    ok: true,
    message: good === 2
      ? 'Sent to the beta server.'
      : 'Sent to the beta server (it is running an older build, so one channel was used).'
  };
}

/*
  =========================================================================
  BROWSING HISTORY REPORTS

  What was asked for:

    "Dar 15 divase aakha device ni browsing history no ek auto-email Admin na
     email ID par jato rehvo joiye … format: Serial No, Date, Device Name,
     URL, ane Time spent … Admin icche to 2-3 specific device ni history
     Admin sivay koi anya vyakti ne pan mokli shake … Admin frequency (jem ke
     10 divas, 15 divas) ane samavala vyakti nu email ID set kari shake che,
     ane admin dvara j aa facility enable ke disable/delete kari shakashi."

  Modelled as a list of SCHEDULES rather than one hard-coded admin address.
  "Every 15 days to the admin" is then simply the first schedule, and
  "these 3 devices, every 10 days, to the class teacher" is the second —
  same code, no special cases.
  =========================================================================
*/

const HISTORY_CAP = 12000;          // total rows kept
const HISTORY_MAX_AGE_MS = 75 * 24 * 60 * 60 * 1000;   // a bit over two cycles

/** Adds reported rows, de-duplicating and pruning. */
function recordHistory(user, deviceId, deviceName, rows) {
  const d = db();
  if (!Array.isArray(d.history)) d.history = [];

  let added = 0;
  for (const row of rows) {
    const url = String((row && row.url) || '').trim();
    if (!/^https?:\/\//i.test(url)) continue;          // no about:, no file://
    const at = Number(row.at) || Date.now();
    const seconds = Math.max(0, Math.min(86400, Math.round(Number(row.seconds) || 0)));

    // The same page, same device, same second is the same visit — devices
    // re-send a window of history so nothing is lost when a request fails.
    const dup = d.history.find(h =>
      h.deviceId === deviceId && h.url === url && Math.abs(h.at - at) < 1500);
    if (dup) {
      if (seconds > (dup.seconds || 0)) dup.seconds = seconds;   // longer visit wins
      continue;
    }

    d.history.push({
      id: 'h-' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36),
      userId: user.id,
      deviceId,
      deviceName: deviceName || 'Unknown device',
      url,
      title: String((row && row.title) || '').slice(0, 300),
      at,
      seconds
    });
    added++;
  }

  const cutoff = Date.now() - HISTORY_MAX_AGE_MS;
  d.history = d.history.filter(h => h.at >= cutoff);
  if (d.history.length > HISTORY_CAP) {
    d.history.sort((a, b) => a.at - b.at);
    d.history = d.history.slice(d.history.length - HISTORY_CAP);
  }
  return added;
}

/**
 * Devices push their history here.
 *
 * Deleting history in the browser is a SOFT delete — the row stays in this
 * database, which is the whole point of the report. The device therefore
 * sends hidden rows too.
 */
app.post('/api/me/history', deviceAuth, (req, res) => {
  const d = db();
  const user = d.users.find(u => u.id === req.device.sub);
  if (!user) return res.status(404).json({ message: 'Account no longer exists.' });

  const body = req.body || {};
  const rows = Array.isArray(body.entries) ? body.entries.slice(0, 500) : [];
  const deviceId = String(body.deviceId || req.device.dev || 'unknown').slice(0, 80);
  const deviceName = String(body.deviceName || req.device.dev || '').slice(0, 80);

  const added = recordHistory(user, deviceId, deviceName, rows);
  if (added) save();
  res.json({ ok: true, added, kept: d.history.length });
});

/** Seconds -> "1h 04m" / "3m 20s" / "12s" */
function humanDuration(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm ' + String(s % 60).padStart(2, '0') + 's';
  const h = Math.floor(m / 60);
  return h + 'h ' + String(m % 60).padStart(2, '0') + 'm';
}

/** The rows a schedule covers. */
function historyFor(schedule, sinceMs) {
  const d = db();
  const devices = Array.isArray(schedule.devices) ? schedule.devices.filter(Boolean) : [];
  return (d.history || [])
    .filter(h => h.at >= sinceMs)
    .filter(h => devices.length === 0 || devices.includes(h.deviceId) || devices.includes(h.deviceName))
    .sort((a, b) => a.at - b.at);
}

function escapeHtml(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Builds the exact table that was asked for. */
function buildReport(schedule, rows, periodFrom, periodTo) {
  const fmt = ms => new Date(ms).toLocaleString('en-GB', { timeZone: 'Asia/Kolkata' });
  const head = ['Serial No', 'Date', 'Device Name', 'URL', 'Time spent'];

  const bodyRows = rows.map((h, i) => [
    String(i + 1),
    fmt(h.at),
    h.deviceName || '—',
    h.url,
    humanDuration(h.seconds)
  ]);

  const html =
    '<div style="font-family:Segoe UI,Arial,sans-serif;color:#222">' +
    '<h2 style="color:#2A3F8F;margin:0 0 4px">SMVS Browser — browsing history</h2>' +
    '<p style="margin:0 0 14px;color:#666">' +
    escapeHtml(fmt(periodFrom)) + ' &rarr; ' + escapeHtml(fmt(periodTo)) +
    ' &middot; ' + rows.length + ' visits' +
    (schedule.devices && schedule.devices.length
      ? ' &middot; devices: ' + escapeHtml(schedule.devices.join(', '))
      : ' &middot; all devices') +
    '</p>' +
    '<table cellspacing="0" cellpadding="6" border="0" style="border-collapse:collapse;font-size:13px">' +
    '<tr style="background:#2A3F8F;color:#fff">' +
    head.map(h => '<th align="left">' + escapeHtml(h) + '</th>').join('') + '</tr>' +
    bodyRows.map((r, i) =>
      '<tr style="background:' + (i % 2 ? '#f6f7fb' : '#fff') + '">' +
      r.map((c, ci) =>
        '<td style="border-bottom:1px solid #e4e6ef;' +
        (ci === 3 ? 'max-width:520px;word-break:break-all;' : 'white-space:nowrap;') + '">' +
        escapeHtml(c) + '</td>').join('') +
      '</tr>').join('') +
    '</table>' +
    (rows.length ? '' : '<p style="color:#888">No visits were recorded in this period.</p>') +
    '</div>';

  const text = [head.join(' | ')]
    .concat(bodyRows.map(r => r.join(' | ')))
    .join('\n');

  return {
    subject: 'SMVS Browser history — ' + new Date(periodTo).toLocaleDateString('en-GB') +
      ' (' + rows.length + ' visits)',
    html,
    text
  };
}

// ---- sending mail ----

/**
 * Sends one email using the SMTP details the administrator saved.
 *
 * `nodemailer` is required lazily and inside a try: if a deployment has not
 * reinstalled dependencies yet, the whole server must still boot and keep
 * filtering. A browser that stops working because an email library is
 * missing would be a far worse failure than a report not going out.
 */
/*
  ---------------------------------------------------------------- SMTP

  Written against `net`/`tls` rather than nodemailer, deliberately.

  The first version required nodemailer, and the dashboard duly reported
  "The nodemailer package is not installed on the server" — because
  installing it needs a package.json upload and a redeploy, and until that
  happens the whole feature is dead. Sending an email is a short, very
  well-specified conversation; depending on a package for it turned a
  finished feature into a deployment errand.

  Supports both of the ways mail servers are reached:
    * port 465 — TLS from the first byte
    * port 587 — plain, then STARTTLS (never plain after that)
*/
const net = require('net');
const tls = require('tls');

function smtpSend(cfg, { to, subject, html, text }) {
  return new Promise(resolve => {
    const port = Number(cfg.port) || 587;
    const host = String(cfg.host).trim();
    const from = String(cfg.from || cfg.user).trim();
    const tlsFromStart = cfg.secure === true || port === 465;

    let socket = null;
    let buffer = '';
    let done = false;
    let upgraded = tlsFromStart;
    let state = 'greeting';
    let caps = [];              // what EHLO said this server can do

    const finish = (ok, message) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { socket && socket.destroy(); } catch { /* already gone */ }
      resolve({ ok, message });
    };
    const timer = setTimeout(
      () => finish(false, 'The mail server did not answer in time.'), 45000);

    const b64 = v => Buffer.from(String(v), 'utf8').toString('base64');
    const header = v => /^[\x20-\x7e]*$/.test(v) ? v : '=?UTF-8?B?' + b64(v) + '?=';

    const boundary = 'smvs-' + Math.random().toString(36).slice(2);
    const wrapped = v => b64(v || '').replace(/(.{76})/g, '$1\r\n');
    const message = [
      'From: ' + header('SMVS Browser') + ' <' + from + '>',
      'To: ' + to,
      'Subject: ' + header(subject),
      'MIME-Version: 1.0',
      'Date: ' + new Date().toUTCString(),
      'Content-Type: multipart/alternative; boundary="' + boundary + '"',
      '',
      '--' + boundary,
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: base64', '',
      wrapped(text), '',
      '--' + boundary,
      'Content-Type: text/html; charset=UTF-8',
      'Content-Transfer-Encoding: base64', '',
      wrapped(html), '',
      '--' + boundary + '--', ''
    ].join('\r\n');

    const send = line => { try { socket.write(line); } catch { /* closing */ } };

    /*
      One reply, one step. Written as a named state rather than an index
      into a list: the list version silently re-ran the first step when a
      reply arrived that it was not expecting, and the conversation stalled
      right after EHLO with no error at all.
    */
    function onReply(code, line) {
      switch (state) {
        case 'greeting':
          if (code !== 220) return finish(false, 'The mail server said: ' + line.trim());
          state = 'ehlo'; return send('EHLO smvs-browser\r\n');

        case 'ehlo': {
          if (code !== 250) return finish(false, 'The mail server refused EHLO: ' + line.trim());

          /*
            Only offer STARTTLS if the server said it speaks it.

            Sending STARTTLS blindly breaks against anything that does not —
            an internal relay, for instance — and the failure looks like a
            password problem. Equally, a password must never travel in clear
            over the internet, so a public server that does not offer
            encryption is refused rather than trusted.
          */
          if (!upgraded) {
            if (caps.some(c => /STARTTLS/i.test(c))) {
              state = 'starttls'; return send('STARTTLS\r\n');
            }
            const local = /^(localhost|127\.|::1|0\.0\.0\.0)/i.test(host);
            if (!local) {
              return finish(false,
                'This mail server does not offer an encrypted connection, so the ' +
                'password will not be sent. Try port 465 with SSL ticked.');
            }
          }
          state = 'auth'; return send('AUTH LOGIN\r\n');
        }

        case 'starttls':
          if (code !== 220) {
            return finish(false, 'The mail server will not start an encrypted session. ' +
              'Try port 465 with SSL ticked.');
          }
          state = 'upgrading';
          return upgrade();

        case 'auth':
          if (code !== 334) return finish(false, 'The mail server refused AUTH LOGIN.');
          state = 'auth-user'; return send(b64(cfg.user) + '\r\n');

        case 'auth-user':
          if (code !== 334) return finish(false, 'The mail server rejected the username.');
          state = 'auth-pass'; return send(b64(cfg.pass) + '\r\n');

        case 'auth-pass':
          if (code !== 235) {
            return finish(false, 'The mail server rejected that username or password. ' +
              'Gmail and Yahoo need an App Password, not the normal one.');
          }
          state = 'from'; return send('MAIL FROM:<' + from + '>\r\n');

        case 'from':
          if (code !== 250) return finish(false, 'The sender address was refused: ' + line.trim());
          state = 'rcpt'; return send('RCPT TO:<' + to + '>\r\n');

        case 'rcpt':
          if (code !== 250 && code !== 251) {
            return finish(false, 'The recipient address was refused: ' + line.trim());
          }
          state = 'data'; return send('DATA\r\n');

        case 'data':
          if (code !== 354) return finish(false, 'The mail server would not accept a message.');
          state = 'body';
          // A line consisting of a single dot would end the message early.
          return send(message.replace(/\r\n\./g, '\r\n..') + '\r\n.\r\n');

        case 'body':
          if (code !== 250) return finish(false, 'The message was not accepted: ' + line.trim());
          state = 'quit'; return send('QUIT\r\n');

        case 'quit':
          return finish(true, 'Sent to ' + to);

        default:
          return;
      }
    }

    function attach() {
      socket.setEncoding('utf8');
      socket.removeAllListeners('data');
      socket.on('data', chunk => {
        buffer += chunk;
        let i;
        while ((i = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, i + 1);
          buffer = buffer.slice(i + 1);
          if (/^\d{3}-/.test(line)) {              // multi-line reply, not the last
            if (state === 'ehlo') caps.push(line.slice(4).trim());
            continue;
          }
          if (state === 'ehlo') caps.push(line.slice(4).trim());
          const code = parseInt(line.slice(0, 3), 10);
          if (!Number.isNaN(code)) onReply(code, line);
        }
      });
      socket.on('error', e => finish(false,
        'Could not reach the mail server (' + (e.code || e.message) + ').'));
      socket.on('close', () => { if (!done) finish(false, 'The mail server closed the connection.'); });
    }

    function upgrade() {
      const plain = socket;
      plain.removeAllListeners('data');
      plain.removeAllListeners('close');
      socket = tls.connect({ socket: plain, servername: host, rejectUnauthorized: false }, () => {
        upgraded = true;
        buffer = '';
        caps = [];
        state = 'ehlo';
        attach();
        send('EHLO smvs-browser\r\n');
      });
      socket.on('error', e => finish(false, 'Encryption failed: ' + e.message));
    }

    try {
      socket = tlsFromStart
        ? tls.connect({ host, port, servername: host, rejectUnauthorized: false })
        : net.connect({ host, port });
    } catch (e) {
      return finish(false, 'Could not open a connection: ' + e.message);
    }
    attach();
  });
}

/*
  ---------------------------------------------- sending over HTTPS instead

  Why this exists: Render's free web services block outbound traffic to the
  SMTP ports (25, 465 and 587) at the firewall, and have done since
  26 September 2025. The connection is dropped rather than refused, so it
  shows up as ETIMEDOUT after a long wait — which looks exactly like a wrong
  password or a typo in the host, and sent us looking in the wrong place.

  An email API speaks ordinary HTTPS on port 443, which is not blocked. Both
  of the ones below have a free tier that needs no card, so nothing has to be
  paid for to make reports work.
*/
function httpsJson(url, { method = 'POST', headers = {}, body = null, timeoutMs = 30000 }) {
  return new Promise(resolve => {
    let target;
    try { target = new URL(url); } catch { return resolve({ ok: false, message: 'Bad URL' }); }
    const payload = body ? JSON.stringify(body) : null;
    const req = https.request(target, {
      method,
      headers: {
        Accept: 'application/json',
        'User-Agent': 'SMVS-Browser-Server',
        ...(payload ? { 'Content-Type': 'application/json',
                        'Content-Length': Buffer.byteLength(payload) } : {}),
        ...headers
      },
      timeout: timeoutMs
    }, response => {
      let raw = '';
      response.on('data', c => { raw += c; });
      response.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(raw); } catch { /* not JSON */ }
        resolve({
          ok: response.statusCode >= 200 && response.statusCode < 300,
          status: response.statusCode, body: parsed, raw: raw.slice(0, 300)
        });
      });
    });
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, message: 'timed out' }); });
    req.on('error', e => resolve({ ok: false, message: e.code || e.message }));
    if (payload) req.write(payload);
    req.end();
  });
}

/** Brevo — free tier, no card, sender confirmed by a code sent to the address. */
async function sendViaBrevo(cfg, { to, subject, html, text }) {
  const r = await httpsJson('https://api.brevo.com/v3/smtp/email', {
    headers: { 'api-key': cfg.apiKey },
    body: {
      sender: { email: cfg.from, name: 'SMVS Browser' },
      to: [{ email: to }],
      subject, htmlContent: html, textContent: text
    }
  });
  if (r.ok) return { ok: true, message: 'Sent to ' + to + ' through Brevo.' };
  const why = (r.body && (r.body.message || r.body.code)) || r.message || ('HTTP ' + r.status);
  if (r.status === 401) {
    return { ok: false, message: 'Brevo refused the API key. Copy it again from ' +
      'Brevo → SMTP & API → API keys.' };
  }
  if (r.status === 400 && /sender/i.test(String(why))) {
    return { ok: false, message: 'Brevo does not recognise "' + cfg.from + '" as a verified ' +
      'sender yet. Add it in Brevo → Senders, confirm the code it emails you, then try again.' };
  }
  return { ok: false, message: 'Brevo refused it: ' + why };
}

/** Resend — also free to start, also plain HTTPS. */
async function sendViaResend(cfg, { to, subject, html, text }) {
  const r = await httpsJson('https://api.resend.com/emails', {
    headers: { Authorization: 'Bearer ' + cfg.apiKey },
    body: { from: 'SMVS Browser <' + cfg.from + '>', to: [to], subject, html, text }
  });
  if (r.ok) return { ok: true, message: 'Sent to ' + to + ' through Resend.' };
  const why = (r.body && (r.body.message || r.body.name)) || r.message || ('HTTP ' + r.status);
  if (r.status === 401 || r.status === 403) {
    return { ok: false, message: 'Resend refused the API key.' };
  }
  return { ok: false, message: 'Resend refused it: ' + why };
}

async function sendMail({ to, subject, html, text }) {
  const cfg = db().mail;
  if (!cfg) return { ok: false, message: 'Email is not set up yet.' };

  try {
    if (cfg.provider === 'brevo')  return await sendViaBrevo(cfg,  { to, subject, html, text });
    if (cfg.provider === 'resend') return await sendViaResend(cfg, { to, subject, html, text });

    if (!cfg.host || !cfg.user) {
      return { ok: false, message: 'Email is not set up yet — choose how to send first.' };
    }
    const r = await smtpSend(cfg, { to, subject, html, text });

    /*
      Turn the one failure people actually hit into an answer instead of a
      riddle. A dropped packet on 25/465/587 is what a blocked port looks
      like, and no amount of retrying or re-typing the password will fix it.
    */
    if (!r.ok && /ETIMEDOUT|timed out|did not answer/i.test(r.message || '')) {
      return { ok: false, message:
        'Could not reach the mail server. Free Render services block SMTP ports ' +
        '(25, 465 and 587) at the firewall, so no SMTP settings can work there. ' +
        'Switch "How to send" to Brevo or Resend — those send over ordinary HTTPS, ' +
        'are free, and need no card.' };
    }
    return r;
  } catch (e) {
    return { ok: false, message: 'Sending failed: ' + (e.message || String(e)) };
  }
}

/*
  ------------------------------------------------- working out the SMTP host

  Nobody should have to know what "smtp.gmail.com, port 587, STARTTLS" means.
  The address already says which provider it is, so the settings are looked
  up from it. Only when the provider genuinely cannot be identified do the
  two boxes open up for typing.

  Two sources, in order:
    1. a table of the providers people actually use here;
    2. failing that, the domain's own MX records — a school on Google
       Workspace has an @school.org address but Gmail's servers behind it,
       and the MX record is what gives that away.
*/
const SMTP_PROVIDERS = [
  { match: ['gmail.com', 'googlemail.com'],
    host: 'smtp.gmail.com', port: 587, secure: false, label: 'Gmail',
    note: 'Gmail needs an App Password, not your normal password.' },
  { match: ['outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'live.in', 'hotmail.co.uk'],
    host: 'smtp-mail.outlook.com', port: 587, secure: false, label: 'Outlook' },
  { match: ['yahoo.com', 'yahoo.in', 'yahoo.co.in', 'ymail.com'],
    host: 'smtp.mail.yahoo.com', port: 465, secure: true, label: 'Yahoo',
    note: 'Yahoo needs an App Password.' },
  { match: ['rediffmail.com', 'rediff.com'],
    host: 'smtp.rediffmail.com', port: 465, secure: true, label: 'Rediffmail' },
  { match: ['zoho.com', 'zoho.in', 'zohomail.com'],
    host: 'smtp.zoho.com', port: 465, secure: true, label: 'Zoho' },
  { match: ['icloud.com', 'me.com', 'mac.com'],
    host: 'smtp.mail.me.com', port: 587, secure: false, label: 'iCloud',
    note: 'iCloud needs an app-specific password.' },
  { match: ['gmx.com', 'gmx.net'],
    host: 'mail.gmx.com', port: 587, secure: false, label: 'GMX' },
  { match: ['yandex.com', 'yandex.ru'],
    host: 'smtp.yandex.com', port: 465, secure: true, label: 'Yandex' },
  { match: ['aol.com'],
    host: 'smtp.aol.com', port: 587, secure: false, label: 'AOL' },
  { match: ['office365.com', 'microsoft.com'],
    host: 'smtp.office365.com', port: 587, secure: false, label: 'Microsoft 365' }
];
/** Whose mail servers actually sit behind a domain. */
const MX_HINTS = [
  { has: ['google.com', 'googlemail.com'], host: 'smtp.gmail.com', port: 587, secure: false,
    label: 'Google Workspace',
    note: 'Google Workspace needs an App Password.' },
  { has: ['outlook.com', 'protection.outlook.com'], host: 'smtp.office365.com', port: 587,
    secure: false, label: 'Microsoft 365' },
  { has: ['zoho.com', 'zoho.eu', 'zoho.in'], host: 'smtp.zoho.com', port: 465, secure: true,
    label: 'Zoho Mail' },
  { has: ['yandex'], host: 'smtp.yandex.com', port: 465, secure: true, label: 'Yandex' },
  { has: ['secureserver.net'], host: 'smtpout.secureserver.net', port: 465, secure: true,
    label: 'GoDaddy' },
  { has: ['hostinger'], host: 'smtp.hostinger.com', port: 465, secure: true, label: 'Hostinger' },
  { has: ['zoho'], host: 'smtp.zoho.com', port: 465, secure: true, label: 'Zoho Mail' }
];

app.get('/api/admin/mail/suggest', requireAdmin, async (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  const at = email.lastIndexOf('@');
  if (at < 1 || at === email.length - 1) {
    return res.json({ known: false, reason: 'not an email address' });
  }
  const domain = email.slice(at + 1);

  const direct = SMTP_PROVIDERS.find(p => p.match.includes(domain));
  if (direct) {
    return res.json({
      known: true, source: 'provider', label: direct.label,
      host: direct.host, port: direct.port, secure: direct.secure,
      note: direct.note || ''
    });
  }

  // A custom domain: ask DNS who handles its mail.
  let mx = [];
  try {
    mx = await new Promise(resolve => {
      const t = setTimeout(() => resolve([]), 6000);
      dns.resolveMx(domain, (err, list) => {
        clearTimeout(t);
        resolve(err || !list ? [] : list);
      });
    });
  } catch { mx = []; }

  const names = mx.map(m => String(m.exchange || '').toLowerCase()).join(' ');
  const hint = names && MX_HINTS.find(h => h.has.some(x => names.includes(x)));
  if (hint) {
    return res.json({
      known: true, source: 'mx', label: hint.label,
      host: hint.host, port: hint.port, secure: hint.secure, note: hint.note || ''
    });
  }

  // A sensible guess for a plain company domain, offered but not forced.
  res.json({
    known: false,
    guessHost: 'smtp.' + domain,
    guessPort: 587,
    mx: mx.map(m => m.exchange).slice(0, 3),
    reason: mx.length
      ? 'This domain uses its own mail servers.'
      : 'No mail servers found for this domain.'
  });
});

app.get('/api/admin/mail', requireAdmin, (_req, res) => {
  const m = db().mail;
  const ready = !!(m && (m.provider === 'smtp' ? (m.host && m.user) : m.apiKey));
  res.json({
    provider: (m && m.provider) || 'brevo',
    hasKey: !!(m && m.apiKey),
    configured: ready,
    host: (m && m.host) || '',
    port: (m && m.port) || 587,
    secure: !!(m && m.secure),
    user: (m && m.user) || '',
    from: (m && m.from) || ''
    // the password is never sent back
  });
});

app.put('/api/admin/mail', requireAdmin, (req, res) => {
  const b = req.body || {};
  const d = db();
  const existing = d.mail || {};
  const provider = ['brevo', 'resend', 'smtp'].includes(b.provider) ? b.provider : 'brevo';
  const from = String(b.from || '').trim();

  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(from)) {
    return res.status(400).json({ message: 'Enter the email address the reports come from.' });
  }

  if (provider === 'brevo' || provider === 'resend') {
    const apiKey = String(b.apiKey || '').trim() || existing.apiKey || '';
    if (!apiKey) {
      return res.status(400).json({
        message: 'Paste the API key from ' + (provider === 'brevo' ? 'Brevo' : 'Resend') + '.'
      });
    }
    d.mail = { provider, from, apiKey };
    save();
    return res.json({ ok: true, provider });
  }

  const host = String(b.host || '').trim();
  const user = String(b.user || '').trim() || from;
  const pass = String(b.pass || '') || existing.pass || '';
  if (!host) return res.status(400).json({ message: 'Enter the SMTP host.' });
  if (!pass) return res.status(400).json({ message: 'Enter the password (for Gmail, an App Password).' });

  d.mail = {
    provider: 'smtp', host, port: Number(b.port) || 587,
    secure: b.secure === true, user, pass, from
  };
  save();
  res.json({ ok: true, provider: 'smtp' });
});

app.delete('/api/admin/mail', requireAdmin, (_req, res) => {
  const d = db(); d.mail = null; save();
  res.json({ ok: true });
});

app.post('/api/admin/mail/test', requireAdmin, async (req, res) => {
  const to = String((req.body || {}).to || '').trim();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to)) {
    return res.status(400).json({ message: 'Enter the address to send the test to.' });
  }
  const r = await sendMail({
    to,
    subject: 'SMVS Browser — test email',
    text: 'If you can read this, the history reports will reach you.',
    html: '<p>If you can read this, the history reports will reach you.</p>'
  });
  if (!r.ok) return res.status(400).json({ message: r.message });
  res.json(r);
});

// ---- report schedules ----

function cleanSchedule(b, existing = {}) {
  const email = String(b.email != null ? b.email : existing.email || '').trim();
  const everyDays = Math.max(1, Math.min(365,
    parseInt(b.everyDays != null ? b.everyDays : existing.everyDays, 10) || 15));
  const devices = Array.isArray(b.devices)
    ? b.devices.map(v => String(v).trim()).filter(Boolean).slice(0, 50)
    : (existing.devices || []);
  return {
    email,
    everyDays,
    devices,
    label: String(b.label != null ? b.label : existing.label || '').trim().slice(0, 60),
    enabled: b.enabled != null ? b.enabled !== false : existing.enabled !== false
  };
}

app.get('/api/admin/reports', requireAdmin, (_req, res) => {
  const d = db();
  const devices = [...new Set((d.history || []).map(h => h.deviceName).filter(Boolean))];
  res.json({
    reports: d.reports || [],
    knownDevices: devices,
    historyRows: (d.history || []).length,
    mailConfigured: !!(d.mail && d.mail.host && d.mail.user)
  });
});

app.post('/api/admin/reports', requireAdmin, (req, res) => {
  const c = cleanSchedule(req.body || {});
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(c.email)) {
    return res.status(400).json({ message: 'Enter a valid email address.' });
  }
  const d = db();
  if (!Array.isArray(d.reports)) d.reports = [];
  const row = {
    id: 'r-' + Math.random().toString(36).slice(2, 10),
    ...c,
    lastSentAt: 0,
    createdAt: Date.now()
  };
  d.reports.push(row);
  save();
  res.json({ ok: true, report: row });
});

app.put('/api/admin/reports/:id', requireAdmin, (req, res) => {
  const d = db();
  const row = (d.reports || []).find(r => r.id === req.params.id);
  if (!row) return res.status(404).json({ message: 'That schedule no longer exists.' });
  Object.assign(row, cleanSchedule(req.body || {}, row));
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(row.email)) {
    return res.status(400).json({ message: 'Enter a valid email address.' });
  }
  save();
  res.json({ ok: true, report: row });
});

app.delete('/api/admin/reports/:id', requireAdmin, (req, res) => {
  const d = db();
  const before = (d.reports || []).length;
  d.reports = (d.reports || []).filter(r => r.id !== req.params.id);
  save();
  res.json({ ok: true, removed: before - d.reports.length });
});

/** Builds and sends one schedule's report now. */
async function runSchedule(row, { markSent = true } = {}) {
  const to = new Date().getTime();
  const from = row.lastSentAt || (to - row.everyDays * 24 * 60 * 60 * 1000);
  const rows = historyFor(row, from);
  const mail = buildReport(row, rows, from, to);

  const result = await sendMail({ to: row.email, ...mail });
  if (result.ok && markSent) {
    row.lastSentAt = to;
    row.lastError = null;
    save();
  } else if (!result.ok) {
    row.lastError = result.message;
    save();
  }
  return { ...result, rows: rows.length };
}

app.post('/api/admin/reports/:id/send', requireAdmin, async (req, res) => {
  const row = (db().reports || []).find(r => r.id === req.params.id);
  if (!row) return res.status(404).json({ message: 'That schedule no longer exists.' });
  // A manual send is for checking it works; it must not move the clock and
  // make the next scheduled report skip a fortnight of history.
  const r = await runSchedule(row, { markSent: false });
  if (!r.ok) return res.status(400).json({ message: r.message });
  res.json(r);
});

/** Preview without sending — so the admin can see the table first. */
app.get('/api/admin/reports/:id/preview', requireAdmin, (req, res) => {
  const row = (db().reports || []).find(r => r.id === req.params.id);
  if (!row) return res.status(404).json({ message: 'That schedule no longer exists.' });
  const to = Date.now();
  const from = row.lastSentAt || (to - row.everyDays * 24 * 60 * 60 * 1000);
  const rows = historyFor(row, from);
  res.type('html').send(buildReport(row, rows, from, to).html);
});

/*
  The clock.

  Checked hourly rather than daily: a free-tier server restarts often, and a
  daily timer that only fires 24 hours after boot would, on a service that
  sleeps, effectively never fire at all. Each schedule carries its own
  lastSentAt, so an hourly check cannot send twice.
*/
const REPORT_TICK_MS = 60 * 60 * 1000;

async function reportTick() {
  try {
    const d = db();
    if (!Array.isArray(d.reports) || !d.reports.length) return;
    if (!d.mail || !d.mail.host) return;               // nothing to send with

    const now = Date.now();
    for (const row of d.reports) {
      if (row.enabled === false) continue;
      const due = (row.lastSentAt || 0) + row.everyDays * 24 * 60 * 60 * 1000;
      if (row.lastSentAt && now < due) continue;
      // First run: start the clock instead of emailing an empty table.
      if (!row.lastSentAt) { row.lastSentAt = now; save(); continue; }
      const r = await runSchedule(row);
      console.log('[report]', row.email, r.ok ? 'sent ' + r.rows + ' rows' : 'FAILED ' + r.message);
    }
  } catch (e) {
    console.log('[report] tick failed:', e.message);
  }
}

if (process.env.NODE_ENV !== 'test') {
  setInterval(reportTick, REPORT_TICK_MS).unref();
}

// ---- the address all devices should use ----

app.get('/api/admin/server-url', requireAdmin, (req, res) => {
  const d = db();
  const devices = (d.devices || []).length;
  res.json({
    serverUrl: d.managedServerUrl || '',
    // What the devices are being told right now, so the page can show the
    // effect rather than just the setting.
    devices,
    seen: (d.devices || []).filter(x => (Date.now() - (x.lastSeenAt || 0)) < 7 * 86400000).length
  });
});

app.put('/api/admin/server-url', requireAdmin, (req, res) => {
  const raw = String((req.body || {}).serverUrl || '').trim().replace(/\/+$/, '');
  if (raw && !/^https?:\/\//i.test(raw)) {
    return res.status(400).json({ message: 'The address must start with https://' });
  }
  const d = db();
  d.managedServerUrl = raw;

  /*
    Every device's policy revision has to move, or the long polls they are
    already holding will not consider anything to have changed and the new
    address would not arrive until the next restart.
  */
  const now = Date.now();
  for (const u of d.users) u.updatedAt = now;
  save();
  notifyPolicyChanged();

  res.json({ ok: true, serverUrl: raw, devicesNotified: (d.devices || []).length });
});

// ---- configuring the beta server ----

app.get('/api/admin/peer/beta', requireAdmin, (_req, res) => {
  const p = db().betaPeer;
  // The password is never sent back to the browser.
  res.json({
    configured: !!(p && p.url && p.username),
    url: (p && p.url) || '',
    username: (p && p.username) || '',
    lastOk: p ? p.lastOk === true : null,
    lastPublishAt: (p && p.lastPublishAt) || 0,
    lastError: (p && p.lastError) || null
  });
});

app.put('/api/admin/peer/beta', requireAdmin, (req, res) => {
  const b = req.body || {};
  const url = String(b.url || '').trim().replace(/\/+$/, '');
  const username = String(b.username || '').trim();
  const password = String(b.password || '');

  if (!url || !username) {
    return res.status(400).json({ message: 'Beta server address and username are both needed.' });
  }
  if (!/^https?:\/\//i.test(url)) {
    return res.status(400).json({ message: 'The address must start with https://' });
  }

  const d = db();
  const existing = d.betaPeer || {};
  if (!password && !existing.password) {
    return res.status(400).json({ message: 'Enter the beta dashboard password.' });
  }

  d.betaPeer = {
    url,
    username,
    // Left blank, the saved password is kept — so the address can be edited
    // without retyping it.
    password: password || existing.password,
    lastOk: existing.lastOk === true,
    lastPublishAt: existing.lastPublishAt || 0,
    lastError: existing.lastError || null
  };
  save();
  res.json({ ok: true, url, username });
});

app.delete('/api/admin/peer/beta', requireAdmin, (_req, res) => {
  const d = db();
  d.betaPeer = null;
  save();
  res.json({ ok: true });
});

app.post('/api/admin/peer/beta/test', requireAdmin, async (_req, res) => {
  const peer = db().betaPeer;
  if (!peer || !peer.url) return res.status(400).json({ message: 'No beta server is configured yet.' });

  const health = await peerRequest(peer.url, '/api/health');
  if (health.message) return res.status(400).json({ message: health.message });
  if (!health.ok) {
    return res.status(400).json({ message: 'The beta server answered ' + health.status + ' at /api/health.' });
  }

  const auth = await peerLogin(peer);
  if (!auth.ok) return res.status(400).json({ message: auth.message });

  res.json({
    ok: true,
    message: 'Connected. The beta server is reachable and the password works.',
    durable: !!(health.body && health.body.durable),
    users: (health.body && health.body.users) || 0
  });
});

/** Re-sends whatever is on the beta channel, without republishing. */
app.post('/api/admin/peer/beta/push', requireAdmin, async (_req, res) => {
  const result = await publishToBetaPeer(db().appVersionBeta);
  if (!result.ok) return res.status(400).json({ message: result.message });
  res.json(result);
});

/*
  =======================================================================
  ONE BUTTON: promote a release from one channel to the other

  The manual route works, but it means pasting four links every time. What
  was asked for was a single button that sends "the same code" across.

  It cannot literally copy the file: Android and Windows treat the beta app
  as a different application, so beta needs its own build. What it CAN do is
  find that build. Both are attached to the same GitHub release, and the
  names differ by one word, so the beta file is derived from the live one
  and then PROVED to be the right thing before anything is published:

    * the APK is downloaded and its package name read — it must really end
      in .beta (or really not, when promoting the other way);
    * the installer is probed and must really answer with a Windows binary.

  Nothing is guessed at and published blind. If the beta file is not on the
  release, the answer says exactly which names were looked for.
  =======================================================================
*/

/** Plausible names for the same build on the other channel. */
function otherChannelUrls(url, toBeta) {
  if (!url) return [];
  const cut = url.lastIndexOf('/');
  if (cut < 0) return [];
  const base = url.slice(0, cut + 1);
  const name = url.slice(cut + 1);
  const out = [];
  const add = n => { const u = base + n; if (n !== name && !out.includes(u)) out.push(u); };

  if (toBeta) {
    // SMVS-Browser-v8.3.apk        -> SMVS-Browser-BETA-v8.3.apk
    add(name.replace(/-v(\d)/, '-BETA-v$1'));
    add(name.replace(/-v(\d)/, '-Beta-v$1'));
    // SMVS-Browser-Setup-3.10.0.exe -> SMVS-Browser-Beta-Setup-3.10.0.exe
    add(name.replace(/-Setup-/i, '-Beta-Setup-'));
    add(name.replace(/-Setup-/i, '-BETA-Setup-'));
    // last resort: a word in front of the file name
    add('BETA-' + name);
    add('Beta-' + name);
  } else {
    add(name.replace(/-BETA-v/i, '-v'));
    add(name.replace(/-Beta-Setup-/i, '-Setup-'));
    add(name.replace(/-BETA-Setup-/i, '-Setup-'));
    add(name.replace(/^BETA-/i, ''));
    add(name.replace(/^Beta-/i, ''));
  }
  return out;
}

/** Is there a real Windows installer at this address? */
function probeInstaller(url, redirects = 0) {
  return new Promise(resolve => {
    if (redirects > 5) return resolve({ ok: false });
    let parsed;
    try { parsed = new URL(url); } catch { return resolve({ ok: false }); }
    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.get(url, { headers: { 'User-Agent': 'SMVS-Server' }, timeout: 30000 }, r => {
      if ([301, 302, 303, 307, 308].includes(r.statusCode) && r.headers.location) {
        r.resume();
        return resolve(probeInstaller(new URL(r.headers.location, url).toString(), redirects + 1));
      }
      if (r.statusCode !== 200) { r.resume(); return resolve({ ok: false, status: r.statusCode }); }
      r.once('data', chunk => {
        const head = chunk.slice(0, 2).toString('latin1');
        req.destroy();
        resolve({ ok: head === 'MZ', head });
      });
      r.on('end', () => resolve({ ok: false }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ ok: false }); });
    req.on('error', () => resolve({ ok: false }));
  });
}

app.post('/api/admin/app/version/promote', requireAdmin, async (req, res) => {
  const b = req.body || {};
  const from = channelOf(b.from);
  const to = channelOf(b.to);
  if (from === to) return res.status(400).json({ message: 'Choose two different channels.' });

  const source = versionFor(from);
  if (!source) {
    return res.status(400).json({
      message: 'Nothing is published on the ' + from + ' channel yet, so there is nothing to send.'
    });
  }

  const toBeta = to === 'beta';
  const tried = [];
  const found = { apkUrl: '', desktopUrl: '' };
  let apkCode = null, apkPackage = null;

  // ---- the Android build ----
  if (source.apkUrl) {
    for (const candidate of otherChannelUrls(source.apkUrl, toBeta)) {
      tried.push(candidate);
      const id = await apkIdentity(candidate);
      if (!id || !id.packageName) continue;
      const isBeta = id.packageName.endsWith('.beta');
      if (isBeta === toBeta) {
        found.apkUrl = candidate;
        apkCode = id.versionCode;
        apkPackage = id.packageName;
        break;
      }
    }
    if (!found.apkUrl) {
      return res.status(400).json({
        message:
          'Could not find the ' + to.toUpperCase() + ' Android build on that release. ' +
          'Looked for: ' + tried.join(', ') + '. Attach it to the same GitHub release ' +
          '(the file built with the ' + to + ' identity), or paste the link by hand above.',
        tried
      });
    }
  }

  // ---- the Windows build ----
  if (source.desktopUrl) {
    for (const candidate of otherChannelUrls(source.desktopUrl, toBeta)) {
      tried.push(candidate);
      const probe = await probeInstaller(candidate);
      if (probe.ok) { found.desktopUrl = candidate; break; }
    }
    if (!found.desktopUrl) {
      return res.status(400).json({
        message:
          'Found the Android build but not the ' + to.toUpperCase() + ' Windows installer. ' +
          'Looked for: ' + tried.filter(t => /\.exe$/i.test(t)).join(', ') + '.',
        tried
      });
    }
  }

  setVersionFor(to, {
    versionCode: apkCode || source.versionCode || 0,
    versionName: source.versionName || '',
    apkUrl: found.apkUrl,
    desktopUrl: found.desktopUrl,
    desktopVersion: source.desktopVersion || '',
    desktopMandatory: source.desktopMandatory !== false,
    mandatory: source.mandatory !== false,
    notes: source.notes || '',
    channel: to,
    apkPackage,
    publishedAt: Date.now()
  });
  save();

  const peer = toBeta ? await publishToBetaPeer(versionFor('beta')) : null;

  res.json({
    ok: true, from, to,
    appVersion: versionFor(to),
    found,
    peer
  });
});

app.post('/api/admin/app/version/copy', requireAdmin, async (req, res) => {
  const b = req.body || {};
  const from = channelOf(b.from);
  const to = channelOf(b.to);

  if (from === to) {
    return res.status(400).json({ message: 'Choose two different channels.' });
  }

  const source = versionFor(from);
  if (!source) {
    return res.status(400).json({
      message: `Nothing is published on the ${from} channel yet, so there is nothing to copy.`
    });
  }

  /*
    Copying moves the CODE from one channel to the other, and each channel
    needs that code built under its own identity. Handing beta the live file
    would look like it worked and quietly update nobody.
  */
  if (source.apkPackage) {
    const isBetaBuild = source.apkPackage.endsWith('.beta');
    if (to === 'beta' && !isBetaBuild) {
      return res.status(400).json({
        message:
          'The ' + from + ' channel is carrying the live build (' + source.apkPackage + '), ' +
          'and a beta device cannot install that — Android treats the two as different apps. ' +
          'Build this same version with the beta identity, attach it to the release, then ' +
          'publish it on the beta channel. Windows has the same rule.'
      });
    }
    if (to === 'live' && isBetaBuild) {
      return res.status(400).json({
        message:
          'The ' + from + ' channel is carrying the beta build (' + source.apkPackage + '). ' +
          'Publishing that to everyone would install a second app instead of updating ' +
          'SMVS Browser. Publish the live-flavoured file of this version instead.'
      });
    }
  }

  setVersionFor(to, { ...source, channel: to, publishedAt: Date.now() });
  save();

  const peer = (to === 'beta') ? await publishToBetaPeer(versionFor('beta')) : null;
  res.json({ ok: true, from, to, appVersion: versionFor(to), peer });
});

app.delete('/api/admin/app/version', requireAdmin, async (req, res) => {
  const channel = channelOf(req.query.channel || (req.body || {}).channel);
  setVersionFor(channel, null);
  save();

  // Leaving the build on the beta server would keep offering an update that
  // this dashboard says no longer exists.
  let peer = null;
  if (channel === 'beta') {
    const p = db().betaPeer;
    if (p && p.url && p.username) {
      const auth = await peerLogin(p);
      if (auth.ok) {
        for (const ch of ['live', 'beta']) {
          await peerRequest(p.url, '/api/admin/app/version?channel=' + ch,
            { method: 'DELETE', token: auth.token });
        }
        peer = { ok: true, message: 'Also removed from the beta server.' };
      } else {
        peer = { ok: false, message: auth.message };
      }
    }
  }

  res.json({ ok: true, channel, peer });
});

app.get('/api/health', (_req, res) => {
  const d = db();
  res.json({
    ok: true,
    users: d.users.length,
    roles: d.roles.length,
    storage: storageKind(),
    durable: USE_PG,
    time: Date.now()
  });
});

/**
 * Tells the dashboard where data is stored, so it can warn the administrator
 * when the server is running on an ephemeral filesystem. Public on purpose:
 * it is shown on the login screen, before anyone has a token, and it leaks
 * nothing beyond the storage back-end's name.
 */
app.get('/api/storage', (_req, res) => {
  res.json({
    storage: storageKind(),
    durable: USE_PG,
    message: USE_PG
      ? 'Connected to PostgreSQL — users and roles are saved permanently.'
      : 'Using a local file. On a free host this is erased when the server restarts, ' +
        'so new users and roles will disappear. Set DATABASE_URL to fix this permanently.'
  });
});

app.get('/', (_req, res) => {
  res.type('html').send(DASHBOARD_HTML);
});

/**
 * Boot order matters: the data must be in memory before anything is seeded or
 * served, otherwise the first request could create a second admin account on
 * top of an existing database.
 */
async function start() {
  if (USE_PG) {
    try {
      await pgInit();
    } catch (e) {
      console.error('\n[db] FATAL: could not connect to PostgreSQL.');
      console.error('[db]', e.message);
      console.error('[db] Check the DATABASE_URL environment variable.\n');
      process.exit(1);
    }
  } else {
    load();
    console.warn(
      '\n[db] WARNING: no DATABASE_URL set — using data/db.json.\n' +
      '[db] On Render/Railway free plans this file is DELETED on every restart,\n' +
      '[db] so users and roles you create will vanish. See DATABASE-SETUP.md.\n'
    );
  }

  seed();
  migrateFeatures();
  if (USE_PG) await flush();

  app.listen(PORT, () => {
    console.log(`SMVS Browser server listening on port ${PORT} (storage: ${storageKind()})`);
  });
}

start();

