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
  appVersion: null, // latest published APK for auto-update
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
      <h3 style="margin-top:0;color:var(--primary)">Publish an app update</h3>
      <p class="muted">
        Phones check this on every launch and every time the app is reopened.
        When the version here is higher than the version on the phone, the new
        APK downloads automatically in the background.
      </p>
      <div class="banner">
        <b>One tap is unavoidable.</b> Android only lets system apps install
        updates with no confirmation at all. The phone will show a single
        "Update?" screen once the download finishes. Everything before that is
        automatic, and a mandatory update blocks browsing until it is applied.
      </div>

      <div id="currentVersionBox" class="hidden"
           style="background:var(--bg);border-radius:10px;padding:14px;margin-bottom:14px">
        <b>Currently published</b>
        <div id="currentVersionText" class="muted" style="margin-top:6px"></div>
        <button class="danger" style="margin-top:10px;font-size:12px"
                onclick="unpublishVersion()">Unpublish</button>
      </div>

      <div class="row">
        <div>
          <label>Version code (whole number, must increase)</label>
          <input id="uVersionCode" type="number" min="1" placeholder="8">
        </div>
        <div>
          <label>Version name (shown to users)</label>
          <input id="uVersionName" placeholder="5.1">
        </div>
      </div>
      <label>APK download link (direct link ending in .apk)</label>
      <input id="uApkUrl" placeholder="https://github.com/you/repo/releases/download/v5.1/app.apk">
      <label>What changed (optional)</label>
      <input id="uNotes" placeholder="Fixed login issue">
      <label style="display:flex;align-items:center;gap:8px;margin-top:12px">
        <input type="checkbox" id="uMandatory" checked style="width:auto">
        <span style="color:var(--text);font-size:14px">
          Mandatory — block browsing until the user updates
        </span>
      </label>
      <p id="updateErr" class="hidden" style="color:var(--danger);font-size:13px"></p>
      <button class="primary" style="margin-top:16px" onclick="publishVersion()">
        Publish update to all phones
      </button>
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
        <thead><tr><th>Website</th><th>User</th><th>Category</th><th>Action</th><th>When</th></tr></thead>
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
        <button class="danger"
          onclick="removeDevice('\${encodeURIComponent(d.userId)}','\${encodeURIComponent(d.name || '')}')">
          Remove
        </button>
      </td>\`;
    tbody.appendChild(tr);
  }
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
  ['users','activity','roles','devices','admins','update'].forEach(t => {
    const panel = $('tab' + t.charAt(0).toUpperCase() + t.slice(1));
    const btn = $('tab' + t.charAt(0).toUpperCase() + t.slice(1) + 'Btn');
    if (panel) panel.classList.toggle('hidden', which !== t);
    if (btn) btn.classList.toggle('active', which === t);
  });
  if (which === 'update') loadVersion();
  if (which === 'roles') renderRoles();
  if (which === 'devices') loadDevices();
  if (which === 'admins') loadAdmins();
}

async function loadVersion() {
  try {
    const d = await api('/api/admin/app/version');
    const v = d.appVersion;
    const box = $('currentVersionBox');
    if (!v) { box.classList.add('hidden'); return; }
    box.classList.remove('hidden');
    $('currentVersionText').innerHTML =
      'Version <b>' + esc(v.versionName || v.versionCode) + '</b> (code ' + v.versionCode + ')<br>' +
      esc(v.apkUrl) + '<br>' +
      (v.mandatory ? 'Mandatory' : 'Optional') +
      ' &middot; published ' + new Date(v.publishedAt).toLocaleString();
    $('uVersionCode').value = v.versionCode + 1;
    $('uVersionName').value = '';
    $('uApkUrl').value = v.apkUrl;
    $('uMandatory').checked = v.mandatory !== false;
  } catch (e) { /* non-fatal */ }
}

async function publishVersion() {
  const err = $('updateErr');
  err.classList.add('hidden');
  try {
    await api('/api/admin/app/version', {
      method: 'POST',
      body: JSON.stringify({
        versionCode: parseInt($('uVersionCode').value, 10),
        versionName: $('uVersionName').value.trim(),
        apkUrl: $('uApkUrl').value.trim(),
        notes: $('uNotes').value.trim(),
        mandatory: $('uMandatory').checked
      })
    });
    toast('Published — phones will pick it up on next launch');
    await loadVersion();
  } catch (e) {
    err.textContent = e.message;
    err.classList.remove('hidden');
  }
}

async function unpublishVersion() {
  if (!confirm('Stop offering this update?')) return;
  try {
    await api('/api/admin/app/version', { method: 'DELETE' });
    $('currentVersionBox').classList.add('hidden');
    toast('Unpublished');
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
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
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
  if (req.body.deviceName) {
    const dev = d.devices.find(x => x.userId === user.id && x.name === req.body.deviceName);
    if (dev) dev.lastSeen = Date.now();
    else d.devices.push({
      userId: user.id, name: String(req.body.deviceName).slice(0, 60), lastSeen: Date.now()
    });
  }
  save();

  // No expiry: the app stays signed in until the user taps Log Out.
  const token = jwt.sign({ kind: 'device', sub: user.id }, JWT_SECRET);

  res.json({
    accessToken: token,
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
  res.json({ policy: policyOf(user) });
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
  if (b.categoryRules !== undefined) user.categoryRules = b.categoryRules;
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
      categoryRules: b.categoryRules !== undefined ? b.categoryRules : undefined,
      homeUrl: b.homeUrl !== undefined ? b.homeUrl : undefined,
      uncategorizedAction:
        b.uncategorizedAction !== undefined ? b.uncategorizedAction : undefined,
      features: b.features !== undefined ? b.features : undefined
    },
    roleRules
  );

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

app.get('/api/app/version', (req, res) => {
  const d = db();
  const info = d.appVersion || null;
  if (!info || !info.versionCode) {
    return res.json({ available: false });
  }
  res.json({
    available: true,
    versionCode: info.versionCode,
    versionName: info.versionName || '',
    apkUrl: info.apkUrl || '',
    mandatory: info.mandatory !== false,
    notes: info.notes || '',
    publishedAt: info.publishedAt || 0
  });
});

app.get('/api/admin/app/version', requireAdmin, (_req, res) => {
  res.json({ appVersion: db().appVersion || null });
});

app.post('/api/admin/app/version', requireAdmin, (req, res) => {
  const b = req.body || {};
  const code = parseInt(b.versionCode, 10);

  if (!Number.isInteger(code) || code < 1) {
    return res.status(400).json({ message: 'versionCode must be a whole number.' });
  }
  const url = String(b.apkUrl || '').trim();
  if (!/^https?:\/\//i.test(url)) {
    return res.status(400).json({ message: 'apkUrl must start with http:// or https://' });
  }

  const d = db();
  d.appVersion = {
    versionCode: code,
    versionName: String(b.versionName || '').trim(),
    apkUrl: url,
    mandatory: b.mandatory !== false,
    notes: String(b.notes || '').trim().slice(0, 500),
    publishedAt: Date.now()
  };
  save();
  res.json({ ok: true, appVersion: d.appVersion });
});

app.delete('/api/admin/app/version', requireAdmin, (_req, res) => {
  const d = db();
  d.appVersion = null;
  save();
  res.json({ ok: true });
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

