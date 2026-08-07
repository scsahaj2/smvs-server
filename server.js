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
 * Tiny JSON-file database.
 *
 * Deliberately dependency-free so the server runs on any free host with zero
 * setup — no Postgres/Mongo add-on required. For a few hundred users this is
 * genuinely fine: the whole file is read once into memory and written back on
 * change.
 *
 * IMPORTANT for free hosts (Render/Railway): their filesystems are ephemeral,
 * so the file is wiped on redeploy/restart. Set DATA_DIR to a mounted disk if
 * you need durability, or swap this module for a real database later — every
 * caller uses the small API below, nothing else changes.
 */

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DEFAULT_DB = {
  admins: [],       // dashboard logins
  users: [],        // browser profiles (Qustodio "profiles")
  activity: [],     // blocked / alerted visits reported by devices
  devices: [],      // which phone last synced which user
  appVersion: null  // latest published APK for auto-update
};

let cache = null;

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
function save() {
  ensureDir();
  // Debounce: several mutations in one request cause a single disk write.
  clearTimeout(writeTimer);
  writeTimer = setTimeout(() => {
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(cache, null, 2));
    } catch (e) {
      console.error('[db] write failed:', e.message);
    }
  }, 50);
}

function flush() {
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
  { id: 'uncategorized', label: 'Unknown / Uncategorised', group: 'Other', def: 'alert' }
];

const ROLE_TEMPLATES = {
  student: {
    allow: ['education', 'reference', 'government', 'search_engines', 'news',
            'health', 'technology', 'sports', 'religion'],
    alert: ['ai_tools', 'webmail', 'entertainment', 'shopping', 'uncategorized'],
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
    allow: ['reference', 'education', 'government', 'search_engines'],
    blockRest: true,
    homeUrl: 'https://www.wikipedia.org/'
  }
};

/** Builds a full categoryRules map for a role. */
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

    <div class="tabs">
      <button id="tabUsersBtn" class="active" onclick="showTab('users')">Users</button>
      <button id="tabActivityBtn" onclick="showTab('activity')">Activity Log</button>
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
      <table>
        <thead><tr><th>Website</th><th>User</th><th>Category</th><th>Action</th><th>When</th></tr></thead>
        <tbody id="activityRows"></tbody>
      </table>
      <p id="noActivity" class="muted hidden">No blocked or alerted visits reported yet.</p>
    </div>
  </div>
</div>

<!-- ============ USER EDITOR ============ -->
<div id="editorModal" class="modal hidden">
  <div class="card">
    <h3 id="editorTitle" style="margin-top:0;color:var(--primary)">Add User</h3>

    <div class="row">
      <div>
        <label>Username (used to sign in)</label>
        <input id="fUsername">
      </div>
      <div>
        <label>Full name</label>
        <input id="fDisplayName">
      </div>
    </div>
    <div class="row">
      <div>
        <label>Email</label>
        <input id="fEmail">
      </div>
      <div>
        <label id="fPassLabel">Password</label>
        <input id="fPassword" type="text" placeholder="min 4 characters">
      </div>
    </div>
    <div class="row">
      <div>
        <label>Role</label>
        <select id="fRole" onchange="applyTemplate()">
          <option value="student">Student</option>
          <option value="staff">Staff</option>
          <option value="admin">Administrator</option>
          <option value="guest">Guest</option>
        </select>
      </div>
      <div>
        <label>Home page</label>
        <input id="fHome" value="https://www.wikipedia.org/">
      </div>
    </div>
    <label style="display:flex;align-items:center;gap:8px;margin-top:12px">
      <input type="checkbox" id="fEnabled" checked style="width:auto">
      <span style="color:var(--text);font-size:14px">Account enabled (can sign in)</span>
    </label>

    <div style="margin-top:14px;padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--bg)">
      <label style="display:flex;align-items:flex-start;gap:8px;margin:0">
        <input type="checkbox" id="fSyncSessions" style="width:auto;margin-top:3px">
        <span style="color:var(--text);font-size:14px">
          <b>Share website logins across this profile's phones</b><br>
          <span class="muted">
            Sign in to a site on one phone and the profile's other phones are
            signed in too. Logins survive switching SMVS users.
          </span>
        </span>
      </label>
      <p class="muted" style="margin:8px 0 0;color:#8A6D00">
        &#9888; These are live login sessions. Anyone with access to this server
        could use them. Chrome deliberately does not sync cookies for this
        reason. Turn this on only for profiles you trust on phones you control.
      </p>
      <button id="btnClearSessions" class="danger hidden"
              style="margin-top:10px;font-size:12px" onclick="clearSessions()">
        Clear saved website logins for this profile
      </button>
    </div>

    <hr style="margin:18px 0;border:0;border-top:1px solid var(--border)">

    <h4 style="margin:0 0 4px;color:var(--primary)">Time-limited access</h4>
    <p class="muted" style="margin:0 0 10px">
      Allow a site <b>only</b> during these hours. Outside the window it is blocked,
      even if its category is allowed.
    </p>
    <div id="timeRules"></div>
    <button onclick="addTimeRule()" style="font-size:13px">+ Add time rule</button>

    <hr style="margin:18px 0;border:0;border-top:1px solid var(--border)">

    <h4 style="margin:0 0 4px;color:var(--primary)">Specific site overrides</h4>
    <p class="muted" style="margin:0 0 8px">One per line. These beat category rules.</p>
    <label>Always ALLOW</label>
    <textarea id="fAllowed" placeholder="wikipedia.org&#10;khanacademy.org"></textarea>
    <label>Always BLOCK (highest priority)</label>
    <textarea id="fBlocked" placeholder="facebook.com"></textarea>

    <hr style="margin:18px 0;border:0;border-top:1px solid var(--border)">

    <h4 style="margin:0 0 4px;color:var(--primary)">Category rules</h4>
    <div style="display:flex;gap:8px;margin:8px 0">
      <button onclick="setAllCats('allow')" style="font-size:12px">Allow all</button>
      <button onclick="setAllCats('alert')" style="font-size:12px">Alert all</button>
      <button onclick="setAllCats('block')" style="font-size:12px">Block all</button>
      <span id="catSummary" class="muted" style="margin-left:auto;align-self:center"></span>
    </div>
    <div id="catList"></div>

    <p id="editorErr" class="hidden" style="color:var(--danger);font-size:13px"></p>
    <div style="display:flex;gap:10px;margin-top:20px">
      <button onclick="closeEditor()" style="flex:1">Cancel</button>
      <button class="primary" style="flex:2" onclick="saveUser()">Save User</button>
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

async function refresh() {
  const data = await api('/api/admin/users');
  USERS = data.users;
  $('stTotal').textContent = data.stats.total;
  $('stActive').textContent = data.stats.active;
  $('stDisabled').textContent = data.stats.disabled;
  renderUsers();

  const act = await api('/api/admin/activity');
  $('stAlerts').textContent = act.activity.length;
  renderActivity(act.activity);
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
      <td><span class="badge b-neutral">\${esc(u.role)}</span></td>
      <td class="muted">\${blocked} blocked · \${alerted} alert</td>
      <td class="muted">\${(u.timeRules || []).length}</td>
      <td><span class="badge \${u.enabled ? 'b-ok' : 'b-off'}">\${u.enabled ? 'ACTIVE' : 'DISABLED'}</span></td>
      <td class="muted">\${u.lastSyncAt ? new Date(u.lastSyncAt).toLocaleString() : 'never'}</td>
      <td style="text-align:right;white-space:nowrap">
        <button onclick="openEditor('\${u.id}')">Edit</button>
        <button class="danger" onclick="removeUser('\${u.id}','\${esc(u.username)}')">Delete</button>
      </td>\`;
    tbody.appendChild(tr);
  }
}

function renderActivity(list) {
  const tbody = $('activityRows');
  tbody.innerHTML = '';
  $('noActivity').classList.toggle('hidden', list.length > 0);
  for (const a of list) {
    const tr = document.createElement('tr');
    tr.innerHTML = \`
      <td>\${esc(a.host || a.url)}</td>
      <td>\${esc(a.username)}</td>
      <td class="muted">\${esc(a.category)}</td>
      <td><span class="badge \${a.action === 'block' ? 'b-off' : 'b-alert'}">\${a.action.toUpperCase()}</span></td>
      <td class="muted">\${new Date(a.timestamp).toLocaleString()}</td>\`;
    tbody.appendChild(tr);
  }
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function showTab(which) {
  $('tabUsers').classList.toggle('hidden', which !== 'users');
  $('tabActivity').classList.toggle('hidden', which !== 'activity');
  $('tabUpdate').classList.toggle('hidden', which !== 'update');
  $('tabUsersBtn').classList.toggle('active', which === 'users');
  $('tabActivityBtn').classList.toggle('active', which === 'activity');
  $('tabUpdateBtn').classList.toggle('active', which === 'update');
  if (which === 'update') loadVersion();
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

  $('fUsername').value = editing ? editing.username : '';
  $('fUsername').disabled = !!editing;
  $('fDisplayName').value = editing ? (editing.displayName || '') : '';
  $('fEmail').value = editing ? (editing.email || '') : '';
  $('fPassword').value = '';
  $('fPassLabel').textContent = editing
    ? 'New password (leave blank to keep current)' : 'Password';
  $('fRole').value = editing ? editing.role : 'student';
  $('fHome').value = editing ? (editing.homeUrl || '') : 'https://www.wikipedia.org/';
  $('fEnabled').checked = editing ? !!editing.enabled : true;
  $('fSyncSessions').checked = editing ? !!editing.syncWebSessions : false;
  $('btnClearSessions').classList.toggle(
    'hidden', !(editing && editing.hasSyncedSession));
  $('fAllowed').value = editing ? (editing.allowedPatterns || []).join('\\n') : '';
  $('fBlocked').value = editing ? (editing.blockedPatterns || []).join('\\n') : '';

  timeRules = editing ? JSON.parse(JSON.stringify(editing.timeRules || [])) : [];
  renderTimeRules();

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

function applyTemplate() {
  if (editing) return;                       // don't stomp an existing user's rules
  const role = $('fRole').value;
  const presets = {
    student: { allow: ['education','reference','government','search_engines','news','health','technology','sports','religion'],
               alert: ['ai_tools','webmail','entertainment','shopping','uncategorized'] },
    staff:   { allow: ['education','reference','government','search_engines','news','health','technology','business_finance','job_search','webmail','ai_tools','sports','travel','religion','forums_blogs','photo_video'],
               alert: ['shopping','entertainment','streaming','social_networks','chat_messaging','file_sharing','uncategorized'] },
    admin:   { allowAllExcept: ['pornography','self_harm','hate'] },
    guest:   { allow: ['reference','education','government','search_engines'], blockRest: true }
  };
  const t = presets[role] || presets.student;
  catState = {};
  for (const c of CATEGORIES) {
    if (t.allowAllExcept) catState[c.id] = t.allowAllExcept.includes(c.id) ? 'block' : 'allow';
    else if (t.allow && t.allow.includes(c.id)) catState[c.id] = 'allow';
    else if (t.alert && t.alert.includes(c.id)) catState[c.id] = 'alert';
    else if (t.blockRest) catState[c.id] = 'block';
    else catState[c.id] = c.def;
  }
  const homes = { student:'https://www.wikipedia.org/', staff:'https://www.google.com/',
                  admin:'https://www.google.com/', guest:'https://www.wikipedia.org/' };
  $('fHome').value = homes[role];
  renderCats();
}

function renderCats() {
  const groups = {};
  for (const c of CATEGORIES) (groups[c.group] ||= []).push(c);

  const host = $('catList');
  host.innerHTML = '';
  for (const [group, cats] of Object.entries(groups)) {
    const g = document.createElement('div');
    g.className = 'cat-group';
    g.innerHTML = \`<h4>\${esc(group)}</h4>\`;
    for (const c of cats) {
      const cur = catState[c.id] || c.def;
      const row = document.createElement('div');
      row.className = 'cat';
      row.innerHTML = \`
        <span class="cat-name">\${esc(c.label)}</span>
        <span class="seg">
          <button data-c="\${c.id}" data-a="allow" class="\${cur==='allow'?'on-allow':''}">Allow</button>
          <button data-c="\${c.id}" data-a="alert" class="\${cur==='alert'?'on-alert':''}">Alert</button>
          <button data-c="\${c.id}" data-a="block" class="\${cur==='block'?'on-block':''}">Block</button>
        </span>\`;
      g.appendChild(row);
    }
    host.appendChild(g);
  }

  host.querySelectorAll('button[data-c]').forEach(btn => {
    btn.onclick = () => { catState[btn.dataset.c] = btn.dataset.a; renderCats(); };
  });
  updateCatSummary();
}

function updateCatSummary() {
  const v = Object.values(catState);
  $('catSummary').textContent =
    \`\${v.filter(x=>x==='allow').length} allowed · \${v.filter(x=>x==='alert').length} alert · \${v.filter(x=>x==='block').length} blocked\`;
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
    allowedPatterns: lines($('fAllowed').value),
    blockedPatterns: lines($('fBlocked').value),
    categoryRules: catState,
    uncategorizedAction: catState['uncategorized'] || 'alert',
    timeRules,
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
function policyOf(u) {
  return {
    mode: u.mode || 'category',
    allowedPatterns: u.allowedPatterns || [],
    blockedPatterns: u.blockedPatterns || [],
    categoryRules: u.categoryRules || {},
    uncategorizedAction: u.uncategorizedAction || 'alert',
    timeRules: u.timeRules || [],
    features: { ...defaultFeatures(), ...(u.features || {}) },
    homeUrl: u.homeUrl || 'https://www.wikipedia.org/'
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
    safeBrowsingEnabled: true
  };
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
seed();
migrateFeatures();

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

  const role = ['admin', 'staff', 'student', 'guest'].includes(b.role) ? b.role : 'student';
  const t = templateFor(role);

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
    categoryRules: b.categoryRules || t.rules,
    uncategorizedAction: b.uncategorizedAction || 'alert',
    timeRules: (b.timeRules || []).map(scheduleUtil.normalise),
    syncWebSessions: b.syncWebSessions === true,
    sessionBlob: null,
    sessionVersion: 0,
    sessionUpdatedAt: 0,
    features: { ...defaultFeatures(), ...(b.features || {}) },
    homeUrl: b.homeUrl || t.homeUrl,
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

  if (b.displayName !== undefined) user.displayName = String(b.displayName).trim();
  if (b.email !== undefined) user.email = String(b.email).trim();
  if (b.role !== undefined && ['admin', 'staff', 'student', 'guest'].includes(b.role)) {
    user.role = b.role;
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

  save();
  res.json({ user: publicUser(user) });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const d = db();
  const idx = d.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'User not found.' });
  d.users.splice(idx, 1);
  save();
  res.json({ ok: true });
});

app.get('/api/admin/activity', requireAdmin, (req, res) => {
  const d = db();
  const userId = req.query.userId;
  const list = userId ? d.activity.filter(a => a.userId === userId) : d.activity;
  res.json({ activity: list.slice(0, 300) });
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
  res.json({ ok: true, users: d.users.length, time: Date.now() });
});

app.get('/', (_req, res) => {
  res.type('html').send(DASHBOARD_HTML);
});

app.listen(PORT, () => {
  console.log(`SMVS Browser server listening on port ${PORT}`);
});

