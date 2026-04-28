/**
 * depmedic-bot - GitHub App webhook handler.
 *
 * Endpoints:
 *   POST /webhook                  GitHub webhook delivery (HMAC-SHA256 verified)
 *   GET  /                         human-readable health page
 *   GET  /api/installs             count of installations (no auth, no PII)
 *
 * Events handled:
 *   - installation, installation_repositories: persist to KV
 *   - pull_request:opened|synchronize|reopened on a PR that touches
 *     .github/workflows/*.yml -> fetch the changed workflow files,
 *     run ci-doctor (bundled below), POST a PR comment with the
 *     audit results. Updates the existing comment if one exists.
 *
 * Security:
 *   - Validates X-Hub-Signature-256 against env.GH_WEBHOOK_SECRET.
 *   - App auth: short-lived JWT (RS256, 5 min) signed with PKCS#8 private
 *     key in env.GH_PRIVATE_KEY -> exchange for installation token.
 *   - Free public-repo audits; private-repo audits gated on
 *     ALLOWED_PRIVATE_REPOS=true (set after Marketplace listing approval).
 *
 * Cost:
 *   - One installation token mint per PR event (cached in memory per
 *     request). One Contents API call per changed workflow file.
 *     ~3 GitHub API calls per PR delivery. 100k PRs/mo fits inside free
 *     Cloudflare plan.
 */

import { auditWorkflow } from './ci-doctor-bundled.js';

const HEADERS_HTML = { 'Content-Type': 'text/html; charset=utf-8' };
const HEADERS_JSON = { 'Content-Type': 'application/json' };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/' || url.pathname === '/health') return health(env);
    if (url.pathname === '/api/installs') return apiInstalls(env);
    if (url.pathname === '/webhook' && request.method === 'POST') return handleWebhook(request, env, ctx);
    return new Response('not found', { status: 404 });
  },
};

async function health(env) {
  return new Response(`<!doctype html><html><head><meta charset="utf-8"><title>depmedic-bot</title>
<style>body{font:16px/1.55 ui-sans-serif,system-ui,sans-serif;background:#0b0d10;color:#e6e8eb;margin:0;padding:48px 24px}
.box{max-width:640px;margin:0 auto;background:#11151b;border:1px solid #1e242c;border-radius:10px;padding:24px}
h1{margin:0 0 8px;font-size:22px}p{color:#b6bec7;margin:8px 0}a{color:#6cb6ff}</style>
</head><body><div class="box">
<h1>depmedic-bot</h1>
<p>This endpoint is the webhook receiver for the <strong>depmedic-bot</strong> GitHub App. It comments on every PR that touches <code>.github/workflows/*.yml</code> with a 14-rule ci-doctor audit and a per-rule fix suggestion.</p>
<p>Install: <a href="https://github.com/apps/${env.APP_NAME}">github.com/apps/${env.APP_NAME}</a></p>
<p>Source / homepage: <a href="https://depmedicdev-byte.github.io/depmedic-bot.html">depmedicdev-byte.github.io/depmedic-bot.html</a></p>
</div></body></html>`, { headers: HEADERS_HTML });
}

async function apiInstalls(env) {
  const list = await env.INSTALLS.list({ prefix: 'install:', limit: 1000 });
  return new Response(JSON.stringify({ count: list.keys.length }), { headers: HEADERS_JSON });
}

async function handleWebhook(request, env, ctx) {
  const sig = request.headers.get('x-hub-signature-256') || '';
  const event = request.headers.get('x-github-event') || '';
  const delivery = request.headers.get('x-github-delivery') || '';
  const rawBody = await request.text();

  const ok = await verifySignature(env.GH_WEBHOOK_SECRET, rawBody, sig);
  if (!ok) return new Response('bad signature', { status: 401 });

  let payload;
  try { payload = JSON.parse(rawBody); } catch { return new Response('bad json', { status: 400 }); }

  // Always 200 fast; do the work async.
  ctx.waitUntil(dispatch(event, payload, env, delivery).catch((e) => console.error('dispatch error', delivery, e && e.stack)));
  return new Response('ok', { status: 200 });
}

async function dispatch(event, payload, env, delivery) {
  if (event === 'installation' || event === 'installation_repositories') {
    return persistInstall(payload, env);
  }
  if (event === 'pull_request') {
    const action = payload.action;
    if (!['opened', 'synchronize', 'reopened'].includes(action)) return;
    return handlePullRequest(payload, env, delivery);
  }
  // ping, marketplace_purchase, etc. - ignore.
}

async function persistInstall(payload, env) {
  const inst = payload.installation;
  if (!inst) return;
  const key = 'install:' + inst.id;
  if (payload.action === 'deleted' || payload.action === 'suspended') {
    await env.INSTALLS.delete(key);
    return;
  }
  await env.INSTALLS.put(key, JSON.stringify({
    id: inst.id,
    account: inst.account && inst.account.login,
    type: inst.account && inst.account.type,
    permissions: inst.permissions,
    events: inst.events,
    created_at: payload.installation && payload.installation.created_at,
    updated_at: new Date().toISOString(),
  }));
}

async function handlePullRequest(payload, env, delivery) {
  const pr = payload.pull_request;
  if (!pr) return;
  const repo = payload.repository;
  if (!repo) return;
  if (repo.private && env.ALLOWED_PRIVATE_REPOS !== 'true') {
    return; // free tier: public repos only until Marketplace listing is approved
  }
  const installId = payload.installation && payload.installation.id;
  if (!installId) return;

  const token = await getInstallationToken(env, installId);
  const [owner, name] = repo.full_name.split('/');
  const prNumber = pr.number;
  const headSha = pr.head && pr.head.sha;

  // List changed files
  const filesResp = await ghApi(token, `/repos/${owner}/${name}/pulls/${prNumber}/files?per_page=100`);
  if (!filesResp.ok) {
    console.error('files API failed', filesResp.status);
    return;
  }
  const files = await filesResp.json();
  const changed = files.filter((f) => f.filename.startsWith(env.WORKFLOW_GLOB) && /\.ya?ml$/i.test(f.filename));
  if (changed.length === 0) return; // nothing to audit

  // Fetch each workflow file at the head SHA, audit it
  const findings = [];
  for (const f of changed) {
    if (f.status === 'removed') continue;
    const raw = await fetchFileAtSha(token, owner, name, f.filename, headSha);
    if (raw == null) continue;
    try {
      const fs = auditWorkflow(raw, f.filename);
      for (const x of fs) findings.push(x);
    } catch (e) {
      console.error('audit error on', f.filename, e && e.message);
    }
  }

  const body = renderComment(findings, changed, env);
  await postOrUpdateComment(token, owner, name, prNumber, body, env);
}

async function fetchFileAtSha(token, owner, name, file, sha) {
  // raw.githubusercontent fallback: the App token is sufficient on Contents API
  const r = await ghApi(token, `/repos/${owner}/${name}/contents/${encodeURIComponent(file)}?ref=${sha}`, {
    headers: { Accept: 'application/vnd.github.raw' },
  });
  if (!r.ok) return null;
  return await r.text();
}

function renderComment(findings, changed, env) {
  const total = findings.length;
  const counts = { error: 0, warn: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const filesLine = changed.map((f) => '`' + f.filename + '`').join(', ');
  if (total === 0) {
    return `${env.COMMENT_HEADER}

Audit clean on ${filesLine}. All 14 ci-doctor rules pass.

<sub>Audited by [depmedic-bot](https://github.com/apps/${env.APP_NAME}). [Run locally](https://www.npmjs.com/package/ci-doctor) with \`npx ci-doctor\`. <a href="https://depmedicdev-byte.github.io/depmedic-bot.html">configure</a> &middot; <a href="https://depmedicdev-byte.github.io/sponsor.html">sponsor</a></sub>`;
  }
  const grouped = {};
  for (const f of findings) {
    const key = f.filename + '#' + f.ruleId;
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(f);
  }
  const lines = [`${env.COMMENT_HEADER}`, '', `**${total} finding${total === 1 ? '' : 's'}** across ${changed.length} workflow file${changed.length === 1 ? '' : 's'}: ${counts.error} error / ${counts.warn} warn / ${counts.info} info.`, ''];
  lines.push('| File | Line | Severity | Rule | Message |');
  lines.push('| --- | --- | --- | --- | --- |');
  for (const f of findings.slice(0, 25)) {
    const msg = String(f.message || '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
    lines.push(`| \`${f.filename}\` | ${f.line || ''} | ${f.severity} | \`${f.ruleId}\` | ${msg} |`);
  }
  if (findings.length > 25) lines.push('', `_+ ${findings.length - 25} more findings; install \`ci-doctor\` locally to see all of them._`);
  lines.push('', `<sub>Audited by [depmedic-bot](https://github.com/apps/${env.APP_NAME}) using [ci-doctor](https://www.npmjs.com/package/ci-doctor). Run \`npx ci-doctor --fix\` to auto-apply the safe fixes. <a href="https://depmedicdev-byte.github.io/depmedic-bot.html">configure</a></sub>`);
  return lines.join('\n');
}

async function postOrUpdateComment(token, owner, name, prNumber, body, env) {
  // Find existing comment by header
  const list = await ghApi(token, `/repos/${owner}/${name}/issues/${prNumber}/comments?per_page=100`);
  if (list.ok) {
    const items = await list.json();
    const mine = items.find((c) => c.user && (c.user.type === 'Bot' || c.user.login.endsWith('[bot]')) && typeof c.body === 'string' && c.body.startsWith(env.COMMENT_HEADER));
    if (mine) {
      const patch = await ghApi(token, `/repos/${owner}/${name}/issues/comments/${mine.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ body }),
      });
      if (patch.ok) return;
    }
  }
  await ghApi(token, `/repos/${owner}/${name}/issues/${prNumber}/comments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ body }),
  });
}

async function ghApi(token, path, init = {}) {
  return await fetch('https://api.github.com' + path, {
    ...init,
    headers: {
      Authorization: 'Bearer ' + token,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'depmedic-bot',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(init.headers || {}),
    },
  });
}

async function getInstallationToken(env, installId) {
  const jwt = await mintAppJwt(env);
  const r = await fetch(`https://api.github.com/app/installations/${installId}/access_tokens`, {
    method: 'POST',
    headers: {
      Authorization: 'Bearer ' + jwt,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'depmedic-bot',
    },
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error('install token mint failed: ' + r.status + ' ' + t.slice(0, 240));
  }
  const j = await r.json();
  return j.token;
}

async function mintAppJwt(env) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claims = { iat: now - 60, exp: now + 9 * 60, iss: env.APP_ID };
  const encH = b64url(new TextEncoder().encode(JSON.stringify(header)));
  const encC = b64url(new TextEncoder().encode(JSON.stringify(claims)));
  const data = encH + '.' + encC;
  const key = await importPrivateKey(env.GH_PRIVATE_KEY);
  const sig = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, key, new TextEncoder().encode(data));
  return data + '.' + b64url(new Uint8Array(sig));
}

async function importPrivateKey(pem) {
  const norm = pem.replace(/\\n/g, '\n');
  const cleaned = norm.replace(/-----BEGIN [^-]+-----/g, '').replace(/-----END [^-]+-----/g, '').replace(/\s+/g, '');
  const der = Uint8Array.from(atob(cleaned), (c) => c.charCodeAt(0));
  return await crypto.subtle.importKey('pkcs8', der.buffer, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
}

function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function verifySignature(secret, body, sigHeader) {
  if (!sigHeader || !sigHeader.startsWith('sha256=')) return false;
  const sigHex = sigHeader.slice(7);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
  const expected = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return safeEq(expected, sigHex);
}

function safeEq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
