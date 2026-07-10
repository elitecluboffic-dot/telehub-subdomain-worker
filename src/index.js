/**
 * ============================================================
 * telehub-subdomain-worker
 * Cloudflare Worker pengganti subdomain-telehub.php
 *
 * Alur sama persis dengan versi PHP:
 *   1. User submit form (subdomain, targetDomain, cnameTarget, dst)
 *   2. Divalidasi (format, reserved list, duplikat, rate limit per IP)
 *   3. Disimpan ke Workers KV (pengganti folder data/*.json)
 *   4. Notifikasi dikirim ke Telegram admin
 *   5. Admin approve manual & pasang CNAME di Cloudflare
 *
 * Beda dari versi PHP:
 *   - Storage pakai Workers KV, bukan file .json di disk
 *     (Workers tidak punya filesystem yang bisa ditulis).
 *   - Reserved subdomain list disimpan di KV key "config:reserved"
 *     (bisa diedit lewat `wrangler kv key put`, tanpa perlu deploy ulang).
 *   - Notifikasi Telegram sudah include fix dari versi PHP:
 *     - Respons JSON dari Telegram API benar-benar dicek ("ok":true/false)
 *     - Field dari user (contact, purpose) di-escape dulu biar Markdown
 *       nggak pecah kalau ada karakter _ * ` [
 *
 * ENDPOINT:
 *   POST /submit        -> submit form pengajuan subdomain
 *   GET  /reserved       -> lihat daftar reserved subdomain (debug/admin)
 *   GET  /health          -> health check simple
 *
 * ENV YANG DIBUTUHKAN (lihat wrangler.toml):
 *   Vars   : SUBDOMAIN_BASE_DOMAIN, RATE_LIMIT_SECONDS, ALLOWED_ORIGINS
 *   Secret : TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
 *   KV     : SUBDOMAIN_KV
 * ============================================================
 */

const DEFAULT_RESERVED = [
  'www', 'api', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'ns1', 'ns2', 'localhost',
];

// ------------------------------------------------------------
// CORS helpers
// ------------------------------------------------------------
function getAllowedOrigin(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);

  if (allowed.includes(origin)) return origin;
  // Kalau ALLOWED_ORIGINS kosong (belum diisi), izinkan semua -- longgarkan
  // ini hanya buat awal development, sebaiknya diisi sebelum go-live.
  if (allowed.length === 0) return '*';
  return null;
}

function corsHeaders(request, env) {
  const origin = getAllowedOrigin(request, env);
  const headers = {
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  if (origin) headers['Access-Control-Allow-Origin'] = origin;
  return headers;
}

function json(data, status, request, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...corsHeaders(request, env),
    },
  });
}

// ------------------------------------------------------------
// Reserved subdomain list (disimpan di KV, editable tanpa redeploy)
// ------------------------------------------------------------
async function getReservedList(env) {
  const raw = await env.SUBDOMAIN_KV.get('config:reserved');
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed;
    } catch (_) {
      // fallthrough ke default
    }
  }
  // Belum ada -- inisialisasi sekali pakai default, biar seterusnya
  // tinggal diedit lewat: wrangler kv key put --binding=SUBDOMAIN_KV
  //   "config:reserved" '["www","api","admin"]'
  await env.SUBDOMAIN_KV.put('config:reserved', JSON.stringify(DEFAULT_RESERVED));
  return DEFAULT_RESERVED;
}

// ------------------------------------------------------------
// Validasi input (mirror persis dari versi PHP)
// ------------------------------------------------------------
function validate(body, reservedList) {
  const errors = [];

  const subdomain = String(body.subdomain ?? '').trim().toLowerCase();
  const targetDomain = String(body.targetDomain ?? '').trim();
  const contact = String(body.contact ?? '').trim();
  const purpose = String(body.purpose ?? '').trim();
  const cnameTarget = String(body.cnameTarget ?? '').trim();
  const txtName = String(body.txtName ?? '').trim();
  const txtValue = String(body.txtValue ?? '').trim();
  const aRecordIp = String(body.aRecordIp ?? '').trim();
  const extraRecords = String(body.extraRecords ?? '').trim();

  const subdomainRe = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  const domainRe = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
  const cnameRe = /^[a-z0-9.-]+$/i;
  const ipv4Re = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Re = /^[0-9a-f:]+$/i;

  if (subdomain === '' || !subdomainRe.test(subdomain)) {
    errors.push('Nama subdomain cuma boleh huruf kecil, angka, dan strip (3-63 karakter), tanpa spasi.');
  } else if (subdomain.length < 3) {
    errors.push('Nama subdomain minimal 3 karakter.');
  } else if (reservedList.includes(subdomain)) {
    errors.push(`Nama "${subdomain}" sudah dipakai sistem, coba nama lain.`);
  }

  if (targetDomain === '' || !domainRe.test(targetDomain)) {
    errors.push('Domain testing kamu formatnya belum valid (contoh: domainkamu.com).');
  }

  if (contact === '' || contact.length < 3) {
    errors.push('Kontak (Telegram/email) wajib diisi biar kami bisa kabari status approve.');
  }

  if (cnameTarget === '') {
    errors.push('Target CNAME wajib diisi (dari dashboard Railway/Vercel/hosting kamu, contoh: dgrb70ce.up.railway.app).');
  } else if (!cnameRe.test(cnameTarget)) {
    errors.push('Format target CNAME tidak valid, cuma boleh huruf, angka, titik, dan strip.');
  }

  if (txtValue !== '' && txtValue.length > 500) {
    errors.push('Value TXT kepanjangan, cek lagi copy-paste-nya.');
  }

  if (aRecordIp !== '' && !(ipv4Re.test(aRecordIp) || ipv6Re.test(aRecordIp))) {
    errors.push('Format IP untuk A record tidak valid (contoh: 192.0.2.10).');
  }

  if (extraRecords.length > 1000) {
    errors.push('Catatan record tambahan kepanjangan, ringkas jadi maks 1000 karakter.');
  }

  return {
    errors,
    data: {
      subdomain, targetDomain, contact, purpose, cnameTarget,
      txtName, txtValue, aRecordIp, extraRecords,
    },
  };
}

// ------------------------------------------------------------
// Cek duplikat subdomain & rate limit per IP
// Pakai metadata KV supaya nggak perlu fetch tiap value satu-satu.
// ------------------------------------------------------------
async function checkDuplicateAndRateLimit(env, subdomain, ip, rateLimitMs) {
  const list = await env.SUBDOMAIN_KV.list({ prefix: 'request:' });
  const now = Date.now();
  let duplicateError = null;
  let rateLimitError = null;

  for (const key of list.keys) {
    const meta = key.metadata || {};
    if (meta.subdomain === subdomain && meta.status !== 'rejected') {
      duplicateError = `Subdomain "${subdomain}" sudah ada yang mengajukan / sedang diproses.`;
    }
    if (meta.ip === ip && (now - (meta.submittedAt || 0)) < rateLimitMs) {
      rateLimitError = 'Kamu baru saja mengirim permintaan. Coba lagi dalam beberapa menit.';
    }
  }

  const errors = [];
  if (duplicateError) errors.push(duplicateError);
  if (rateLimitError) errors.push(rateLimitError);
  return errors;
}

// ------------------------------------------------------------
// Telegram
// ------------------------------------------------------------
function escapeMarkdown(text) {
  return String(text)
    .replace(/_/g, '\\_')
    .replace(/\*/g, '\\*')
    .replace(/`/g, '\\`')
    .replace(/\[/g, '\\[');
}

async function sendTelegramMessage(env, text) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) {
    console.error('[telehub-worker] Telegram belum dikonfigurasi (secret kosong), notifikasi dilewati.');
    return false;
  }

  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`;
  const payload = {
    chat_id: env.TELEGRAM_CHAT_ID,
    text,
    parse_mode: 'Markdown',
  };

  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error('[telehub-worker] fetch ke Telegram gagal:', err.message);
    return false;
  }

  let decoded;
  try {
    decoded = await res.json();
  } catch (err) {
    console.error('[telehub-worker] Respons Telegram bukan JSON valid:', err.message);
    return false;
  }

  // INI BAGIAN PENTING: cek "ok" dari respons Telegram, bukan cuma
  // status HTTP-nya. Kalau Markdown pecah / token salah, Telegram
  // tetap balas dengan HTTP 200/400 berisi JSON {"ok":false,...}.
  if (!decoded || decoded.ok !== true) {
    console.error('[telehub-worker] Telegram API menolak pesan:', decoded?.description || JSON.stringify(decoded));
    return false;
  }

  return true;
}

// ------------------------------------------------------------
// Handler utama
// ------------------------------------------------------------
async function handleSubmit(request, env) {
  const contentType = request.headers.get('Content-Type') || '';
  let body = {};
  try {
    if (contentType.includes('application/json')) {
      body = await request.json();
    } else {
      const form = await request.formData();
      body = Object.fromEntries(form.entries());
    }
  } catch (_) {
    return json({ ok: false, errors: ['Body request tidak valid.'] }, 400, request, env);
  }

  // Honeypot -- kalau field ini keisi, itu bot. Pura-pura sukses.
  if (body.website) {
    return json({ ok: true }, 200, request, env);
  }

  const reservedList = await getReservedList(env);
  const { errors, data } = validate(body, reservedList);

  if (errors.length > 0) {
    return json({ ok: false, errors }, 400, request, env);
  }

  const baseDomain = env.SUBDOMAIN_BASE_DOMAIN || 'telehub.web.id';
  const rateLimitSeconds = parseInt(env.RATE_LIMIT_SECONDS || '300', 10);
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  const dupRateErrors = await checkDuplicateAndRateLimit(env, data.subdomain, ip, rateLimitSeconds * 1000);
  if (dupRateErrors.length > 0) {
    return json({ ok: false, errors: dupRateErrors }, 400, request, env);
  }

  const now = Date.now();
  const requestId = `${new Date(now).toISOString().replace(/[-:TZ.]/g, '').slice(0, 14)}-${crypto.randomUUID().slice(0, 6)}`;

  const txtNameFinal = data.txtName !== '' ? data.txtName : `_verify.${data.subdomain}`;
  const record = {
    id: requestId,
    subdomain: data.subdomain,
    fullDomain: `${data.subdomain}.${baseDomain}`,
    targetDomain: data.targetDomain,
    cnameTarget: data.cnameTarget,
    txtName: txtNameFinal,
    txtValue: data.txtValue,
    contact: data.contact,
    purpose: data.purpose,
    ip,
    userAgent: request.headers.get('User-Agent') || '',
    status: 'pending',
    submittedAt: now,
  };

  // Simpan ke KV. Metadata dipakai buat query cepat (duplikat/rate-limit)
  // tanpa perlu fetch isi value tiap key.
  await env.SUBDOMAIN_KV.put(`request:${requestId}`, JSON.stringify(record), {
    metadata: {
      subdomain: record.subdomain,
      ip: record.ip,
      submittedAt: record.submittedAt,
      status: record.status,
    },
  });

  // ---- Notifikasi Telegram ----
  let dnsBlock = `Type   Name                Value\nCNAME  ${data.subdomain}                -> ${data.cnameTarget}\n`;
  if (data.txtValue !== '') {
    dnsBlock += `TXT    ${txtNameFinal}  -> ${data.txtValue}\n`;
  }

  const text = `🌐 *Permintaan Subdomain Baru*\n\n`
    + `*Subdomain:* \`${data.subdomain}.${baseDomain}\`\n`
    + `*Domain testing user:* \`${data.targetDomain}\`\n`
    + `*Kontak:* ${escapeMarkdown(data.contact)}\n`
    + `*Tujuan:* ${data.purpose !== '' ? escapeMarkdown(data.purpose) : '-'}\n\n`
    + `*Record DNS yang perlu dipasang di Cloudflare:*\n`
    + '```\n' + dnsBlock + '```\n'
    + `*IP:* \`${ip}\`\n`
    + `*ID Request:* \`${requestId}\`\n\n`
    + `Setujui? Pasang record di atas di Cloudflare, lalu update status manual.`;

  const sent = await sendTelegramMessage(env, text);
  if (!sent) {
    // Gagal kirim notif TIDAK menggagalkan submission -- data user
    // tetap kesimpan di KV. Cek `wrangler tail` buat lihat log errornya.
    console.error(`[telehub-worker] Gagal kirim notifikasi Telegram untuk request ${requestId}`);
  }

  return json({ ok: true, fullDomain: record.fullDomain }, 200, request, env);
}

async function handleReservedList(request, env) {
  const list = await getReservedList(env);
  return json({ ok: true, reserved: list }, 200, request, env);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }

    if (url.pathname === '/health') {
      return json({ ok: true, service: 'telehub-subdomain-worker' }, 200, request, env);
    }

    if (url.pathname === '/submit' && request.method === 'POST') {
      return handleSubmit(request, env);
    }

    if (url.pathname === '/reserved' && request.method === 'GET') {
      return handleReservedList(request, env);
    }

    return json({ ok: false, errors: ['Not found'] }, 404, request, env);
  },
};
