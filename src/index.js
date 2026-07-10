/*
 * telehub-subdomain-worker
 * Cloudflare Worker pengganti subdomain-telehub.php
 *
 * Alur:
 *   1. User submit form (subdomain, targetDomain, email, contact, telegramUsername, dnsRecords, dst)
 *   2. Divalidasi (format, reserved list, duplikat, rate limit per IP)
 *   3. Disimpan ke Workers KV (pengganti folder data/*.json)
 *   4. Notifikasi dikirim ke Telegram admin, DENGAN 2 TOMBOL: Approve / Reject
 *   5. Admin tap tombol di Telegram -> status di KV ke-update otomatis,
 *      pesan Telegram di-edit (tombol hilang, diganti label status),
 *      dan email dikirim ke user (via Resend) ke field `email` (wajib diisi
 *      di form, jadi tidak perlu lagi nebak-nebak dari field `contact`).
 *      Admin TETAP pasang CNAME/TXT manual di dashboard Cloudflare -- tombol
 *      approve cuma menandai status + mengabari user, bukan otomatis bikin
 *      DNS record di Cloudflare (itu di luar scope worker ini).
 *
 * ====================================================================
 *  BARU DI VERSI INI (sinkron dengan frontend terbaru)
 * ====================================================================
 *
 *  A) FIELD `email` (WAJIB) -- BARU
 *     - Frontend sekarang punya field email terpisah & wajib diisi,
 *       dipakai SATU-SATUNYA sumber tujuan pengiriman email Resend.
 *     - Field `contact` sekarang murni "kontak lain" (WA/dsb), tidak lagi
 *       dipakai buat nebak-nebak apakah harus dikirimi email atau tidak.
 *
 *  B) FIELD `telegramUsername` (OPSIONAL) -- BARU
 *     - Divalidasi ringan (5-32 karakter: huruf/angka/underscore),
 *       disimpan di record & ditampilkan di notifikasi Telegram admin.
 *
 *  C) TOMBOL APPROVE/REJECT DI TELEGRAM
 *     - Pesan notifikasi dikirim dengan `reply_markup` berisi 2 inline
 *       button: "✅ Approve" dan "❌ Reject", `callback_data` =
 *       `approve:<requestId>` / `reject:<requestId>`.
 *     - Endpoint: POST /telegram-webhook, WAJIB didaftarkan lewat
 *       `setWebhook` (lihat langkah setup di bawah).
 *     - Cuma chat yang sama dengan `TELEGRAM_CHAT_ID` yang boleh
 *       approve/reject.
 *     - Direkomendasikan pasang `TELEGRAM_WEBHOOK_SECRET`.
 *
 *  D) EMAIL VIA RESEND (https://resend.com)
 *     - Dipakai buat ngabarin user otomatis pas admin approve/reject,
 *       lewat email ke field `email` (wajib & sudah tervalidasi format
 *       di langkah submit, jadi tidak ada lagi skip diam-diam).
 *     - Perlu 2 hal baru di environment: `RESEND_API_KEY` (secret) dan
 *       `RESEND_FROM_EMAIL` (var, contoh: "Telehub <noreply@domainkamu.com>").
 *
 * ====================================================================
 *  LANGKAH SETUP RESEND (API key belum ada -- ini caranya dari nol)
 * ====================================================================
 *   1. Daftar / login di https://resend.com
 *   2. Tambahkan & verifikasi domain pengirim kamu di Resend
 *      (Domains -> Add Domain -> ikuti instruksi DNS record TXT/MX/CNAME
 *      yang mereka kasih, ini domain BEDA dari domain testing user ya --
 *      ini domain KAMU yang dipakai buat kirim email, misal domainkamu.com).
 *   3. Setelah domain verified, buat API key: API Keys -> Create API Key.
 *   4. Simpan sebagai SECRET di Cloudflare Worker (jangan taruh di
 *      wrangler.toml biar tidak ke-commit ke git):
 *        wrangler secret put RESEND_API_KEY
 *      lalu paste API key-nya saat diminta.
 *   5. Tambahkan var biasa (boleh di wrangler.toml) buat alamat pengirim:
 *        RESEND_FROM_EMAIL = "Telehub <noreply@domainkamu.com>"
 *      (alamat "noreply@domainkamu.com" harus pakai domain yang tadi
 *      di-verify di step 2).
 *
 * ====================================================================
 *  LANGKAH SETUP TELEGRAM WEBHOOK (buat tombol Approve/Reject)
 * ====================================================================
 *   1. Generate string random buat jadi secret token, contoh pakai:
 *        openssl rand -hex 32
 *      Simpan ini sebagai var `TELEGRAM_WEBHOOK_SECRET` (boleh via
 *      `wrangler secret put TELEGRAM_WEBHOOK_SECRET` biar aman).
 *   2. Deploy worker ini dulu (`wrangler deploy`) supaya punya URL,
 *      misal: https://telehub-worker.namamu.workers.dev
 *   3. Daftarkan webhook ke Telegram (jalankan sekali saja dari
 *      terminal kamu, GANTI <TOKEN> dan <SECRET> dan <URL_WORKER>):
 *
 *        curl -F "url=<URL_WORKER>/telegram-webhook" \
 *             -F "secret_token=<SECRET>" \
 *             https://api.telegram.org/bot<TOKEN>/setWebhook
 *
 *      Kalau sukses, responnya: {"ok":true,"result":true,"description":"Webhook was set"}
 *   4. Cek status webhook kapan saja dengan:
 *
 *        curl https://api.telegram.org/bot<TOKEN>/getWebhookInfo
 *
 *   5. Selesai. Sekarang tiap notifikasi baru bakal ada tombol Approve/Reject,
 *      dan tap tombolnya bakal masuk ke endpoint /telegram-webhook worker ini.
 *
 * ====================================================================
 *  ENV YANG DIBUTUHKAN (lengkap, lihat wrangler.toml)
 * ====================================================================
 *   Vars   : SUBDOMAIN_BASE_DOMAIN, RATE_LIMIT_SECONDS, ALLOWED_ORIGINS,
 *            RESEND_FROM_EMAIL
 *   Secrets: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, RESEND_API_KEY,
 *            TELEGRAM_WEBHOOK_SECRET (opsional tapi sangat disarankan)
 *   KV     : SUBDOMAIN_KV
 *
 * ENDPOINT:
 *   POST /submit             -> submit form pengajuan subdomain
 *   GET  /reserved            -> lihat daftar reserved subdomain (debug/admin)
 *   GET  /health               -> health check simple
 *   POST /telegram-webhook -> nerima callback tombol Approve/Reject dari Telegram
 */

const DEFAULT_RESERVED = [
  'www', 'api', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'ns1', 'ns2', 'localhost',
];

const MAX_DNS_RECORDS = 10; // batas wajar per permintaan, cegah payload raksasa

// ============================================================
// CORS helpers
// ============================================================

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

// ============================================================
// Reserved subdomain list (disimpan di KV, editable tanpa redeploy)
// ============================================================

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

// ============================================================
// Normalisasi input dnsRecords: terima array dari frontend baru
// (tiap item: cnameName, cnameTarget, txtName, txtValue), atau
// fallback ke field top-level (client lama / kompatibilitas mundur).
// ============================================================

function normalizeDnsRecords(body) {
  if (Array.isArray(body.dnsRecords) && body.dnsRecords.length > 0) {
    return body.dnsRecords.map((r) => ({
      cnameName: String(r?.cnameName ?? '').trim(),
      cnameTarget: String(r?.cnameTarget ?? '').trim(),
      txtName: String(r?.txtName ?? '').trim(),
      txtValue: String(r?.txtValue ?? '').trim(),
    }));
  }
  // fallback: client lama cuma kirim field top-level
  return [{
    cnameName: String(body.cnameName ?? '').trim(),
    cnameTarget: String(body.cnameTarget ?? '').trim(),
    txtName: String(body.txtName ?? '').trim(),
    txtValue: String(body.txtValue ?? '').trim(),
  }];
}

// ============================================================
// Validasi input
// ============================================================

function validate(body, reservedList) {
  const errors = [];

  const subdomain = String(body.subdomain ?? '').trim().toLowerCase();
  const targetDomain = String(body.targetDomain ?? '').trim();
  const email = String(body.email ?? '').trim();
  const contact = String(body.contact ?? '').trim();
  const telegramUsername = String(body.telegramUsername ?? '').trim().replace(/^@/, '');
  const purpose = String(body.purpose ?? '').trim();
  const aRecordIp = String(body.aRecordIp ?? '').trim();
  const extraRecords = String(body.extraRecords ?? '').trim();

  const subdomainRe = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  const domainRe = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
  const cnameNameRe = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$/i;
  const cnameTargetRe = /^[a-z0-9.-]+$/i;
  const txtNameRe = /^[a-z0-9._-]+$/i;
  const ipv4Re = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Re = /^[0-9a-f:]+$/i;
  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  const telegramUsernameRe = /^[a-zA-Z0-9_]{5,32}$/;

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

  if (email === '' || !emailRe.test(email)) {
    errors.push('Email wajib diisi dengan format yang valid -- ini yang dipakai buat kirim status approve/reject.');
  }

  if (contact === '' || contact.length < 3) {
    errors.push('Kontak (WA/lainnya) wajib diisi.');
  }

  if (telegramUsername !== '' && !telegramUsernameRe.test(telegramUsername)) {
    errors.push('Format username Telegram tidak valid (5-32 karakter: huruf, angka, underscore).');
  }

  if (aRecordIp !== '' && !(ipv4Re.test(aRecordIp) || ipv6Re.test(aRecordIp))) {
    errors.push('Format IP untuk A record tidak valid (contoh: 192.0.2.10).');
  }

  if (extraRecords.length > 1000) {
    errors.push('Catatan record tambahan kepanjangan, ringkas jadi maks 1000 karakter.');
  }

  // ---- Validasi dnsRecords (array, minimal 1 record wajib CNAME) ----
  const dnsRecordsRaw = normalizeDnsRecords(body);

  if (dnsRecordsRaw.length > MAX_DNS_RECORDS) {
    errors.push(`Maksimal ${MAX_DNS_RECORDS} record CNAME/TXT per permintaan.`);
  }

  const dnsRecords = [];
  const seenNames = new Set();
  const trimmed = dnsRecordsRaw.slice(0, MAX_DNS_RECORDS);

  trimmed.forEach((r, i) => {
    const label = `Record #${i + 1}`;

    // --- Nama CNAME per record ---
    let cnameName = r.cnameName.toLowerCase();
    if (cnameName === '') {
      if (trimmed.length === 1) {
        // Cuma 1 record & nama dikosongkan -> fallback ke subdomain utama
        // (perilaku lama, tetap jalan biar nggak breaking buat client lama).
        cnameName = subdomain;
      } else {
        errors.push(`${label}: Nama CNAME wajib diisi kalau kamu mengajukan lebih dari satu record.`);
      }
    }

    if (cnameName !== '' && !cnameNameRe.test(cnameName)) {
      errors.push(`${label}: Format nama CNAME tidak valid (huruf, angka, titik, strip, underscore saja).`);
    } else if (cnameName !== '' && reservedList.includes(cnameName)) {
      errors.push(`${label}: Nama "${cnameName}" sudah dipakai sistem, coba nama lain.`);
    }

    if (cnameName !== '') {
      if (seenNames.has(cnameName)) {
        errors.push(`${label}: Nama "${cnameName}" dipakai dua kali dalam permintaan ini -- satu nama DNS cuma boleh 1 target CNAME.`);
      }
      seenNames.add(cnameName);
    }

    // --- Target CNAME ---
    if (r.cnameTarget === '') {
      errors.push(`${label}: Target CNAME wajib diisi (dari dashboard Railway/Vercel/hosting kamu).`);
    } else if (!cnameTargetRe.test(r.cnameTarget)) {
      errors.push(`${label}: Format target CNAME tidak valid, cuma boleh huruf, angka, titik, dan strip.`);
    }

    // --- TXT opsional, tapi kalau salah satu diisi, dua-duanya wajib ---
    if ((r.txtName && !r.txtValue) || (!r.txtName && r.txtValue)) {
      errors.push(`${label}: Nama dan Value TXT harus diisi berdua atau dikosongkan berdua.`);
    }

    if (r.txtName !== '' && !txtNameRe.test(r.txtName)) {
      errors.push(`${label}: Format nama record TXT tidak valid.`);
    }

    if (r.txtValue.length > 500) {
      errors.push(`${label}: Value TXT kepanjangan, cek lagi copy-paste-nya.`);
    }

    dnsRecords.push({
      cnameName,
      cnameTarget: r.cnameTarget,
      // default nama TXT kalau dikosongkan, unik per record biar nggak tabrakan
      txtName: r.txtName !== '' ? r.txtName : (r.txtValue !== '' ? `_verify${i > 0 ? i + 1 : ''}.${cnameName || subdomain}` : ''),
      txtValue: r.txtValue,
    });
  });

  return {
    errors,
    data: {
      subdomain, targetDomain, email, contact, telegramUsername, purpose,
      aRecordIp, extraRecords, dnsRecords,
    },
  };
}

// ============================================================
// Cek duplikat nama (subdomain utama + tiap cnameName per record) &
// rate limit per IP. Pakai metadata KV supaya nggak perlu fetch tiap
// value satu-satu.
// ============================================================

async function checkDuplicateAndRateLimit(env, requestedNames, ip, rateLimitMs) {
  const list = await env.SUBDOMAIN_KV.list({ prefix: 'request:' });
  const now = Date.now();
  const duplicateNames = new Set();
  let rateLimitError = null;

  for (const key of list.keys) {
    const meta = key.metadata || {};

    if (meta.status !== 'rejected') {
      let existingNames = [];
      if (meta.names) {
        try {
          const parsed = JSON.parse(meta.names);
          if (Array.isArray(parsed)) existingNames = parsed;
        } catch (_) {
          existingNames = meta.subdomain ? [meta.subdomain] : [];
        }
      } else if (meta.subdomain) {
        // metadata lama (belum punya "names") -- fallback ke subdomain saja
        existingNames = [meta.subdomain];
      }

      for (const n of existingNames) {
        if (requestedNames.includes(n)) duplicateNames.add(n);
      }
    }

    if (meta.ip === ip && (now - (meta.submittedAt || 0)) < rateLimitMs) {
      rateLimitError = 'Kamu baru saja mengirim permintaan. Coba lagi dalam beberapa menit.';
    }
  }

  const errors = [];
  if (duplicateNames.size > 0) {
    errors.push(`Nama "${[...duplicateNames].join(', ')}" sudah ada yang mengajukan / sedang diproses.`);
  }
  if (rateLimitError) errors.push(rateLimitError);
  return errors;
}

// ============================================================
// Telegram helpers
// ============================================================

function escapeMarkdown(text) {
  return String(text)
    .replace(/_/g, '\\_')
    .replace(/\*/g, '\\*')
    .replace(/`/g, '\\`')
    .replace(/\[/g, '\\[');
}

function toInlineCode(value) {
  const cleaned = String(value)
    .replace(/`/g, "'")
    .replace(/\r?\n/g, ' ')
    .trim();
  return '`' + cleaned + '`';
}

// Kirim pesan baru. `replyMarkup` opsional (dipakai buat tombol Approve/Reject).
// Return decoded response Telegram ({ok:false} kalau gagal) supaya caller bisa
// ambil message_id hasil kirim.
async function sendTelegramMessage(env, text, replyMarkup) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) {
    console.error('[telehub-worker] Telegram belum dikonfigurasi (secret kosong), notifikasi dilewati.');
    return { ok: false };
  }

  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`;
  const payload = {
    chat_id: env.TELEGRAM_CHAT_ID,
    text,
    parse_mode: 'Markdown',
  };
  if (replyMarkup) payload.reply_markup = replyMarkup;

  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error('[telehub-worker] fetch ke Telegram gagal:', err.message);
    return { ok: false };
  }

  let decoded;
  try {
    decoded = await res.json();
  } catch (err) {
    console.error('[telehub-worker] Respons Telegram bukan JSON valid:', err.message);
    return { ok: false };
  }

  // INI BAGIAN PENTING: cek "ok" dari respons Telegram, bukan cuma
  // status HTTP-nya. Kalau Markdown pecah / token salah, Telegram
  // tetap balas dengan HTTP 200/400 berisi JSON {"ok":false,...}.
  if (!decoded || decoded.ok !== true) {
    console.error('[telehub-worker] Telegram API menolak pesan:', decoded?.description || JSON.stringify(decoded));
    return { ok: false };
  }

  return decoded; // { ok: true, result: { message_id, chat: {...}, ... } }
}

// Edit pesan yang sudah terkirim (dipakai buat hapus tombol + tambah label status
// setelah admin approve/reject).
async function editTelegramMessage(env, chatId, messageId, text, replyMarkup) {
  if (!env.TELEGRAM_BOT_TOKEN) return false;
  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/editMessageText`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        message_id: messageId,
        text,
        parse_mode: 'Markdown',
        reply_markup: replyMarkup, // {inline_keyboard: []} -> hapus semua tombol
      }),
    });
    const decoded = await res.json().catch(() => null);
    if (!decoded || decoded.ok !== true) {
      console.error('[telehub-worker] Gagal edit pesan Telegram:', decoded?.description || JSON.stringify(decoded));
      return false;
    }
    return true;
  } catch (err) {
    console.error('[telehub-worker] fetch editMessageText gagal:', err.message);
    return false;
  }
}

// Wajib dipanggil tiap kali ada tap tombol, kalau tidak Telegram bakal
// nampilin "loading spinner" di tombol tanpa henti di sisi admin.
async function answerCallbackQuery(env, callbackQueryId, text, showAlert = false) {
  if (!env.TELEGRAM_BOT_TOKEN) return false;
  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`;
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        callback_query_id: callbackQueryId,
        text,
        show_alert: showAlert,
      }),
    });
    return true;
  } catch (err) {
    console.error('[telehub-worker] fetch answerCallbackQuery gagal:', err.message);
    return false;
  }
}

function buildApprovalKeyboard(requestId) {
  return {
    inline_keyboard: [[
      { text: '✅ Approve', callback_data: `approve:${requestId}` },
      { text: '❌ Reject', callback_data: `reject:${requestId}` },
    ]],
  };
}

function buildDnsRecordsText(dnsRecords) {
  return dnsRecords
    .map((r, i) => {
      const noPrefix = dnsRecords.length > 1 ? `${i + 1}. ` : '';
      const block = [
        `${noPrefix}*CNAME*`,
        `Name  : ${toInlineCode(r.cnameName)}`,
        `Value : ${toInlineCode(r.cnameTarget)}`,
      ];
      if (r.txtValue !== '') {
        block.push('');
        block.push(`${noPrefix}*TXT*`);
        block.push(`Name  : ${toInlineCode(r.txtName)}`);
        block.push(`Value : ${toInlineCode(r.txtValue)}`);
      }
      return block.join('\n');
    })
    .join('\n\n');
}

// ============================================================
// Resend (email) helper
// ============================================================

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim());
}

async function sendResendEmail(env, to, subject, html) {
  if (!env.RESEND_API_KEY || !env.RESEND_FROM_EMAIL) {
    console.error('[telehub-worker] Resend belum dikonfigurasi (RESEND_API_KEY/RESEND_FROM_EMAIL kosong), email dilewati.');
    return false;
  }

  if (!isValidEmail(to)) {
    // Seharusnya tidak pernah terjadi karena `email` sudah wajib &
    // divalidasi di langkah submit, tapi tetap dijaga di sini.
    console.log('[telehub-worker] Field email tidak valid, email Resend dilewati:', to);
    return false;
  }

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: env.RESEND_FROM_EMAIL,
        to: [to],
        subject,
        html,
      }),
    });

    const decoded = await res.json().catch(() => null);

    if (!res.ok) {
      console.error('[telehub-worker] Resend API menolak email:', decoded?.message || res.status);
      return false;
    }

    return true;
  } catch (err) {
    console.error('[telehub-worker] fetch ke Resend gagal:', err.message);
    return false;
  }
}

function buildApprovedEmailHtml(record) {
  const rows = record.dnsRecords.map((r) => {
    const txtRow = r.txtValue
      ? `<br/><b>TXT</b> &mdash; Name: <code>${r.txtName}</code>, Value: <code>${r.txtValue}</code>`
      : '';
    return `<li><b>CNAME</b> &mdash; Name: <code>${r.cnameName}</code>, Target: <code>${r.cnameTarget}</code>${txtRow}</li>`;
  }).join('');

  return `
    <p>Halo,</p>
    <p>Pengajuan subdomain <b>${record.fullDomain}</b> kamu sudah <b>disetujui</b> dan record DNS berikut sudah dipasang di Cloudflare:</p>
    <ul>${rows}</ul>
    <p>Propagasi DNS biasanya butuh beberapa menit sampai maksimal 24 jam. Kalau setelah itu masih belum aktif, silakan hubungi admin.</p>
    <p>Terima kasih!</p>
  `;
}

function buildRejectedEmailHtml(record) {
  return `
    <p>Halo,</p>
    <p>Mohon maaf, pengajuan subdomain <b>${record.fullDomain}</b> kamu belum bisa kami setujui saat ini.</p>
    <p>Silakan hubungi admin untuk info lebih lanjut atau ajukan ulang dengan detail yang berbeda.</p>
  `;
}

// ============================================================
// Handler: submit form
// ============================================================

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

  // Semua nama yang "diklaim" permintaan ini: subdomain utama + tiap
  // cnameName per record (dedup), biar dua user gak bisa rebutan nama
  // DNS yang sama walau lewat record tambahan (bukan cuma nama utama).
  const requestedNames = Array.from(new Set([data.subdomain, ...data.dnsRecords.map((r) => r.cnameName)]));

  const dupRateErrors = await checkDuplicateAndRateLimit(env, requestedNames, ip, rateLimitSeconds * 1000);
  if (dupRateErrors.length > 0) {
    return json({ ok: false, errors: dupRateErrors }, 400, request, env);
  }

  const now = Date.now();
  const requestId = `${new Date(now).toISOString().replace(/[-:TZ.]/g, '').slice(0, 14)}-${crypto.randomUUID().slice(0, 6)}`;

  const record = {
    id: requestId,
    subdomain: data.subdomain,
    fullDomain: `${data.subdomain}.${baseDomain}`,
    targetDomain: data.targetDomain,
    dnsRecords: data.dnsRecords, // array lengkap: cnameName, cnameTarget, txtName, txtValue
    aRecordIp: data.aRecordIp,
    extraRecords: data.extraRecords,
    email: data.email,
    contact: data.contact,
    telegramUsername: data.telegramUsername,
    purpose: data.purpose,
    ip,
    userAgent: request.headers.get('User-Agent') || '',
    status: 'pending', // pending -> approved | rejected (lewat tombol Telegram)
    submittedAt: now,
    processedAt: null,
    processedBy: null,
  };

  // Simpan ke KV. Metadata dipakai buat query cepat (duplikat/rate-limit)
  // tanpa perlu fetch isi value tiap key. "names" menyimpan SEMUA nama
  // yang diklaim permintaan ini (subdomain utama + tiap cnameName record).
  await env.SUBDOMAIN_KV.put(`request:${requestId}`, JSON.stringify(record), {
    metadata: {
      subdomain: record.subdomain,
      names: JSON.stringify(requestedNames),
      ip: record.ip,
      submittedAt: record.submittedAt,
      status: record.status,
    },
  });

  // ---- Notifikasi Telegram (dengan tombol Approve/Reject) ----
  const divider = '\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500';
  const dnsRecordsText = buildDnsRecordsText(data.dnsRecords);
  const recordCountLabel = `${data.dnsRecords.length} record${data.dnsRecords.length > 1 ? '' : ''}`;
  const telegramUsernameLine = data.telegramUsername !== ''
    ? `💬 *Telegram*       : ${toInlineCode('@' + data.telegramUsername)}\n`
    : '';

  const text = `🦋 *Permintaan Subdomain Baru*\n${divider}\n\n`
    + `📌 *Subdomain*      : ${toInlineCode(data.subdomain + '.' + baseDomain)}\n`
    + `🎯 *Domain testing* : ${toInlineCode(data.targetDomain)}\n`
    + `📧 *Email*          : ${toInlineCode(data.email)}\n`
    + `👤 *Kontak*         : ${escapeMarkdown(data.contact)}\n`
    + telegramUsernameLine
    + `📝 *Tujuan*         : ${data.purpose !== '' ? escapeMarkdown(data.purpose) : '-'}\n\n`
    + `${divider}\n`
    + `📋 *Record DNS yang perlu dipasang di Cloudflare* (${recordCountLabel})\n\n`
    + `${dnsRecordsText}\n\n`
    + `${divider}\n`
    + `🌍 *IP*           : ${toInlineCode(ip)}\n`
    + `🆔 *ID Request*   : ${toInlineCode(requestId)}\n\n`
    + `✅ Pasang record di atas di Cloudflare, lalu tap tombol di bawah buat catat statusnya.`;

  const keyboard = buildApprovalKeyboard(requestId);
  const tgResult = await sendTelegramMessage(env, text, keyboard);

  if (!tgResult.ok) {
    // Gagal kirim notif TIDAK menggagalkan submission -- data user
    // tetap kesimpan di KV. Cek `wrangler tail` buat lihat log errornya.
    console.error(`[telehub-worker] Gagal kirim notifikasi Telegram untuk request ${requestId}`);
  } else {
    // Simpan referensi chat_id/message_id -- berguna buat debug/audit,
    // meski proses approve/reject sendiri tidak bergantung ke field ini
    // (webhook ambil chat_id/message_id langsung dari callback_query).
    record.telegram = {
      chatId: tgResult.result?.chat?.id ?? null,
      messageId: tgResult.result?.message_id ?? null,
    };
    await env.SUBDOMAIN_KV.put(`request:${requestId}`, JSON.stringify(record), {
      metadata: {
        subdomain: record.subdomain,
        names: JSON.stringify(requestedNames),
        ip: record.ip,
        submittedAt: record.submittedAt,
        status: record.status,
      },
    });
  }

  return json({ ok: true, fullDomain: record.fullDomain }, 200, request, env);
}

// ============================================================
// Handler: Telegram webhook (callback tombol Approve/Reject)
// ============================================================

async function handleTelegramWebhook(request, env) {
  // Verifikasi secret token dari header -- diset otomatis oleh Telegram
  // kalau kamu daftarkan webhook pakai parameter `secret_token` (lihat
  // instruksi setup di komentar atas file ini).
  if (env.TELEGRAM_WEBHOOK_SECRET) {
    const headerSecret = request.headers.get('X-Telegram-Bot-Api-Secret-Token');
    if (headerSecret !== env.TELEGRAM_WEBHOOK_SECRET) {
      return new Response('Forbidden', { status: 403 });
    }
  }

  let update;
  try {
    update = await request.json();
  } catch (_) {
    return new Response('Bad Request', { status: 400 });
  }

  const cq = update.callback_query;
  if (!cq) {
    // Update lain (misal command /start, pesan biasa, dll) -- diabaikan,
    // cukup balas 200 OK biar Telegram tidak retry terus.
    return new Response('OK', { status: 200 });
  }

  const chatId = cq.message?.chat?.id;

  // Cuma chat admin (TELEGRAM_CHAT_ID) yang boleh approve/reject.
  if (String(chatId) !== String(env.TELEGRAM_CHAT_ID)) {
    await answerCallbackQuery(env, cq.id, 'Kamu tidak berhak melakukan aksi ini.', true);
    return new Response('OK', { status: 200 });
  }

  const [action, requestId] = String(cq.data || '').split(':');
  if (!requestId || (action !== 'approve' && action !== 'reject')) {
    await answerCallbackQuery(env, cq.id, 'Aksi tidak dikenal.', true);
    return new Response('OK', { status: 200 });
  }

  const raw = await env.SUBDOMAIN_KV.get(`request:${requestId}`);
  if (!raw) {
    await answerCallbackQuery(env, cq.id, 'Request tidak ditemukan (mungkin sudah dihapus).', true);
    return new Response('OK', { status: 200 });
  }

  const record = JSON.parse(raw);

  if (record.status !== 'pending') {
    await answerCallbackQuery(env, cq.id, `Request ini sudah diproses sebelumnya (status: ${record.status}).`, true);
    return new Response('OK', { status: 200 });
  }

  const adminName = cq.from?.username ? `@${cq.from.username}` : (cq.from?.first_name || 'admin');
  const now = Date.now();

  record.status = action === 'approve' ? 'approved' : 'rejected';
  record.processedAt = now;
  record.processedBy = adminName;

  const requestedNames = Array.from(new Set([record.subdomain, ...record.dnsRecords.map((r) => r.cnameName)]));

  await env.SUBDOMAIN_KV.put(`request:${requestId}`, JSON.stringify(record), {
    metadata: {
      subdomain: record.subdomain,
      names: JSON.stringify(requestedNames),
      ip: record.ip,
      submittedAt: record.submittedAt,
      status: record.status,
    },
  });

  // Edit pesan Telegram: hapus tombol, tambahkan label status di bawah teks asli.
  const statusLabel = action === 'approve'
    ? `✅ *DISETUJUI* oleh ${escapeMarkdown(adminName)}`
    : `❌ *DITOLAK* oleh ${escapeMarkdown(adminName)}`;

  if (cq.message?.message_id && cq.message?.text) {
    await editTelegramMessage(
      env,
      chatId,
      cq.message.message_id,
      `${cq.message.text}\n\n${statusLabel}`,
      { inline_keyboard: [] },
    );
  }

  // Kirim email ke user via Resend, ke field `email` (wajib & sudah
  // tervalidasi format-nya sejak langkah submit).
  if (action === 'approve') {
    await sendResendEmail(
      env,
      record.email,
      `Subdomain ${record.fullDomain} disetujui`,
      buildApprovedEmailHtml(record),
    );
  } else {
    await sendResendEmail(
      env,
      record.email,
      `Subdomain ${record.fullDomain} ditolak`,
      buildRejectedEmailHtml(record),
    );
  }

  await answerCallbackQuery(env, cq.id, action === 'approve' ? 'Disetujui ✅' : 'Ditolak ❌');
  return new Response('OK', { status: 200 });
}

// ============================================================
// Handler: reserved list
// ============================================================

async function handleReservedList(request, env) {
  const list = await getReservedList(env);
  return json({ ok: true, reserved: list }, 200, request, env);
}

// ============================================================
// Router utama
// ============================================================

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

    if (url.pathname === '/telegram-webhook' && request.method === 'POST') {
      return handleTelegramWebhook(request, env);
    }

    return json({ ok: false, errors: ['Not found'] }, 404, request, env);
  },
};
