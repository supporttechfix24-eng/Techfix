// netlify/functions/review-moderation.js
//
// SCHEDULED function (runs every minute — see netlify.toml).
//
// New reviews are saved by the website as  approved:false, status:'pending'.
// This function waits until a review is at least 5 minutes old, then scans
// it for malware / suspicious content:
//
//   clean       -> approved:true , status:'approved'  (appears on the site)
//                  + a thank-you email is sent to the customer
//   suspicious  -> approved:false, status:'flagged'   (stays hidden; the reasons
//                  are saved in scanReasons so you can review it in the admin panel)
//
// Required Netlify environment variables:
//   FIREBASE_SERVICE_ACCOUNT   the full service-account JSON (Firebase Console ->
//                              Project settings -> Service accounts -> Generate key)
//                              (talks to Firestore over REST — no extra npm package needed)
//   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM   (same as the appointment email)
// Optional:
//   SAFE_BROWSING_API_KEY      Google Safe Browsing key — links are also checked against Google's malware list

const crypto = require('crypto');
const nodemailer = require('nodemailer');

const SITE_URL = 'https://techfix24.netlify.app';
const HOLD_MS = 5 * 60 * 1000;       // keep every review pending for 5 minutes
const MAX_PER_RUN = 25;

/* ------------------------------------------------------------------ */
/*  Scanner                                                            */
/* ------------------------------------------------------------------ */
const SHORTENERS = /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|is\.gd|rb\.gy|shorturl\.at|ow\.ly|buff\.ly|tiny\.cc|rebrand\.ly)\b/i;
const BAD_EXT = /\.(exe|apk|scr|bat|cmd|msi|jar|vbs|ps1|dll|iso|zip|rar|7z|lnk|hta|js)(\b|$)/i;
const BAD_TLD = /\.(zip|mov|xyz|top|click|tk|gq|ml|cf|ga|work|loan|country|kim|men|review|stream|download)(\/|:|\s|$)/i;

const RULES = [
  [/<\s*\/?\s*(script|iframe|object|embed|svg|link|style|form|meta|base|img|video|audio|a)\b/i, 'contains HTML / script tags'],
  [/(javascript|vbscript)\s*:|data\s*:\s*text\/html|data\s*:[^,]{0,40};base64/i, 'contains script / data URI'],
  [/\bon[a-z]{3,}\s*=/i, 'contains inline event handler'],
  [/&#x?[0-9a-f]+;|%3c\s*script|\\u003c|\\x3c/i, 'contains encoded markup'],
  [/\b(union\s+select|drop\s+table|insert\s+into|or\s+1\s*=\s*1|xp_cmdshell)\b|;\s*--/i, 'looks like SQL injection'],
  [/\b(powershell|cmd\.exe|wget\s|curl\s|bash\s+-c|eval\s*\(|base64\s+-d|certutil|mshta|regsvr32|rundll32)\b|\$\(|`[^`]+`\s*\|/i, 'contains shell / command text'],
  [/\b(keygen|crack(ed)?|warez|torrent|loader|payload|trojan|ransomware|botnet|rat\s+tool)\b/i, 'mentions malware / piracy keywords'],
  [/\b(viagra|casino|betting|jackpot|lottery|giveaway|forex|crypto\s*(signal|invest)|bitcoin|usdt|earn\s*\$|make\s+money|work\s+from\s+home|loan\s+offer|adult|porn|escort)\b/i, 'looks like spam / scam'],
  [/(t\.me\/|wa\.me\/|chat\.whatsapp\.com|telegram\.me\/|discord\.gg\/)/i, 'contains messaging-invite link'],
  [/\b(click\s+here|verify\s+your\s+account|your\s+account\s+(is|has\s+been)\s+(suspended|locked)|password|otp\s*code|send\s+me\s+(money|bkash|nagad))\b/i, 'looks like phishing'],
  [/(টাকা\s*ইনকাম|ঘরে\s*বসে\s*আয়|ক্লিক\s*করুন|লটারি|জুয়া|বেটিং)/, 'looks like spam / scam (Bangla)'],
  [/(.)\1{11,}/, 'long repeated characters'],
  [/\b(\w{2,})\b(?:\s+\1\b){7,}/i, 'repeated words'],
  [/[A-Za-z0-9+\/=_-]{70,}/, 'long encoded / random string'],
];

const URL_RE = /((?:[hH][tT][tT][pP][sS]?:\/\/|[fF][tT][pP]:\/\/|[wW][wW][wW]\.)[^\s<>"')]+)|\b([a-z0-9-]+\.)+(com|net|org|info|biz|io|co|me|ly|app|xyz|top|click|link|site|online|shop|store|bd|in|ru|cn|tk|ml|ga|cf|gq|zip|mov)\b(\/[^\s]*)?/g;

function extractUrls(text) {
  const out = [];
  let m;
  URL_RE.lastIndex = 0;
  while ((m = URL_RE.exec(text)) !== null) out.push(m[0]);
  return out;
}

function scanReview(r) {
  const fields = [r.name, r.email, r.service, r.review].map(function (v) { return String(v == null ? '' : v); });
  const text = fields.join('\n');
  const reasons = [];

  RULES.forEach(function (rule) { if (rule[0].test(text)) reasons.push(rule[1]); });

  // Links: reviews rarely need any, so every link is at least noted.
  const emailDomain = (String(r.email || '').split('@')[1] || '').toLowerCase();
  const urls = extractUrls([r.name, r.service, r.review].join('\n'))
    .filter(function (u) { return u.toLowerCase().replace(/^www\./, '') !== emailDomain; });
  if (urls.length) reasons.push('contains ' + urls.length + ' link' + (urls.length > 1 ? 's' : ''));
  urls.forEach(function (u) {
    if (SHORTENERS.test(u)) reasons.push('shortened link: ' + u.slice(0, 60));
    if (BAD_EXT.test(u)) reasons.push('link to a downloadable / executable file: ' + u.slice(0, 60));
    if (BAD_TLD.test(u)) reasons.push('link with a risky domain ending: ' + u.slice(0, 60));
    if (/\/\/\d{1,3}(\.\d{1,3}){3}/.test(u)) reasons.push('link to a raw IP address');
    if (/xn--/i.test(u)) reasons.push('link with look-alike (punycode) domain');
    if (/@/.test(u.replace(/^[a-z]+:\/\//i, '').split('/')[0])) reasons.push('link with credentials trick (@)');
  });

  // Basic field sanity
  if (!/^[^\s@,;<>"]+@[^\s@,;<>"]+\.[^\s@,;<>"]+$/.test(String(r.email || ''))) reasons.push('invalid email address');
  if (String(r.name || '').length > 80) reasons.push('name too long');

  return { urls: urls, reasons: Array.from(new Set(reasons)) };
}

// Plain-language reasons that are safe to show / email to the customer
// (never include text the customer typed, so they cannot be abused to smuggle links).
const FRIENDLY = [
  [/Safe Browsing/i,            'A link in your review was reported as unsafe.', 'আপনার রিভিউয়ের একটি লিংক অনিরাপদ হিসেবে চিহ্নিত হয়েছে।'],
  [/link|IP address|punycode|credentials|messaging-invite/i, 'Links or web addresses are not allowed in reviews.', 'রিভিউতে লিংক বা ওয়েব ঠিকানা দেওয়া যাবে না।'],
  [/HTML|script|data URI|event handler|encoded markup|SQL|shell/i, 'Code or special markup is not allowed in reviews.', 'রিভিউতে কোড বা বিশেষ মার্কআপ দেওয়া যাবে না।'],
  [/malware|piracy/i,           'Mentions of cracked software, malware or piracy are not allowed.', 'ক্র্যাক সফটওয়্যার, ম্যালওয়্যার বা পাইরেসির কথা লেখা যাবে না।'],
  [/spam|scam|phishing/i,       'The text looks like spam, advertising or a scam.', 'লেখাটি স্প্যাম, বিজ্ঞাপন বা প্রতারণার মতো দেখাচ্ছে।'],
  [/repeated|encoded \/ random/i, 'The text looks like repeated or random characters.', 'লেখাটি বারবার একই বা অর্থহীন অক্ষরের মতো দেখাচ্ছে।'],
  [/invalid email/i,            'The email address looks invalid.', 'ইমেইল ঠিকানাটি সঠিক মনে হচ্ছে না।'],
  [/name too long/i,            'The name is too long.', 'নামটি খুব বড়।'],
];
function friendlyReasons(reasons) {
  const en = [], bn = [];
  (reasons || []).forEach(function (r) {
    let hit = null;
    for (let i = 0; i < FRIENDLY.length; i++) { if (FRIENDLY[i][0].test(r)) { hit = FRIENDLY[i]; break; } }
    const e = hit ? hit[1] : 'The text was flagged by our automatic safety check.';
    const b = hit ? hit[2] : 'লেখাটি আমাদের স্বয়ংক্রিয় নিরাপত্তা যাচাইয়ে আটকে গেছে।';
    if (en.indexOf(e) < 0) { en.push(e); bn.push(b); }
  });
  return { en: en, bn: bn };
}

async function safeBrowsingHits(urls) {
  const key = process.env.SAFE_BROWSING_API_KEY;
  if (!key || !urls.length) return [];
  try {
    const res = await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + encodeURIComponent(key), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'techfix-review-scan', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: urls.slice(0, 20).map(function (u) { return { url: /^[a-z]+:\/\//i.test(u) ? u : 'http://' + u }; }),
        },
      }),
    });
    if (!res.ok) return [];
    const data = await res.json();
    return (data.matches || []).map(function (m) { return 'Google Safe Browsing: ' + m.threatType + ' (' + (m.threat && m.threat.url || '').slice(0, 60) + ')'; });
  } catch (e) {
    console.error('review-moderation: Safe Browsing check failed', e);
    return [];
  }
}

/* ------------------------------------------------------------------ */
/*  Thank-you email                                                    */
/* ------------------------------------------------------------------ */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function buildEmail({ name, rating }) {
  const displayName = (name || '').trim() || 'Customer';
  const safeName = escapeHtml(displayName);
  const subject = 'Thank You for Rating TechFix!';

  const stars = rating
    ? '<p style="margin:0 0 22px; font-size:24px; letter-spacing:4px; color:#f59e0b; text-align:center;">' +
      '&#9733;'.repeat(rating) +
      '<span style="color:#d1d5db;">' + '&#9733;'.repeat(5 - rating) + '</span></p>'
    : '';

  const text =
    `Dear ${displayName},\n\n` +
    `Thank you for rating TechFix! We truly appreciate your feedback and support. ` +
    `Your trust inspires us to provide better service.\n\n` +
    `Best regards,\n` +
    `TechFix Team\n` +
    `Computer & Software Services\n` +
    `Sakhipur, Tangail, Bangladesh\n` +
    `Email: support.techfix24@gmail.com\n` +
    `Website: ${SITE_URL}`;

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Thank You for Rating TechFix!</title>
</head>
<body style="margin:0; padding:0; background:#f5f7fa; font-family:Arial, Helvetica, sans-serif; color:#222;">
  <div style="width:100%; padding:30px 12px; box-sizing:border-box;">
    <div style="max-width:520px; margin:0 auto; background:#ffffff; border-radius:10px; border:1px solid #e5e7eb; overflow:hidden;">

      <div style="background:#0d6efd; padding:22px 30px;">
        <span style="color:#ffffff; font-size:22px; font-weight:bold; letter-spacing:.3px;">TechFix</span>
      </div>

      <div style="padding:30px;">
        <h2 style="color:#0d6efd; margin:0 0 20px; font-size:21px; line-height:1.3;">
          Thank You for Rating TechFix!
        </h2>

        <p style="margin:0 0 16px; font-size:15px; line-height:1.6;">Dear ${safeName},</p>

        ${stars}

        <p style="margin:0 0 16px; font-size:15px; line-height:1.7; color:#333;">
          Thank you for rating TechFix! We truly appreciate your feedback and support.
          Your trust inspires us to provide better service.
        </p>

        <p style="margin:24px 0 0; font-size:15px; line-height:1.6;">
          Best regards,<br>
          <strong>TechFix Team</strong>
        </p>

        <div style="margin-top:28px; padding-top:18px; border-top:1px solid #e5e7eb; color:#555; font-size:13px; line-height:1.7;">
          <strong style="color:#222; font-size:15px;">TechFix</strong><br>
          Computer &amp; Software Services<br>
          Sakhipur, Tangail, Bangladesh<br>
          <a href="mailto:support.techfix24@gmail.com" style="color:#222; text-decoration:none;">support.techfix24@gmail.com</a><br>
          <a href="${SITE_URL}" style="color:#222; text-decoration:none;">techfix24.netlify.app</a>
          <p style="margin:12px 0 0; color:#777; font-size:12px;">Reliable &bull; Professional &bull; Trusted</p>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`;

  return { subject, text, html };
}


function buildRejectionEmail({ name, reasons }) {
  const displayName = (name || '').trim() || 'Customer';
  const safeName = escapeHtml(displayName);
  const subject = 'Update on your TechFix review';
  const items = (reasons && reasons.length ? reasons : ['The text was flagged by our automatic safety check.']);

  const text =
    `Dear ${displayName},\n\n` +
    `Thank you for taking the time to review TechFix. Unfortunately, your review could not be published ` +
    `because our automatic safety check found the following:\n\n` +
    items.map(function (x) { return `  - ${x}`; }).join('\n') + `\n\n` +
    `If you believe this is a mistake, please contact us at support.techfix24@gmail.com ` +
    `or visit ${SITE_URL}/contact and our team will review it manually. ` +
    `You are also welcome to submit a new review without the items above.\n\n` +
    `Best regards,\n` +
    `TechFix Team\n` +
    `Computer & Software Services\n` +
    `Sakhipur, Tangail, Bangladesh\n` +
    `Email: support.techfix24@gmail.com\n` +
    `Website: ${SITE_URL}`;

  const html = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${subject}</title></head>
<body style="margin:0; padding:0; background:#f5f7fa; font-family:Arial, Helvetica, sans-serif; color:#222;">
  <div style="width:100%; padding:30px 12px; box-sizing:border-box;">
    <div style="max-width:520px; margin:0 auto; background:#ffffff; border-radius:10px; border:1px solid #e5e7eb; overflow:hidden;">
      <div style="background:#0d6efd; padding:22px 30px;">
        <span style="color:#ffffff; font-size:22px; font-weight:bold; letter-spacing:.3px;">TechFix</span>
      </div>
      <div style="padding:30px;">
        <h2 style="color:#0d6efd; margin:0 0 20px; font-size:21px; line-height:1.3;">Update on your review</h2>
        <p style="margin:0 0 16px; font-size:15px; line-height:1.6;">Dear ${safeName},</p>
        <p style="margin:0 0 16px; font-size:15px; line-height:1.7; color:#333;">
          Thank you for taking the time to review TechFix. Unfortunately, your review could not be published
          because our automatic safety check found the following:
        </p>
        <div style="margin:0 0 18px; padding:14px 18px; background:#fff7ed; border-left:4px solid #f59e0b; border-radius:6px;">
          <ul style="margin:0; padding-left:18px; font-size:14px; line-height:1.8; color:#7c2d12;">
            ${items.map(function (x) { return '<li>' + escapeHtml(x) + '</li>'; }).join('')}
          </ul>
        </div>
        <p style="margin:0 0 16px; font-size:15px; line-height:1.7; color:#333;">
          If you believe this is a mistake, please contact us at
          <a href="mailto:support.techfix24@gmail.com" style="color:#0d6efd;">support.techfix24@gmail.com</a>
          or visit our <a href="${SITE_URL}/contact" style="color:#0d6efd;">contact page</a> and our team will review it manually.
          You are also welcome to submit a new review without the items above.
        </p>
        <p style="margin:24px 0 0; font-size:15px; line-height:1.6;">Best regards,<br><strong>TechFix Team</strong></p>
        <div style="margin-top:28px; padding-top:18px; border-top:1px solid #e5e7eb; color:#555; font-size:13px; line-height:1.7;">
          <strong style="color:#222; font-size:15px;">TechFix</strong><br>
          Computer &amp; Software Services<br>
          Sakhipur, Tangail, Bangladesh<br>
          <a href="mailto:support.techfix24@gmail.com" style="color:#222; text-decoration:none;">support.techfix24@gmail.com</a><br>
          <a href="${SITE_URL}" style="color:#222; text-decoration:none;">techfix24.netlify.app</a>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`;
  return { subject, text, html };
}

async function sendMailTo(to, mail) {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS || !SMTP_FROM) {
    console.error('review-moderation: SMTP environment variables are not fully configured; email skipped.');
    return false;
  }
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST, port: Number(SMTP_PORT), secure: Number(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
  await transporter.sendMail({ from: SMTP_FROM, to: String(to).trim(), subject: mail.subject, text: mail.text, html: mail.html });
  return true;
}

async function sendRejection(r, reasons) {
  if (!/^[^\s@,;<>"]+@[^\s@,;<>"]+\.[^\s@,;<>"]+$/.test(String(r.email || ''))) return false;
  return sendMailTo(r.email, buildRejectionEmail({ name: String(r.name || '').slice(0, 80), reasons: reasons }));
}

async function sendThanks(r) {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS || !SMTP_FROM) {
    console.error('review-moderation: SMTP environment variables are not fully configured; thank-you email skipped.');
    return false;
  }
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST, port: Number(SMTP_PORT), secure: Number(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
  const rating = Math.min(5, Math.max(0, parseInt(r.rating, 10) || 0));
  const { subject, text, html } = buildEmail({ name: String(r.name || '').slice(0, 80), rating });
  await transporter.sendMail({ from: SMTP_FROM, to: String(r.email).trim(), subject, text, html });
  return true;
}

/* ------------------------------------------------------------------ */
/*  Firestore over REST (service-account auth, no firebase-admin)      */
/* ------------------------------------------------------------------ */
const PROJECT_ID = 'techfix-4f654';
const DOCS = 'https://firestore.googleapis.com/v1/projects/' + PROJECT_ID + '/databases/(default)/documents';
let tokenCache = { value: null, exp: 0 };

function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); }

async function getAccessToken() {
  if (tokenCache.value && Date.now() < tokenCache.exp - 60000) return tokenCache.value;
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT is not set in Netlify environment variables');
  let sa;
  try { sa = JSON.parse(raw); } catch (e) { throw new Error('FIREBASE_SERVICE_ACCOUNT is not valid JSON (paste the whole key file content)'); }
  if (!sa.client_email || !sa.private_key) throw new Error('FIREBASE_SERVICE_ACCOUNT is missing client_email / private_key');
  const now = Math.floor(Date.now() / 1000);
  const head = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = b64url(JSON.stringify({
    iss: sa.client_email, scope: 'https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600,
  }));
  const sig = crypto.createSign('RSA-SHA256').update(head + '.' + claim).sign(sa.private_key);
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + head + '.' + claim + '.' + b64url(sig),
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) throw new Error('Google sign-in failed: ' + (data.error_description || data.error || res.status));
  tokenCache = { value: data.access_token, exp: Date.now() + (data.expires_in || 3600) * 1000 };
  return tokenCache.value;
}

async function fsFetch(url, opts) {
  const token = await getAccessToken();
  const res = await fetch(url, Object.assign({}, opts, {
    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
  }));
  const data = await res.json().catch(function () { return {}; });
  if (!res.ok) throw new Error('Firestore ' + res.status + ': ' + ((data.error && data.error.message) || 'request failed'));
  return data;
}

function str(f, k) { return (f[k] && f[k].stringValue) || ''; }

async function fetchPending() {
  const rows = await fsFetch(DOCS + ':runQuery', {
    method: 'POST',
    body: JSON.stringify({ structuredQuery: {
      from: [{ collectionId: 'reviews' }],
      where: { fieldFilter: { field: { fieldPath: 'status' }, op: 'EQUAL', value: { stringValue: 'pending' } } },
      limit: 50,
    } }),
  });
  return rows.filter(function (r) { return r.document; }).map(function (r) {
    const f = r.document.fields || {};
    return {
      path: r.document.name,
      id: r.document.name.split('/').pop(),
      name: str(f, 'name'), email: str(f, 'email'), service: str(f, 'service'), review: str(f, 'review'),
      rating: f.rating ? parseInt(f.rating.integerValue || f.rating.doubleValue || 0, 10) : 0,
      dateMs: f.date && f.date.timestampValue ? new Date(f.date.timestampValue).getTime() : null,
    };
  });
}

async function updateReview(r, fields) {
  const body = { fields: {} };
  Object.keys(fields).forEach(function (k) {
    const v = fields[k];
    body.fields[k] = typeof v === 'boolean' ? { booleanValue: v }
      : Array.isArray(v) ? { arrayValue: { values: v.map(function (x) { return { stringValue: String(x) }; }) } }
      : v instanceof Date ? { timestampValue: v.toISOString() }
      : { stringValue: String(v) };
  });
  const mask = Object.keys(fields).map(function (k) { return 'updateMask.fieldPaths=' + encodeURIComponent(k); }).join('&');
  await fsFetch('https://firestore.googleapis.com/v1/' + r.path + '?' + mask, { method: 'PATCH', body: JSON.stringify(body) });
}

/* ------------------------------------------------------------------ */
/*  Moderation run (used by the schedule AND the admin "Check now")    */
/* ------------------------------------------------------------------ */
async function processPending(opts) {
  const force = !!(opts && opts.force);       // admin "Check now" skips the 5-minute wait
  const pending = await fetchPending();
  const cutoff = Date.now() - HOLD_MS;
  const due = pending.filter(function (r) { return force || !r.dateMs || r.dateMs <= cutoff; }).slice(0, MAX_PER_RUN);
  const result = { pending: pending.length, checked: due.length, approved: 0, flagged: 0, errors: [] };

  for (const r of due) {
    try {
      const scan = scanReview(r);
      const gsb = await safeBrowsingHits(scan.urls);
      const reasons = scan.reasons.concat(gsb);
      if (reasons.length) {
        const fr = friendlyReasons(reasons);
        await updateReview(r, {
          approved: false, status: 'flagged', scanReasons: reasons,
          publicReasons: fr.en, publicReasonsBn: fr.bn, checkedAt: new Date(),
        });
        result.flagged++;
        try {
          if (await sendRejection(r, fr.en)) await updateReview(r, { rejectedEmailAt: new Date() });
        } catch (mailErr) {
          console.error('review-moderation: rejection email failed for', r.id, mailErr);
          result.errors.push('Rejection email failed: ' + mailErr.message);
        }
      } else {
        // NOTE: no empty scanReasons array is written here (keeps the update minimal and reliable)
        await updateReview(r, { approved: true, status: 'approved', checkedAt: new Date() });
        result.approved++;
        try {
          if (await sendThanks(r)) await updateReview(r, { thankedAt: new Date() });
        } catch (mailErr) {
          console.error('review-moderation: thank-you email failed for', r.id, mailErr);
          result.errors.push('Thank-you email failed: ' + mailErr.message);
        }
      }
    } catch (err) {
      console.error('review-moderation: failed to process', r.id, err);
      result.errors.push(err.message);
    }
  }
  console.log('review-moderation:', JSON.stringify(result));
  return result;
}

exports.handler = async function () {
  try {
    await processPending();
    return { statusCode: 200 };
  } catch (e) {
    console.error('review-moderation:', e.message);
    return { statusCode: 500 };
  }
};

exports.processPending = processPending;
exports.scanReview = scanReview;
exports.buildEmail = buildEmail;
exports.buildRejectionEmail = buildRejectionEmail;
exports.friendlyReasons = friendlyReasons;
