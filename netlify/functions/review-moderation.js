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
//   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM   (same as the appointment email)
// Optional:
//   SAFE_BROWSING_API_KEY      Google Safe Browsing key — links are also checked against Google's malware list

const admin = require('firebase-admin');
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

const URL_RE = /((?:https?:\/\/|ftp:\/\/|www\.)[^\s<>"')]+)|\b([a-z0-9-]+\.)+(com|net|org|info|biz|io|co|me|ly|app|xyz|top|click|link|site|online|shop|store|bd|in|ru|cn|tk|ml|ga|cf|gq|zip|mov)\b(\/[^\s]*)?/gi;

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
/*  Scheduled handler                                                  */
/* ------------------------------------------------------------------ */
function getDb() {
  if (!admin.apps.length) {
    const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT is not set');
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(raw)) });
  }
  return admin.firestore();
}

exports.handler = async function () {
  let db;
  try { db = getDb(); }
  catch (e) { console.error('review-moderation:', e.message); return { statusCode: 500 }; }

  const snap = await db.collection('reviews').where('status', '==', 'pending').get();
  const cutoff = Date.now() - HOLD_MS;
  const due = snap.docs.filter(function (d) {
    const t = d.get('date');
    // A pending review with no usable date is treated as due so it can never get stuck.
    return !t || !t.toMillis || t.toMillis() <= cutoff;
  }).slice(0, MAX_PER_RUN);

  let approved = 0, flagged = 0;
  for (const doc of due) {
    const r = doc.data();
    try {
      const scan = scanReview(r);
      const gsb = await safeBrowsingHits(scan.urls);
      const reasons = scan.reasons.concat(gsb);
      const base = { checkedAt: admin.firestore.FieldValue.serverTimestamp(), scanReasons: reasons };

      if (reasons.length) {
        await doc.ref.update(Object.assign({ approved: false, status: 'flagged' }, base));
        flagged++;
      } else {
        await doc.ref.update(Object.assign({ approved: true, status: 'approved' }, base));
        approved++;
        try {
          if (await sendThanks(r)) await doc.ref.update({ thankedAt: admin.firestore.FieldValue.serverTimestamp() });
        } catch (mailErr) {
          console.error('review-moderation: thank-you email failed for', doc.id, mailErr);
        }
      }
    } catch (err) {
      console.error('review-moderation: failed to process', doc.id, err);
    }
  }
  console.log('review-moderation: checked', due.length, '| approved', approved, '| flagged', flagged);
  return { statusCode: 200 };
};

exports.scanReview = scanReview;
exports.buildEmail = buildEmail;
