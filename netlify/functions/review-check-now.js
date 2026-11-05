// netlify/functions/review-check-now.js
//
// Called by the admin panel's "Check pending reviews now" button.
// Only the admin (verified through their Firebase login token) can use it.
// Runs the same scan as the scheduled function, without the 5-minute wait,
// and returns a readable result / error so problems are visible.

const { processPending } = require('./review-moderation');

const API_KEY = 'AIzaSyBEzDwFvrlM7vp3jX49o0P1A8jZwI7dUmI';   // public Firebase web key
const ADMIN_EMAIL = 'shamimmd1618@gmail.com';

function reply(code, obj) { return { statusCode: code, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(obj) }; }

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') return reply(405, { ok: false, error: 'Method Not Allowed' });
  let idToken = '';
  try { idToken = String(JSON.parse(event.body || '{}').idToken || ''); } catch (e) {}
  if (!idToken) return reply(401, { ok: false, error: 'Not signed in.' });

  try {
    const res = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + API_KEY, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken }),
    });
    const data = await res.json();
    const email = data && data.users && data.users[0] && String(data.users[0].email || '').toLowerCase();
    if (!res.ok || email !== ADMIN_EMAIL) return reply(403, { ok: false, error: 'Admin only.' });
  } catch (e) {
    return reply(502, { ok: false, error: 'Could not verify login: ' + e.message });
  }

  try {
    const result = await processPending({ force: true });
    return reply(200, Object.assign({ ok: true }, result));
  } catch (e) {
    return reply(500, { ok: false, error: e.message });
  }
};
