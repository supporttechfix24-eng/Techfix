# TechFix Website (Netlify)

The public site: English + Bengali (`/bn/`) pages, the admin panel
(`login-admin.html`), custom pages/blocks CMS, and an appointment
confirmation-email function.

This is deployed **separately from** the Telegram bridge
(`techfix-telegram-integration`) — they only share the same Firestore
database, nothing else.

## Deploy

1. Push this folder to a GitHub repo (or drag-and-drop it into Netlify's
   dashboard) and connect it as a new Netlify site. `netlify.toml` already
   tells Netlify to publish the repo root and run `netlify/functions/` as
   Functions — no extra build configuration needed.
2. In **Netlify → Site settings → Environment variables**, add (for the
   appointment confirmation email):
   ```
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=465
   SMTP_USER=your_email@gmail.com
   SMTP_PASS=your_16_char_app_password   (Gmail: myaccount.google.com/apppasswords)
   SMTP_FROM=your_email@gmail.com
   ```
   These are **separate** from the Telegram bridge's SMTP variables — set on
   both if you want both features working, even though the values can be
   identical.
3. Deploy. Netlify installs `package.json`'s one dependency (`nodemailer`)
   for the function automatically.

## ⚠️ Publish the Firestore rules — required, one-time

`firestore.rules` in this folder is only a text file until you paste it into
**Firebase Console → Firestore Database → Rules → Publish**. Nothing in this
repo does that automatically. Until you publish it, the site is running on
whatever rules are already live in your Firebase project (which may not
match what these pages now write/read).

The rules restrict all admin actions (approving reviews, managing
appointments/pages/live chat from `login-admin.html`) to Firebase Auth users
whose email is exactly the one hardcoded in `firestore.rules`
(`isAdmin()` function, near the top). If you ever change the admin's login
email, update that line and republish.

## What's new in this build vs. before

- **Bengali version** at `/bn/` (and `hreflang` links between the two in
  `sitemap.xml`)
- **Custom pages**: `login-admin.html` → *Pages* creates pages served at
  `/p/<slug>` via `page.html` + `cms-extra.js`. Now includes optional
  "Browser tab / SEO title" and "Hide from search engines" controls in the
  editor
- **Custom code blocks**: `login-admin.html` → *Code Editor* → injected
  site-wide by `cms-extra.js`
- **Appointment confirmation email**: sent via
  `netlify/functions/send-confirmation-email.js` right after a booking is
  saved; a failure here never blocks or changes the booking itself
- **Privacy-conscious "Track My Appointment"**: `appointmentTracking/{ref}`
  holds only the last 4 phone digits — never the full phone, email, or notes
- `firestore.rules`: admin-only access enforced server-side (not just hidden
  in the UI), plus basic spam/size limits on every public write

## Folder

```
techfix24-site/
├─ index.html, services.html, pricing.html, contact.html,
│  appointment.html, reviews.html      # English pages
├─ bn/                                 # Bengali versions of the same pages
├─ login-admin.html                    # admin panel (Firebase Auth login)
├─ page.html                           # renders any /p/<slug> custom page
├─ cms-extra.js                        # injects custom pages/blocks site-wide
├─ firestore.rules                     # publish this in Firebase Console
├─ netlify/functions/
│  └─ send-confirmation-email.js       # appointment confirmation email
├─ netlify.toml, _redirects, robots.txt, sitemap.xml
├─ favicon*.png/ico, apple-touch-icon.png, site.webmanifest
├─ 404.html
└─ package.json                        # just nodemailer, for the function
```
