// netlify/functions/send-confirmation-email.js
//
// Server-side only. Sends the English appointment-confirmation email using
// the existing TechFix SMTP account. This function does NOT generate,
// change, or store the Track/Support ID — it only emails the ID that was
// already generated and saved by the appointment form.
//
// Required environment variables (set in Netlify dashboard, never in code):
//   SMTP_HOST
//   SMTP_PORT
//   SMTP_USER
//   SMTP_PASS
//   SMTP_FROM
//
// The appointment tracking page URL can optionally be overridden with
// TRACK_URL; otherwise it defaults to the existing English appointment page
// where the "Track My Appointment" panel already lives.

const nodemailer = require('nodemailer');

const TRACK_URL =
  process.env.TRACK_URL ||
  'https://techfix24.netlify.app/appointment#trackAppointmentPanel';

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function buildEmail({ name, trackId }) {
  const safeName = escapeHtml(name || 'Customer');
  const safeId = escapeHtml(trackId);

  const subject = `TechFix Appointment Confirmation – ${trackId}`;

  const text =
    `Hello ${name || 'Customer'},\n\n` +
    `Your appointment request has been successfully received by TechFix.\n\n` +
    `Track/Support ID: ${trackId}\n` +
    `Status: Pending\n\n` +
    `You can use your Track/Support ID to check your appointment status anytime:\n` +
    `${TRACK_URL}\n\n` +
    `Thank you for choosing TechFix.\n\n` +
    `TechFix\n` +
    `Sakhipur, Tangail`;

  const html = `
  <div style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #222;">
    <h2 style="color: #0d6efd; margin-bottom: 4px;">TechFix Appointment Confirmation</h2>
    <p>Hello ${safeName},</p>
    <p>Your appointment request has been successfully received by TechFix.</p>
    <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
      <tr>
        <td style="padding: 6px 0; color: #555;">Track/Support ID</td>
        <td style="padding: 6px 0; font-weight: bold;">${safeId}</td>
      </tr>
      <tr>
        <td style="padding: 6px 0; color: #555;">Status</td>
        <td style="padding: 6px 0;">
          <span style="background:#fff3cd;color:#664d03;padding:2px 10px;border-radius:12px;font-size:13px;">Pending</span>
        </td>
      </tr>
    </table>
    <p>You can use your Track/Support ID to check your appointment status anytime.</p>
    <p style="text-align: center; margin: 24px 0;">
      <a href="${TRACK_URL}"
         style="background:#0d6efd;color:#fff;text-decoration:none;padding:12px 24px;border-radius:6px;display:inline-block;font-weight:bold;">
        Track My Appointment
      </a>
    </p>
    <p>Thank you for choosing TechFix.</p>
    <p style="margin-top: 24px; color: #555;">
      TechFix<br>
      Sakhipur, Tangail
    </p>
  </div>`;

  return { subject, text, html };
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || '{}');
  } catch (err) {
    return { statusCode: 400, body: JSON.stringify({ success: false, error: 'Invalid JSON body' }) };
  }

  const { name, email, trackId } = payload;

  // Basic validation. The Track/Support ID must already exist — this
  // function never creates one.
  if (!email || !trackId) {
    return {
      statusCode: 400,
      body: JSON.stringify({ success: false, error: 'Missing required fields: email and trackId are required.' }),
    };
  }

  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM } = process.env;

  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS || !SMTP_FROM) {
    // Fail safely: never expose which var is missing to the client, just log
    // server-side for debugging. The appointment itself is unaffected.
    console.error('send-confirmation-email: SMTP environment variables are not fully configured.');
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: 'Email service is not configured.' }),
    };
  }

  try {
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT),
      secure: Number(SMTP_PORT) === 465, // true for port 465, false for 587/others
      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS,
      },
    });

    const { subject, text, html } = buildEmail({ name, trackId });

    await transporter.sendMail({
      from: SMTP_FROM,
      to: email,
      subject,
      text,
      html,
    });

    return { statusCode: 200, body: JSON.stringify({ success: true }) };
  } catch (error) {
    // Log safely server-side. The appointment has already been saved by the
    // caller before this function is invoked, so a failure here must never
    // roll back or duplicate the appointment or its Track/Support ID.
    console.error('send-confirmation-email: failed to send email for trackId', trackId, error);
    return { statusCode: 500, body: JSON.stringify({ success: false, error: 'Failed to send email.' }) };
  }
};
