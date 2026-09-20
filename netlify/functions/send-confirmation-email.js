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
// Optional:
//   TRACK_URL
//
// If TRACK_URL is not provided, the function uses the existing
// TechFix appointment tracking panel URL.

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

  // Plain-text version
  const text =
    `Hello ${name || 'Customer'},\n\n` +
    `Your appointment request has been successfully received by TechFix.\n\n` +
    `Track/Support ID: ${trackId}\n` +
    `Status: Pending\n\n` +
    `You can use your Track/Support ID to check your appointment status anytime:\n` +
    `${TRACK_URL}\n\n` +
    `Thank you for choosing TechFix.\n\n` +
    `TechFix – Computer & Software Services\n` +
    `Sakhipur, Tangail, Bangladesh\n` +
    `Email: support.techfix24@gmail.com\n` +
    `Website: https://techfix24.netlify.app\n\n` +
    `Reliable • Professional • Trusted`;

  // HTML version
  const html = `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TechFix Appointment Confirmation</title>
  </head>

  <body style="margin:0; padding:0; background:#f5f7fa; font-family:Arial, Helvetica, sans-serif; color:#222;">

    <div style="width:100%; padding:30px 12px; box-sizing:border-box;">

      <div style="
        max-width:520px;
        margin:0 auto;
        background:#ffffff;
        border-radius:10px;
        padding:30px;
        box-sizing:border-box;
        border:1px solid #e5e7eb;
      ">

        <!-- Header -->
        <h2 style="
          color:#0d6efd;
          margin:0 0 20px;
          font-size:22px;
          line-height:1.3;
        ">
          TechFix Appointment Confirmation
        </h2>

        <!-- Greeting -->
        <p style="margin:0 0 16px; font-size:15px; line-height:1.6;">
          Hello ${safeName},
        </p>

        <p style="margin:0 0 20px; font-size:15px; line-height:1.6;">
          Your appointment request has been successfully received by TechFix.
        </p>

        <!-- Appointment Details -->
        <table style="
          width:100%;
          border-collapse:collapse;
          margin:16px 0 20px;
          font-size:14px;
        ">
          <tr>
            <td style="
              padding:8px 0;
              color:#555;
              width:55%;
            ">
              Track/Support ID
            </td>

            <td style="
              padding:8px 0;
              font-weight:bold;
              color:#222;
            ">
              ${safeId}
            </td>
          </tr>

          <tr>
            <td style="
              padding:8px 0;
              color:#555;
            ">
              Status
            </td>

            <td style="padding:8px 0;">
              <span style="
                background:#fff3cd;
                color:#664d03;
                padding:4px 10px;
                border-radius:12px;
                font-size:13px;
                display:inline-block;
              ">
                Pending
              </span>
            </td>
          </tr>
        </table>

        <!-- Tracking Information -->
        <p style="
          margin:0 0 22px;
          font-size:14px;
          line-height:1.6;
          color:#444;
        ">
          You can use your Track/Support ID to check your appointment status anytime.
        </p>

        <!-- Track Button -->
        <p style="
          text-align:center;
          margin:26px 0;
        ">
          <a
            href="${TRACK_URL}"
            style="
              background:#0d6efd;
              color:#ffffff;
              text-decoration:none;
              padding:13px 26px;
              border-radius:6px;
              display:inline-block;
              font-weight:bold;
              font-size:14px;
            "
          >
            Track My Appointment
          </a>
        </p>

        <!-- Thank You -->
        <p style="
          margin:24px 0 0;
          font-size:14px;
          line-height:1.6;
        ">
          Thank you for choosing TechFix.
        </p>

        <!-- Professional Footer -->
        <div style="
          margin-top:28px;
          padding-top:18px;
          border-top:1px solid #e5e7eb;
          color:#555;
          font-size:13px;
          line-height:1.7;
        ">

          <strong style="
            color:#222;
            font-size:15px;
          ">
            TechFix
          </strong>

          <br>

          Computer &amp; Software Services

          <br>

          Sakhipur, Tangail, Bangladesh

          <br>

          <a
            href="mailto:support.techfix24@gmail.com"
            style="
              color:black;
              text-decoration:none;
            "
          >
            support.techfix24@gmail.com
          </a>

          <br>

          <a
            href="https://techfix24.netlify.app"
            style="
              color:black;
              text-decoration:none;
            "
          >
            techfix24.netlify.app
          </a>

          <p style="
            margin:12px 0 0;
            color:#777;
            font-size:12px;
          ">
            Reliable &bull; Professional &bull; Trusted
          </p>

        </div>

      </div>

    </div>

  </body>
  </html>
  `;

  return { subject, text, html };
}

exports.handler = async function (event) {
  // Only POST requests are allowed
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: 'Method Not Allowed',
    };
  }

  // Parse request body
  let payload;

  try {
    payload = JSON.parse(event.body || '{}');
  } catch (err) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        success: false,
        error: 'Invalid JSON body',
      }),
    };
  }

  const { name, email, trackId } = payload;

  // Basic validation.
  // The Track/Support ID must already exist.
  // This function never creates or changes the ID.
  if (!email || !trackId) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        success: false,
        error: 'Missing required fields: email and trackId are required.',
      }),
    };
  }

  // Read SMTP configuration from Netlify environment variables
  const {
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASS,
    SMTP_FROM,
  } = process.env;

  // Check required environment variables
  if (
    !SMTP_HOST ||
    !SMTP_PORT ||
    !SMTP_USER ||
    !SMTP_PASS ||
    !SMTP_FROM
  ) {
    // Never expose which environment variable is missing to the client.
    console.error(
      'send-confirmation-email: SMTP environment variables are not fully configured.'
    );

    return {
      statusCode: 500,
      body: JSON.stringify({
        success: false,
        error: 'Email service is not configured.',
      }),
    };
  }

  try {
    // Create SMTP transporter
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT),

      // Gmail:
      // 465 = SSL/TLS
      // 587 = STARTTLS
      secure: Number(SMTP_PORT) === 465,

      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS,
      },
    });

    // Build email
    const {
      subject,
      text,
      html,
    } = buildEmail({
      name,
      trackId,
    });

    // Send email
    await transporter.sendMail({
      from: SMTP_FROM,
      to: email,
      subject,
      text,
      html,
    });

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
      }),
    };

  } catch (error) {
    // Log safely on server side.
    // Appointment data is not changed or rolled back.
    console.error(
      'send-confirmation-email: failed to send email for trackId',
      trackId,
      error
    );

    return {
      statusCode: 500,
      body: JSON.stringify({
        success: false,
        error: 'Failed to send email.',
      }),
    };
  }
};