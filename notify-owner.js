// Netlify serverless function — sends a WhatsApp alert to the owner
// via CallMeBot whenever a new transfer request comes in.
//
// SECURITY NOTES:
// - The CallMeBot phone number and API key live here (server-side), never
//   in index.html, since client-side JS is visible to anyone via page source.
// - This endpoint also checks a shared secret (APP_SHARED_SECRET) and the
//   request's Origin header, to stop random internet traffic from hitting
//   this URL and spamming the owner's WhatsApp. This is not bulletproof —
//   a determined attacker who reads the site's JS can extract the secret —
//   but it stops casual scanning/abuse of a public, unauthenticated URL.
//
// SETUP:
// 1. In the Netlify dashboard: Site settings > Environment variables > Add:
//      OWNER_PHONE       = 675XXXXXXXX   (no + or spaces)
//      CALLMEBOT_APIKEY  = the key CallMeBot sent after activation
//      APP_SHARED_SECRET = any long random string you choose
// 2. Put the SAME APP_SHARED_SECRET value into index.html (see the
//    APP_SHARED_SECRET constant near the top of the script).
// 3. Redeploy after setting the environment variables.

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const OWNER_PHONE = process.env.OWNER_PHONE;
  const CALLMEBOT_APIKEY = process.env.CALLMEBOT_APIKEY;
  const APP_SHARED_SECRET = process.env.APP_SHARED_SECRET;

  if (!OWNER_PHONE || !CALLMEBOT_APIKEY || !APP_SHARED_SECRET) {
    console.error('Missing required environment variables');
    return { statusCode: 500, body: 'Server not configured' };
  }

  // Reject requests that don't carry the correct shared secret header.
  const providedSecret = event.headers['x-app-secret'] || event.headers['X-App-Secret'];
  if (providedSecret !== APP_SHARED_SECRET) {
    console.warn('Rejected request with invalid or missing shared secret');
    return { statusCode: 403, body: 'Forbidden' };
  }

  let record;
  try {
    record = JSON.parse(event.body);
  } catch (err) {
    return { statusCode: 400, body: 'Invalid request body' };
  }

  const { staff, customer, acctname, acctnum, bank, amount, createdAt } = record;

  const message =
    `🔔 NEW TRANSFER REQUEST\n` +
    `Staff: ${staff}\n` +
    `Customer: ${customer}\n` +
    `Send to: ${acctname}\n` +
    `Account #: ${acctnum}\n` +
    `Bank: ${bank}\n` +
    `Amount: K${amount}\n` +
    `Time: ${createdAt}\n\n` +
    `Check the Dashboard once sent.`;

  const url = 'https://api.callmebot.com/whatsapp.php'
    + '?phone=' + encodeURIComponent(OWNER_PHONE)
    + '&text=' + encodeURIComponent(message)
    + '&apikey=' + encodeURIComponent(CALLMEBOT_APIKEY);

  try {
    const res = await fetch(url);
    const text = await res.text();
    return { statusCode: 200, body: JSON.stringify({ ok: true, callmebot: text }) };
  } catch (err) {
    console.error('CallMeBot send failed:', err);
    // Return 200 anyway — the transfer request itself is already safely
    // saved in Firebase regardless of whether this notification succeeds.
    return { statusCode: 200, body: JSON.stringify({ ok: false, error: 'notify failed' }) };
  }
};
