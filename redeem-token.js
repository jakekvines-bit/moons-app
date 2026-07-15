// Server-side only. Uses the Supabase SERVICE ROLE key, which must be set as
// an environment variable in the Netlify dashboard (Site settings -> Environment
// variables) and must NEVER be placed in the HTML/JS that ships to the browser.
//
// What this does: takes a long-lived device token from a saved personal link,
// looks up which account it belongs to, and mints a fresh one-time sign-in
// token for that account. The browser then exchanges that for a real Supabase
// session via supabase.auth.verifyOtp(). No email, no click-through, no typing.

const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

exports.handler = async function (event) {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: JSON.stringify({ error: "Method not allowed" }) };
  }

  if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Server is missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY." })
    };
  }

  let token;
  try {
    const body = JSON.parse(event.body || "{}");
    token = body.token;
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: "Bad request body." }) };
  }

  if (!token || typeof token !== "string") {
    return { statusCode: 400, body: JSON.stringify({ error: "Missing token." }) };
  }

  const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

  const { data: row, error: rowErr } = await admin
    .from("device_tokens")
    .select("user_id")
    .eq("token", token)
    .maybeSingle();

  if (rowErr || !row) {
    return { statusCode: 404, body: JSON.stringify({ error: "This saved link is no longer valid." }) };
  }

  const { data: userRes, error: userErr } = await admin.auth.admin.getUserById(row.user_id);
  if (userErr || !userRes || !userRes.user || !userRes.user.email) {
    return { statusCode: 404, body: JSON.stringify({ error: "Could not find the account for this link." }) };
  }

  const { data: linkData, error: linkErr } = await admin.auth.admin.generateLink({
    type: "magiclink",
    email: userRes.user.email
  });

  if (linkErr || !linkData || !linkData.properties || !linkData.properties.hashed_token) {
    return { statusCode: 500, body: JSON.stringify({ error: "Could not generate a sign-in token." }) };
  }

  // Best-effort bookkeeping; don't fail the request if this write has trouble.
  admin
    .from("device_tokens")
    .update({ last_used_at: new Date().toISOString() })
    .eq("token", token)
    .then(
      function () {},
      function () {}
    );

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token_hash: linkData.properties.hashed_token })
  };
};
