// POST /api/interac/exchange
// Called by callback.html after Interac redirects back with ?code= & ?state=
// 1. Validates state against Supabase session
// 2. Exchanges code for access_token using a signed client_assertion
// 3. Fetches userinfo to get the unique `sub` (permanent user identifier from Interac)
// 4. Hashes the sub and records the vote — duplicate sub = 409

import { createClient } from '@supabase/supabase-js';
import { SignJWT, importPKCS8 } from 'jose';
import crypto from 'crypto';

const INTERAC_ISSUER      = 'https://gateway-portal.hub-verify.innovation.interac.ca';
const INTERAC_TOKEN_URL   = `${INTERAC_ISSUER}/oauth2/token`;
const INTERAC_USERINFO_URL = `${INTERAC_ISSUER}/userinfo`;
const CLIENT_ID           = '12011230-9c6c-42e3-9834-1bf2d8ee2a91';
const KID                 = 'petition-rp-2026';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { code, state } = req.body ?? {};
  if (!code || !state) {
    return res.status(400).json({ error: 'code and state are required' });
  }

  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
  );

  // 1. Retrieve and validate session
  const { data: session, error: sessionErr } = await supabase
    .from('pending_sessions')
    .select('*')
    .eq('state', state)
    .single();

  if (sessionErr || !session) {
    return res.status(400).json({ error: 'Invalid or expired state. Please restart the verification.' });
  }

  // Check session not older than 10 minutes
  if (Date.now() - new Date(session.created_at).getTime() > 10 * 60 * 1000) {
    await supabase.from('pending_sessions').delete().eq('state', state);
    return res.status(400).json({ error: 'Verification session expired. Please try again.' });
  }

  // Delete session immediately (one-use)
  await supabase.from('pending_sessions').delete().eq('state', state);

  // Derive redirect_uri (must match what was sent in start.js)
  const host = req.headers['x-forwarded-host'] ?? req.headers.host ?? 'localhost:3000';
  const proto = req.headers['x-forwarded-proto'] ?? 'https';
  const redirectUri = `${proto}://${host}/callback`;

  // Load private key
  const privatePem = (process.env.INTERAC_PRIVATE_KEY ?? '').replace(/\\n/g, '\n');
  if (!privatePem) {
    return res.status(500).json({ error: 'INTERAC_PRIVATE_KEY env var not set' });
  }
  const privateKey = await importPKCS8(privatePem, 'RS256');

  // 2. Build signed client_assertion JWT (required by Interac token endpoint)
  const now = Math.floor(Date.now() / 1000);
  const clientAssertion = await new SignJWT({
    iss: CLIENT_ID,
    sub: CLIENT_ID,
    aud: INTERAC_TOKEN_URL,
    jti: crypto.randomUUID(),
    iat: now,
    exp: now + 300,
  })
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .sign(privateKey);

  // 3. Exchange code for access_token
  const tokenParams = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
    client_id: CLIENT_ID,
    redirect_uri: redirectUri,
    code_verifier: session.code_verifier,
  });

  let tokenData;
  try {
    const tokenRes = await fetch(INTERAC_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenParams.toString(),
    });
    tokenData = await tokenRes.json();
    if (!tokenRes.ok) {
      console.error('Token error:', tokenData);
      return res.status(502).json({ error: 'Token exchange failed', detail: tokenData });
    }
  } catch (e) {
    console.error('Token fetch error:', e);
    return res.status(502).json({ error: 'Could not reach Interac token endpoint' });
  }

  // 4. Fetch userinfo to get the user's unique sub
  let userInfo;
  try {
    const userRes = await fetch(INTERAC_USERINFO_URL, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    userInfo = await userRes.json();
    if (!userRes.ok) {
      console.error('UserInfo error:', userInfo);
      return res.status(502).json({ error: 'Could not retrieve user identity' });
    }
  } catch (e) {
    console.error('UserInfo fetch error:', e);
    return res.status(502).json({ error: 'Could not reach Interac userinfo endpoint' });
  }

  if (!userInfo.sub) {
    return res.status(502).json({ error: 'No subject identifier returned from Interac' });
  }

  // 5. Hash the sub — we never store raw PII, only a one-way hash
  const token = crypto.createHash('sha256')
    .update(`interac::${userInfo.sub}`)
    .digest('hex');

  // 6. Record the vote (UNIQUE constraint catches duplicates)
  const { error: insertError } = await supabase
    .from('signatures')
    .insert({ verification_token: token, province: session.province });

  if (insertError?.code === '23505') {
    return res.status(409).json({ error: 'You have already signed this petition.' });
  }
  if (insertError) {
    console.error('Insert error:', insertError);
    return res.status(500).json({ error: 'Database error — please try again.' });
  }

  // Return minimal info — no PII
  return res.status(200).json({
    success: true,
    source: userInfo.source ?? 'verified',
  });
}
