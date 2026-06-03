// POST /api/interac-exchange
// Called by the frontend after Interac redirects back to /callback.
// Exchanges the auth code for tokens, hashes the sub, records the vote.

import { createClient } from '@supabase/supabase-js';
import { SignJWT, importPKCS8 } from 'jose';
import crypto from 'crypto';

const INTERAC_ISSUER    = 'https://gateway-portal.hub-verify.innovation.interac.ca';
const TOKEN_ENDPOINT    = `${INTERAC_ISSUER}/oauth2/token`;
const USERINFO_ENDPOINT = `${INTERAC_ISSUER}/userinfo`;
const CLIENT_ID         = '12011230-9c6c-42e3-9834-1bf2d8ee2a91';
const KID               = 'petition-rp-2026';

function loadPrivateKeyPem() {
  const b64 = process.env.INTERAC_PRIVATE_KEY_B64;
  if (!b64) throw new Error('INTERAC_PRIVATE_KEY_B64 not set');
  return Buffer.from(b64, 'base64').toString('utf8');
}

// HMAC-SHA256 is stronger than plain SHA256+salt concatenation.
// The HASH_SALT makes the hash useless to anyone who steals the DB —
// they cannot reverse it without the salt.
function hashVoterSub(sub) {
  const salt = process.env.HASH_SALT;
  if (!salt) throw new Error('HASH_SALT env var not set');
  return crypto.createHmac('sha256', salt).update(sub).digest('hex');
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  try {
    if (req.method !== 'POST')
      return res.status(405).json({ error: 'Method not allowed' });

    const { code, state } = req.body ?? {};
    if (!code || !state)
      return res.status(400).json({ error: 'Missing code or state' });

    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY   // service role — bypasses RLS
    );

    // ── 1. Validate state, retrieve session ──────────────────────────
    const { data: sessions, error: fetchErr } = await supabase
      .from('pending_sessions')
      .select('province, code_verifier, nonce')
      .eq('state', state)
      .limit(1);

    if (fetchErr || !sessions?.length)
      return res.status(400).json({ error: 'Invalid or expired session. Please start over.' });

    const { province, code_verifier } = sessions[0];

    // Delete immediately — one-time use
    await supabase.from('pending_sessions').delete().eq('state', state);

    const host        = req.headers['x-forwarded-host'] ?? req.headers.host ?? 'localhost:3000';
    const proto       = req.headers['x-forwarded-proto'] ?? 'https';
    const redirectUri = `${proto}://${host}/callback`;

    // ── 2. Build signed client_assertion for the token endpoint ──────
    const pem        = loadPrivateKeyPem();
    const privateKey = await importPKCS8(pem, 'RS256');
    const now        = Math.floor(Date.now() / 1000);

    const clientAssertion = await new SignJWT({
      iss: CLIENT_ID,
      sub: CLIENT_ID,
      aud: TOKEN_ENDPOINT,   // aud = token_endpoint per Interac docs
      exp: now + 300,
      iat: now,
      jti: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: 'RS256', kid: KID })
      .sign(privateKey);

    // ── 3. Exchange auth code → access token ─────────────────────────
    const tokenRes = await fetch(TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:            'authorization_code',
        code,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion:      clientAssertion,
        client_id:             CLIENT_ID,
        redirect_uri:          redirectUri,
        code_verifier,         // PKCE verifier from session
      }).toString(),
    });

    if (!tokenRes.ok) {
      const body = await tokenRes.text();
      console.error('[exchange] Token error:', body);
      return res.status(502).json({ error: 'Verification failed at token step', detail: body });
    }

    const { access_token } = await tokenRes.json();

    // ── 4. Fetch verified user claims ────────────────────────────────
    const userinfoRes = await fetch(USERINFO_ENDPOINT, {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    if (!userinfoRes.ok) {
      const body = await userinfoRes.text();
      console.error('[exchange] Userinfo error:', body);
      return res.status(502).json({ error: 'Verification failed at identity step', detail: body });
    }

    const { sub } = await userinfoRes.json();
    if (!sub) return res.status(400).json({ error: 'No identity returned from Interac' });

    // ── 5. Hash the sub — never store it raw ─────────────────────────
    // HMAC-SHA256(HASH_SALT, sub)
    // Same person → same hash every time (deterministic)
    // Different salt → different hash (salt rotation invalidates all)
    const voterHash = hashVoterSub(sub);

    // ── 6. Insert — unique constraint blocks double votes ─────────────
    const { error: insertError } = await supabase
      .from('signatures')
      .insert({ voter_hash: voterHash, province });

    if (insertError) {
      // Postgres error 23505 = unique_violation
      if (insertError.code === '23505') {
        return res.status(409).json({
          error: 'already_voted',
          message: 'Your identity has already been used to sign this petition.',
        });
      }
      console.error('[exchange] Insert error:', insertError);
      return res.status(500).json({ error: 'Could not record vote' });
    }

    // vote_counts is updated automatically by the DB trigger
    return res.status(200).json({ success: true, province });

  } catch (err) {
    console.error('[interac-exchange] Unhandled error:', err);
    return res.status(500).json({ error: 'Internal server error', detail: err.message });
  }
}
