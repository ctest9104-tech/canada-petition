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

// Hash 1 — blocks same-method duplicates
// IVS: sub is stable per user per RP → reliably catches bank re-votes
// IDVS: sub is a per-session job_id → catches same session re-use
function hashSub(sub) {
  const salt = process.env.HASH_SALT;
  if (!salt) throw new Error('HASH_SALT not set');
  return crypto.createHmac('sha256', salt).update(sub).digest('hex');
}

// Hash 2 — blocks cross-method duplicates
// given_name + family_name + birthdate are stable across both IVS and IDVS
// for the same real person. This is what prevents bank + ID double voting.
function hashIdentity(givenName, familyName, birthdate) {
  const salt = process.env.HASH_SALT;
  if (!salt) throw new Error('HASH_SALT not set');
  const normalize = s => (s || '').toUpperCase().replace(/\s+/g, ' ').trim();
  const composite = `${normalize(givenName)}|${normalize(familyName)}|${(birthdate || '').trim()}`;
  return crypto.createHmac('sha256', salt).update(composite).digest('hex');
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
      process.env.SUPABASE_SERVICE_KEY
    );

    // ── 1. Validate state ────────────────────────────────────────────
    const { data: sessions, error: fetchErr } = await supabase
      .from('pending_sessions')
      .select('province, code_verifier')
      .eq('state', state)
      .limit(1);

    if (fetchErr || !sessions?.length)
      return res.status(400).json({ error: 'Invalid or expired session. Please start over.' });

    const { province, code_verifier } = sessions[0];
    await supabase.from('pending_sessions').delete().eq('state', state);

    const host        = req.headers['x-forwarded-host'] ?? req.headers.host ?? 'localhost:3000';
    const proto       = req.headers['x-forwarded-proto'] ?? 'https';
    const redirectUri = `${proto}://${host}/callback`;

    // ── 2. client_assertion for token endpoint ───────────────────────
    const pem        = loadPrivateKeyPem();
    const privateKey = await importPKCS8(pem, 'RS256');
    const now        = Math.floor(Date.now() / 1000);

    const clientAssertion = await new SignJWT({
      iss: CLIENT_ID, sub: CLIENT_ID,
      aud: TOKEN_ENDPOINT,
      exp: now + 300, iat: now,
      jti: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: 'RS256', kid: KID })
      .sign(privateKey);

    // ── 3. Exchange code → access token ─────────────────────────────
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
        code_verifier,
      }).toString(),
    });

    if (!tokenRes.ok) {
      const err = await tokenRes.text();
      console.error('[exchange] Token error:', err);
      return res.status(502).json({ error: 'Token exchange failed', detail: err });
    }

    const { access_token } = await tokenRes.json();

    // ── 4. Fetch verified identity claims ────────────────────────────
    const userinfoRes = await fetch(USERINFO_ENDPOINT, {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    if (!userinfoRes.ok) {
      const err = await userinfoRes.text();
      console.error('[exchange] Userinfo error:', err);
      return res.status(502).json({ error: 'Identity fetch failed', detail: err });
    }

    const claims = await userinfoRes.json();
    const { sub, given_name, family_name, birthdate, doc_type, scan_result } = claims;

    if (!sub)
      return res.status(400).json({ error: 'No identity returned from Interac' });

    // ── 5. Validate document scan quality (IDVS only) ────────────────
    // If doc_type is present, this was a document scan (IDVS).
    // Reject anything other than CLEAR — suspected/rejected docs don't count.
    if (doc_type && scan_result && scan_result !== 'CLEAR') {
      return res.status(400).json({
        error: 'document_not_verified',
        message: `Your document scan was ${scan_result}. Please try again with a clear, valid government ID.`,
      });
    }

    // ── 6. Determine verification method for audit trail ────────────
    const verificationMethod = doc_type ? 'IDVS' : 'IVS';

    // ── 7. Build both deduplication hashes ──────────────────────────
    const voterHashSub = hashSub(sub);

    // Identity hash requires name + birthdate. Both IVS and IDVS return these.
    // If missing (unusual edge case), fall back to sub-only deduplication.
    const hasIdentityFields = given_name && family_name && birthdate;
    const voterHashIdentity = hasIdentityFields
      ? hashIdentity(given_name, family_name, birthdate)
      : null;

    // ── 8. Check voter_hash (sub) for duplicates ─────────────────────
    const { data: existingSub } = await supabase
      .from('signatures')
      .select('id')
      .eq('voter_hash', voterHashSub)
      .limit(1);

    if (existingSub?.length)
      return res.status(409).json({
        error: 'already_voted',
        message: 'You have already signed this petition.',
      });

    // ── 9. Check voter_hash_identity (name+DOB) for cross-method dupes
    if (voterHashIdentity) {
      const { data: existingIdentity } = await supabase
        .from('signatures')
        .select('id')
        .eq('voter_hash_identity', voterHashIdentity)
        .limit(1);

      if (existingIdentity?.length)
        return res.status(409).json({
          error: 'already_voted',
          message: 'Your identity has already been used to sign this petition.',
        });
    }

    // ── 10. Insert — both unique constraints enforce atomically ──────
    const { error: insertError } = await supabase
      .from('signatures')
      .insert({
        voter_hash:          voterHashSub,
        voter_hash_identity: voterHashIdentity,
        verification_method: verificationMethod,
        province,
      });

    if (insertError) {
      // 23505 = unique_violation — race condition caught at DB level
      if (insertError.code === '23505')
        return res.status(409).json({
          error: 'already_voted',
          message: 'Your identity has already been used to sign this petition.',
        });
      console.error('[exchange] Insert error:', insertError);
      return res.status(500).json({ error: 'Could not record vote' });
    }

    return res.status(200).json({ success: true, province, method: verificationMethod });

  } catch (err) {
    console.error('[interac-exchange]', err);
    return res.status(500).json({ error: 'Internal server error', detail: err.message });
  }
}
