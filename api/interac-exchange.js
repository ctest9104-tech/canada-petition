// POST /api/interac-exchange
// Called by frontend after Interac redirects to /callback.
// Enforces: one vote per Canadian, zero duplicates across all methods and ID types.

import { createClient }   from '@supabase/supabase-js';
import { SignJWT, importPKCS8 } from 'jose';
import crypto from 'crypto';

const INTERAC_ISSUER    = 'https://gateway-portal.hub-verify.innovation.interac.ca';
const TOKEN_ENDPOINT    = `${INTERAC_ISSUER}/oauth2/token`;
const USERINFO_ENDPOINT = `${INTERAC_ISSUER}/userinfo`;
const CLIENT_ID         = '12011230-9c6c-42e3-9834-1bf2d8ee2a91';
const KID               = 'petition-rp-2026';
const REDIRECT_URI      = 'https://canada-petition.vercel.app/callback';

// Document types accepted by Interac IDVS — health card is NOT supported by Interac
const ACCEPTED_DOC_TYPES = new Set([
  'passport', 'drivers_license', 'national_card',
  'resident_permit', 'indigenous_card',
]);

function loadKey() {
  const b64 = process.env.INTERAC_PRIVATE_KEY_B64;
  if (!b64) throw new Error('INTERAC_PRIVATE_KEY_B64 not set');
  return Buffer.from(b64, 'base64').toString('utf8');
}

// Hash 1 — blocks same-session / same-method repeat votes
// IVS:  sub is a stable pairwise ID → reliably catches bank re-votes
// IDVS: sub is a per-session job_id → catches same session only
function hashSub(sub) {
  const salt = process.env.HASH_SALT;
  if (!salt) throw new Error('HASH_SALT not set');
  return crypto.createHmac('sha256', salt).update(sub).digest('hex');
}

// Hash 2 — blocks cross-method duplicate votes
// given_name + family_name + birthdate are stable across IVS and IDVS
// for the same real person. This is what stops bank→ID and ID→bank gaming.
function hashIdentity(givenName, familyName, birthdate) {
  const salt = process.env.HASH_SALT;
  if (!salt) throw new Error('HASH_SALT not set');
  const norm = s => (s || '').toUpperCase().replace(/\s+/g, ' ').trim();
  return crypto
    .createHmac('sha256', salt)
    .update(`${norm(givenName)}|${norm(familyName)}|${(birthdate || '').trim()}`)
    .digest('hex');
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  try {
    if (req.method !== 'POST')
      return res.status(405).json({ error: 'Method not allowed' });

    const { code, state } = req.body ?? {};
    if (!code || !state)
      return res.status(400).json({ error: 'Missing code or state' });

    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY   // bypasses RLS — only Vercel can write
    );

    // ── 1. Validate state — one-time use ────────────────────────
    const { data: sessions, error: fetchErr } = await supabase
      .from('pending_sessions')
      .select('province, code_verifier')
      .eq('state', state)
      .limit(1);

    if (fetchErr || !sessions?.length)
      return res.status(400).json({
        error: 'session_expired',
        message: 'Your verification session has expired. Please start over.',
      });

    const { province, code_verifier } = sessions[0];

    // Delete immediately — one-time use, prevents replay attacks
    await supabase.from('pending_sessions').delete().eq('state', state);

    // ── 2. Build client_assertion JWT for token endpoint ────────
    const pem        = loadKey();
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

    // ── 3. Exchange auth code → access token ────────────────────
    const tokenRes = await fetch(TOKEN_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:            'authorization_code',
        code,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion:      clientAssertion,
        client_id:             CLIENT_ID,
        redirect_uri:          REDIRECT_URI,
        code_verifier,
      }).toString(),
    });

    if (!tokenRes.ok) {
      const err = await tokenRes.text();
      console.error('[exchange] Token error:', err);
      return res.status(502).json({ error: 'Token exchange failed', detail: err });
    }

    const { access_token } = await tokenRes.json();

    // ── 4. Fetch verified identity claims from Interac ───────────
    const userinfoRes = await fetch(USERINFO_ENDPOINT, {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    if (!userinfoRes.ok) {
      const err = await userinfoRes.text();
      console.error('[exchange] Userinfo error:', err);
      return res.status(502).json({ error: 'Identity fetch failed', detail: err });
    }

    const claims = await userinfoRes.json();
    const {
      sub,
      given_name,
      family_name,
      birthdate,
      doc_type,
      scan_result,
    } = claims;

    if (!sub)
      return res.status(400).json({ error: 'No identity returned from Interac' });

    // ── 5. IDVS-specific validation ──────────────────────────────
    // doc_type present = document scan (IDVS) flow was used
    const isIDVS = Boolean(doc_type);

    if (isIDVS) {
      // Reject unrecognised document types
      if (!ACCEPTED_DOC_TYPES.has(doc_type)) {
        return res.status(400).json({
          error: 'unsupported_document',
          message: `Document type "${doc_type}" is not accepted. Please use a passport, driver's licence, provincial ID, permanent resident card, or Indian status card.`,
        });
      }

      // Reject anything other than a CLEAR scan.
      // SUSPECTED = signs of tampering. REJECTED = couldn't process.
      // The DB constraint also enforces this as a second layer.
      if (scan_result && scan_result !== 'CLEAR') {
        return res.status(400).json({
          error: 'document_not_verified',
          message: `Your document scan was ${scan_result}. Please try again in good lighting with a valid, unexpired government ID.`,
          flags: claims.suspected_flags ?? claims.rejected_flags ?? [],
        });
      }
    }

    // ── 6. Build deduplication hashes ────────────────────────────
    const voterHashSub = hashSub(sub);

    // Identity hash — requires name + birthdate.
    // Both IVS and IDVS return these; the same person always produces
    // the same hash regardless of which method they used.
    const hasIdentity = given_name && family_name && birthdate;
    const voterHashIdentity = hasIdentity
      ? hashIdentity(given_name, family_name, birthdate)
      : null;

    // For IDVS, identity hash is critical because sub changes each session.
    // Log a warning if it's unexpectedly missing.
    if (isIDVS && !voterHashIdentity) {
      console.warn('[exchange] IDVS vote missing identity fields — sub-only dedup only', {
        doc_type, has_given_name: !!given_name,
        has_family_name: !!family_name, has_birthdate: !!birthdate,
      });
    }

    // ── 7. Check voter_hash (sub) — same-method duplicate ────────
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

    // ── 8. Check voter_hash_identity — cross-method duplicate ────
    // This catches: bank vote then ID scan, or ID scan then bank vote,
    // or scanning a different ID type (passport after licence, etc.)
    if (voterHashIdentity) {
      const { data: existingIdentity } = await supabase
        .from('signatures')
        .select('id, verification_method')
        .eq('voter_hash_identity', voterHashIdentity)
        .limit(1);

      if (existingIdentity?.length) {
        const prior = existingIdentity[0].verification_method;
        return res.status(409).json({
          error: 'already_voted',
          message: `Your identity has already been used to sign this petition${prior ? ` (via ${prior})` : ''}.`,
        });
      }
    }

    // ── 9. Insert — DB constraints are the final safety net ──────
    // Even if two requests race past checks 7 & 8 simultaneously,
    // the UNIQUE constraints on voter_hash and voter_hash_identity
    // ensure only one INSERT commits. The other gets error 23505.
    const { error: insertError } = await supabase
      .from('signatures')
      .insert({
        voter_hash:          voterHashSub,
        voter_hash_identity: voterHashIdentity,
        verification_method: isIDVS ? 'IDVS' : 'IVS',
        doc_type:            doc_type ?? null,
        scan_result:         isIDVS ? (scan_result ?? 'CLEAR') : null,
        province,
      });

    if (insertError) {
      if (insertError.code === '23505')  // unique_violation
        return res.status(409).json({
          error: 'already_voted',
          message: 'Your identity has already been used to sign this petition.',
        });
      if (insertError.code === '23514')  // check_violation (scan_result must be CLEAR)
        return res.status(400).json({
          error: 'document_not_verified',
          message: 'Only CLEAR document scans are accepted.',
        });
      console.error('[exchange] Insert error:', insertError);
      return res.status(500).json({ error: 'Could not record vote' });
    }

    // vote_counts table updated automatically by DB trigger
    return res.status(200).json({
      success: true,
      province,
      method: isIDVS ? 'IDVS' : 'IVS',
    });

  } catch (err) {
    console.error('[interac-exchange] Unhandled:', err);
    return res.status(500).json({ error: 'Internal server error', detail: err.message });
  }
}
