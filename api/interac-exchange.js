// POST /api/interac-exchange
// Called by frontend after Interac redirects to /callback.
// Enforces one vote per Canadian across every verification path:
//   - same Interac sub (same-method replay)
//   - same legal identity (name + birthdate) across IVS and IDVS
//   - same identity under name-normalisation drift (middle names, accents,
//     hyphens, apostrophes) via a looser strict-form hash
//   - same physical document re-scanned in a new IDVS session
// All four checks plus the insert run inside the record_signature RPC so
// there is no TOCTOU window between SELECT and INSERT.

import { createClient }   from '@supabase/supabase-js';
import { SignJWT, importPKCS8 } from 'jose';
import crypto from 'crypto';

const INTERAC_ISSUER    = 'https://gateway-portal.hub-verify.innovation.interac.ca';
const TOKEN_ENDPOINT    = `${INTERAC_ISSUER}/oauth2/token`;
const USERINFO_ENDPOINT = `${INTERAC_ISSUER}/userinfo`;
const CLIENT_ID         = '12011230-9c6c-42e3-9834-1bf2d8ee2a91';
const KID               = 'petition-rp-2026';
const REDIRECT_URI      = 'https://canada-petition.vercel.app/callback';

const ACCEPTED_DOC_TYPES = new Set([
  'passport', 'drivers_license', 'national_card',
  'resident_permit', 'indigenous_card',
]);

function loadKey() {
  const b64 = process.env.INTERAC_PRIVATE_KEY_B64;
  if (!b64) throw new Error('INTERAC_PRIVATE_KEY_B64 not set');
  return Buffer.from(b64, 'base64').toString('utf8');
}

function hmac(value) {
  const salt = process.env.HASH_SALT;
  if (!salt) throw new Error('HASH_SALT not set');
  return crypto.createHmac('sha256', salt).update(value).digest('hex');
}

// Aggressive name normalisation. Survives:
//   - accents and diacritics (ZoÃ© â†’ ZOE)
//   - hyphens, apostrophes, spaces (St-Pierre, O'Brien â†’ STPIERRE, OBRIEN)
//   - case and trailing whitespace
function normaliseName(s) {
  return (s ?? '')
    .normalize('NFD')
    .replace(/[Ì€-Í¯]/g, '')
    .replace(/[^A-Za-z0-9]/g, '')
    .toUpperCase();
}

// Birthdate from Interac is ISO 8601 (YYYY-MM-DD). Trim only.
function normaliseBirthdate(s) {
  return (s ?? '').trim();
}

// Document number: strip whitespace and punctuation, uppercase.
// Catches whitespace/hyphen differences between scans of the same ID.
function normaliseDocNumber(s) {
  return (s ?? '').replace(/[^A-Za-z0-9]/g, '').toUpperCase();
}

// Strict-form identity hash. Designed so the same person produces the
// same hash even when their IDs disagree on middle names, accents, etc.
//   familyName (fully normalised) | birthdate | first letter of given name
// First letter is enough to disambiguate siblings sharing a birthdate
// without being fooled by middle-name presence/absence.
function buildIdentityHashes(givenName, familyName, birthdate) {
  const g  = normaliseName(givenName);
  const f  = normaliseName(familyName);
  const bd = normaliseBirthdate(birthdate);

  if (!g || !f || !bd) return { strictExact: null, strictLoose: null };

  const strictExact = hmac(`${g}|${f}|${bd}`);
  const strictLoose = hmac(`${f}|${bd}|${g.charAt(0)}`);
  return { strictExact, strictLoose };
}

// Interac userinfo can expose the document number under several names
// depending on the doc type. Try all of them.
function extractDocNumber(claims) {
  return (
    claims.document_number ||
    claims.doc_number       ||
    claims.id_number        ||
    claims.passport_number  ||
    claims.licence_number   ||
    claims.license_number   ||
    null
  );
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
      process.env.SUPABASE_SERVICE_KEY
    );

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
    await supabase.from('pending_sessions').delete().eq('state', state);

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

    const isIDVS = Boolean(doc_type);

    if (isIDVS) {
      if (!ACCEPTED_DOC_TYPES.has(doc_type)) {
        return res.status(400).json({
          error: 'unsupported_document',
          message: `Document type "${doc_type}" is not accepted. Please use a passport, driver's licence, provincial ID, permanent resident card, or Indian status card.`,
        });
      }
      if (scan_result && scan_result !== 'CLEAR') {
        return res.status(400).json({
          error: 'document_not_verified',
          message: `Your document scan was ${scan_result}. Please try again in good lighting with a valid, unexpired government ID.`,
          flags: claims.suspected_flags ?? claims.rejected_flags ?? [],
        });
      }
    }

    const voterHashSub = hmac(sub);
    const { strictExact, strictLoose } =
      buildIdentityHashes(given_name, family_name, birthdate);

    const docNumber = isIDVS ? extractDocNumber(claims) : null;
    const voterHashDoc = (isIDVS && docNumber)
      ? hmac(`${doc_type}|${normaliseDocNumber(docNumber)}`)
      : null;

    if (isIDVS && !strictExact) {
      console.warn('[exchange] IDVS vote missing identity fields â€” degraded dedup', {
        doc_type,
        has_given_name: !!given_name,
        has_family_name: !!family_name,
        has_birthdate:  !!birthdate,
      });
    }

    const { data: rpcRows, error: rpcErr } = await supabase
      .rpc('record_signature', {
        p_voter_hash:                 voterHashSub,
        p_voter_hash_identity:        strictExact,
        p_voter_hash_identity_strict: strictLoose,
        p_voter_hash_doc:             voterHashDoc,
        p_verification_method:        isIDVS ? 'IDVS' : 'IVS',
        p_doc_type:                   doc_type ?? null,
        p_scan_result:                isIDVS ? (scan_result ?? 'CLEAR') : null,
        p_province:                   province,
      });

    if (rpcErr) {
      console.error('[exchange] RPC error:', rpcErr);
      return res.status(500).json({ error: 'Could not record vote' });
    }

    const result = Array.isArray(rpcRows) ? rpcRows[0] : rpcRows;

    if (result?.status === 'duplicate') {
      const prior = result.duplicate_of && result.duplicate_of !== 'unknown'
        ? ` (via ${result.duplicate_of})`
        : '';
      return res.status(409).json({
        error: 'already_voted',
        message: `Your identity has already been used to sign this petition${prior}.`,
      });
    }

    if (result?.status === 'invalid_scan') {
      return res.status(400).json({
        error: 'document_not_verified',
        message: 'Only CLEAR document scans are accepted.',
      });
    }

    if (result?.status !== 'ok') {
      console.error('[exchange] Unexpected RPC status:', result);
      return res.status(500).json({ error: 'Could not record vote' });
    }

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
