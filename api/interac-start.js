// GET /api/interac-start?province=Ontario
// Initiates the Interac Hub OIDC authorization code flow.
// JWT request object structure matches exactly:
// https://documents.hub-verify.innovation.interac.ca/docs/32-authorization-request

import { createClient } from '@supabase/supabase-js';
import { SignJWT, importPKCS8 } from 'jose';
import crypto from 'crypto';

const INTERAC_ISSUER   = 'https://gateway-portal.hub-verify.innovation.interac.ca';
const INTERAC_AUTH_URL = `${INTERAC_ISSUER}/auth`;
const CLIENT_ID        = '12011230-9c6c-42e3-9834-1bf2d8ee2a91';
const SCOPE            = 'openid general_scope';
const KID              = 'petition-rp-2026';

// Hardcoded — must match exactly what is registered in the Interac developer portal
// Set SITE_URL in Vercel env vars to override (e.g. for a custom domain)
const REDIRECT_URI = process.env.SITE_URL
  ? `${process.env.SITE_URL}/callback`
  : 'https://canada-petition.vercel.app/callback';

const VALID_PROVINCES = [
  'Alberta','British Columbia','Manitoba','New Brunswick',
  'Newfoundland and Labrador','Nova Scotia','Ontario',
  'Prince Edward Island','Quebec','Saskatchewan',
  'Northwest Territories','Nunavut','Yukon'
];

function b64url(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Decode base64-encoded PEM (avoids all newline/escaping issues in env vars)
function loadPemFromB64(b64 = '') {
  return Buffer.from(b64.trim(), 'base64').toString('utf8');
}

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');

  try {
    if (req.method !== 'GET') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const { province } = req.query;
    if (!province || !VALID_PROVINCES.includes(province)) {
      return res.status(400).json({ error: 'Valid province required' });
    }

    if (!process.env.INTERAC_PRIVATE_KEY_B64) {
      return res.status(500).json({ error: 'INTERAC_PRIVATE_KEY_B64 env var not set in Vercel' });
    }
    if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
      return res.status(500).json({ error: 'Supabase env vars not set' });
    }

    // Decode base64 → PEM string
    const pem = loadPemFromB64(process.env.INTERAC_PRIVATE_KEY_B64);

    let privateKey;
    try {
      privateKey = await importPKCS8(pem, 'RS256');
    } catch (keyErr) {
      console.error('[interac-start] PEM parse failed:', keyErr.message);
      return res.status(500).json({
        error: 'Could not parse private key — check INTERAC_PRIVATE_KEY_B64 in Vercel env vars',
        detail: keyErr.message
      });
    }

    // PKCE
    const codeVerifier  = b64url(crypto.randomBytes(48));
    const codeChallenge = b64url(crypto.createHash('sha256').update(codeVerifier).digest());

    const state = b64url(crypto.randomBytes(32));
    const nonce = b64url(crypto.randomBytes(32));

    // Signed request object JWT — payload matches the Interac Hub spec exactly.
    // No exp field (not in spec), no extra claims.
    const requestJwt = await new SignJWT({
      iss:                   CLIENT_ID,
      aud:                   `${INTERAC_ISSUER}/`,
      client_id:             CLIENT_ID,
      scope:                 SCOPE,
      response_type:         'code',
      redirect_uri:          REDIRECT_URI,
      state,
      nonce,
      code_challenge:        codeChallenge,
      code_challenge_method: 'S256',
      ui_locale:             'en-CA',
    })
      .setProtectedHeader({ alg: 'RS256', kid: KID })
      .setIssuedAt()
      .sign(privateKey);

    // Persist PKCE session so we can verify state at /callback
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY
    );

    // Purge stale sessions opportunistically
    await supabase
      .from('pending_sessions')
      .delete()
      .lt('created_at', new Date(Date.now() - 10 * 60 * 1000).toISOString());

    const { error: sessionErr } = await supabase
      .from('pending_sessions')
      .insert({ state, province, code_verifier: codeVerifier, nonce });

    if (sessionErr) {
      console.error('[interac-start] Session insert error:', sessionErr);
      return res.status(500).json({
        error: 'Could not create verification session',
        detail: sessionErr.message
      });
    }

    // Build the authorization URL
    const params = new URLSearchParams({
      request:       requestJwt,
      response_type: 'code',
      client_id:     CLIENT_ID,
      scope:         SCOPE,
      state,
      redirect_uri:  REDIRECT_URI,
    });

    return res.status(200).json({ authUrl: `${INTERAC_AUTH_URL}?${params}` });

  } catch (err) {
    console.error('[interac-start] Unhandled error:', err);
    return res.status(500).json({ error: 'Internal server error', detail: err.message });
  }
}
