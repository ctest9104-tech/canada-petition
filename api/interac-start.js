// GET /api/interac-start?province=Ontario
// Initiates the Interac Hub OIDC authorization code flow.

import { createClient } from '@supabase/supabase-js';
import { SignJWT, importPKCS8 } from 'jose';
import crypto from 'crypto';

const INTERAC_ISSUER   = 'https://gateway-portal.hub-verify.innovation.interac.ca';
const INTERAC_AUTH_URL = `${INTERAC_ISSUER}/auth`;
const CLIENT_ID        = '12011230-9c6c-42e3-9834-1bf2d8ee2a91';
const SCOPE            = 'openid general_scope';
const KID              = 'petition-rp-2026';
const REDIRECT_URI     = 'https://canada-petition.vercel.app/callback';

const VALID_PROVINCES = [
  'Alberta','British Columbia','Manitoba','New Brunswick',
  'Newfoundland and Labrador','Nova Scotia','Ontario',
  'Prince Edward Island','Quebec','Saskatchewan',
  'Northwest Territories','Nunavut','Yukon',
];

function b64url(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');

  try {
    if (req.method !== 'GET')
      return res.status(405).json({ error: 'Method not allowed' });

    const { province } = req.query;
    if (!province || !VALID_PROVINCES.includes(province))
      return res.status(400).json({ error: 'Valid province required' });

    // Load private key from base64-encoded env var
    const rawB64 = process.env.INTERAC_PRIVATE_KEY_B64;
    if (!rawB64)
      return res.status(500).json({ error: 'INTERAC_PRIVATE_KEY_B64 not set' });

    const pem        = Buffer.from(rawB64, 'base64').toString('utf8');
    const privateKey = await importPKCS8(pem, 'RS256');

    // PKCE
    const codeVerifier  = b64url(crypto.randomBytes(48));
    const codeChallenge = b64url(
      crypto.createHash('sha256').update(codeVerifier).digest()
    );
    const state = b64url(crypto.randomBytes(32));
    const nonce = b64url(crypto.randomBytes(32));

    // Build signed request JWT — matches Interac spec exactly:
    // ui_locale (no s), no exp field, setIssuedAt() only
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
      ui_locale:             'en-CA',   // ← no 's' — matches Interac spec
    })
      .setProtectedHeader({ alg: 'RS256', kid: KID })
      .setIssuedAt()                    // ← iat only, no exp
      .sign(privateKey);

    // Persist PKCE session
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY
    );

    await supabase
      .from('pending_sessions')
      .delete()
      .lt('created_at', new Date(Date.now() - 10 * 60 * 1000).toISOString());

    const { error: sessionErr } = await supabase
      .from('pending_sessions')
      .insert({ state, province, code_verifier: codeVerifier, nonce });

    if (sessionErr) {
      console.error('[interac-start] session insert:', sessionErr);
      return res.status(500).json({ error: 'Could not create session' });
    }

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
    console.error('[interac-start] error:', err);
    return res.status(500).json({ error: 'Internal server error', detail: err.message });
  }
}
