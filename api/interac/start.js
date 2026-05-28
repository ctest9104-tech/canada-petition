// GET /api/interac/start?province=Ontario
// Initiates the Interac Hub OIDC authorization code flow.
// Builds a signed JWT request object (as required by Interac Hub docs),
// stores the PKCE code_verifier + state in Supabase, and returns the redirect URL.

import { createClient } from '@supabase/supabase-js';
import { SignJWT, importPKCS8 } from 'jose';
import crypto from 'crypto';

const INTERAC_ISSUER    = 'https://gateway-portal.hub-verify.innovation.interac.ca';
const INTERAC_AUTH_URL  = `${INTERAC_ISSUER}/auth`;
const CLIENT_ID         = '12011230-9c6c-42e3-9834-1bf2d8ee2a91';
const SCOPE             = 'openid general_scope';
const KID               = 'petition-rp-2026';

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function generateCodeVerifier() {
  return base64url(crypto.randomBytes(48));
}

function generateCodeChallenge(verifier) {
  return base64url(crypto.createHash('sha256').update(verifier).digest());
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { province } = req.query;
  const validProvinces = [
    'Alberta','British Columbia','Manitoba','New Brunswick',
    'Newfoundland and Labrador','Nova Scotia','Ontario',
    'Prince Edward Island','Quebec','Saskatchewan',
    'Northwest Territories','Nunavut','Yukon'
  ];
  if (!province || !validProvinces.includes(province)) {
    return res.status(400).json({ error: 'Valid province required' });
  }

  // Derive our public-facing URL for the redirect_uri
  const host = req.headers['x-forwarded-host'] ?? req.headers.host ?? 'localhost:3000';
  const proto = req.headers['x-forwarded-proto'] ?? 'https';
  const baseUrl = `${proto}://${host}`;
  const redirectUri = `${baseUrl}/callback`;
  const jwksUri = `${baseUrl}/api/jwks`;

  // PKCE
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  // State + nonce
  const state = base64url(crypto.randomBytes(32));
  const nonce = base64url(crypto.randomBytes(32));

  // Load private key from env
  const privatePem = (process.env.INTERAC_PRIVATE_KEY ?? '').replace(/\\n/g, '\n');
  if (!privatePem) {
    return res.status(500).json({ error: 'INTERAC_PRIVATE_KEY env var not set' });
  }
  const privateKey = await importPKCS8(privatePem, 'RS256');

  // Build the signed request object JWT (required by Interac Hub)
  const now = Math.floor(Date.now() / 1000);
  const requestJwt = await new SignJWT({
    iss: CLIENT_ID,
    aud: `${INTERAC_ISSUER}/`,
    client_id: CLIENT_ID,
    scope: SCOPE,
    response_type: 'code',
    redirect_uri: redirectUri,
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    ui_locale: 'en-CA',
    exp: now + 300,
  })
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .sign(privateKey);

  // Persist session so we can verify state + use code_verifier at callback
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
  );

  // Clean up expired sessions (>10 min old) opportunistically
  await supabase
    .from('pending_sessions')
    .delete()
    .lt('created_at', new Date(Date.now() - 10 * 60 * 1000).toISOString());

  const { error: sessionError } = await supabase
    .from('pending_sessions')
    .insert({ state, province, code_verifier: codeVerifier, nonce });

  if (sessionError) {
    console.error('Session insert error:', sessionError);
    return res.status(500).json({ error: 'Could not create session' });
  }

  // Build the full authorization URL
  const params = new URLSearchParams({
    request: requestJwt,
    response_type: 'code',
    client_id: CLIENT_ID,
    scope: SCOPE,
    state,
    redirect_uri: redirectUri,
  });

  const authUrl = `${INTERAC_AUTH_URL}?${params.toString()}`;

  return res.status(200).json({ authUrl, state });
}
