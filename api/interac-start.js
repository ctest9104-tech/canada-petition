import { createClient } from '@supabase/supabase-js';
import { SignJWT, importPKCS8 } from 'jose';
import crypto from 'crypto';

const INTERAC_ISSUER   = 'https://gateway-portal.hub-verify.innovation.interac.ca';
const INTERAC_AUTH_URL = `${INTERAC_ISSUER}/auth`;
const CLIENT_ID        = '12011230-9c6c-42e3-9834-1bf2d8ee2a91';
const KID              = 'petition-rp-2026';

// general_scope = Interac shows the user a choice: bank (IVS) OR document scan (IDVS)
// This single scope handles both methods — no separate buttons needed on your site
const SCOPE = 'openid general_scope';

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function generateCodeVerifier()          { return base64url(crypto.randomBytes(48)); }
function generateCodeChallenge(verifier) { return base64url(crypto.createHash('sha256').update(verifier).digest()); }

function loadPrivateKeyPem() {
  const b64 = process.env.INTERAC_PRIVATE_KEY_B64;
  if (!b64) throw new Error('INTERAC_PRIVATE_KEY_B64 env var not set');
  return Buffer.from(b64, 'base64').toString('utf8');
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  try {
    if (req.method !== 'GET')
      return res.status(405).json({ error: 'Method not allowed' });

    const { province } = req.query;
    const validProvinces = [
      'Alberta','British Columbia','Manitoba','New Brunswick',
      'Newfoundland and Labrador','Nova Scotia','Ontario',
      'Prince Edward Island','Quebec','Saskatchewan',
      'Northwest Territories','Nunavut','Yukon',
    ];
    if (!province || !validProvinces.includes(province))
      return res.status(400).json({ error: 'Valid province required' });

    const host        = req.headers['x-forwarded-host'] ?? req.headers.host ?? 'localhost:3000';
    const proto       = req.headers['x-forwarded-proto'] ?? 'https';
    const baseUrl     = `${proto}://${host}`;
    const redirectUri = `${baseUrl}/callback`;

    const codeVerifier  = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const state = base64url(crypto.randomBytes(32));
    const nonce = base64url(crypto.randomBytes(32));

    const pem        = loadPrivateKeyPem();
    const privateKey = await importPKCS8(pem, 'RS256');
    const now        = Math.floor(Date.now() / 1000);

    const requestJwt = await new SignJWT({
      iss:                   CLIENT_ID,
      aud:                   `${INTERAC_ISSUER}/`,
      client_id:             CLIENT_ID,
      scope:                 SCOPE,
      response_type:         'code',
      redirect_uri:          redirectUri,
      state,
      nonce,
      code_challenge:        codeChallenge,
      code_challenge_method: 'S256',
      ui_locales:            'en-CA',
      exp:                   now + 300,
    })
      .setProtectedHeader({ alg: 'RS256', kid: KID })
      .sign(privateKey);

    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY
    );

    await supabase
      .from('pending_sessions')
      .delete()
      .lt('created_at', new Date(Date.now() - 10 * 60 * 1000).toISOString());

    const { error: sessionError } = await supabase
      .from('pending_sessions')
      .insert({ state, province, code_verifier: codeVerifier, nonce });

    if (sessionError)
      return res.status(500).json({ error: 'Could not create session' });

    const params = new URLSearchParams({
      request:       requestJwt,
      response_type: 'code',
      client_id:     CLIENT_ID,
      scope:         SCOPE,
      state,
      redirect_uri:  redirectUri,
    });

    return res.status(200).json({ authUrl: `${INTERAC_AUTH_URL}?${params}`, state });

  } catch (err) {
    console.error('[interac-start]', err);
    return res.status(500).json({ error: 'Internal server error', detail: err.message });
  }
}
