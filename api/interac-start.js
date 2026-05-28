// GET /api/interac/start?province=Ontario
import { createClient } from '@supabase/supabase-js';
import { SignJWT, importPKCS8 } from 'jose';
import crypto from 'crypto';

const INTERAC_ISSUER   = 'https://gateway-portal.hub-verify.innovation.interac.ca';
const INTERAC_AUTH_URL = `${INTERAC_ISSUER}/auth`;
const CLIENT_ID        = '12011230-9c6c-42e3-9834-1bf2d8ee2a91';
const SCOPE            = 'openid general_scope';
const KID              = 'petition-rp-2026';

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function generateCodeVerifier()         { return base64url(crypto.randomBytes(48)); }
function generateCodeChallenge(verifier){ return base64url(crypto.createHash('sha256').update(verifier).digest()); }

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');

  // ✅ Wrap everything so crashes always return JSON, never raw text
  try {
    if (req.method !== 'GET') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const { province } = req.query;
    const validProvinces = [
      'Alberta','British Columbia','Manitoba','New Brunswick',
      'Newfoundland and Labrador','Nova Scotia','Ontario',
      'Prince Edward Island','Quebec','Saskatchewan',
      'Northwest Territories','Nunavut','Yukon',
    ];
    if (!province || !validProvinces.includes(province)) {
      return res.status(400).json({ error: 'Valid province required' });
    }

    const host      = req.headers['x-forwarded-host'] ?? req.headers.host ?? 'localhost:3000';
    const proto     = req.headers['x-forwarded-proto'] ?? 'https';
    const baseUrl   = `${proto}://${host}`;
    const redirectUri = `${baseUrl}/callback`;
    const jwksUri     = `${baseUrl}/api/jwks`;

    const codeVerifier  = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const state = base64url(crypto.randomBytes(32));
    const nonce = base64url(crypto.randomBytes(32));

    // ✅ Normalize newlines AND trim whitespace that can sneak in from env editors
    const rawPem    = process.env.INTERAC_PRIVATE_KEY ?? '';
    const privatePem = rawPem.replace(/\\n/g, '\n').trim();

    if (!privatePem) {
      return res.status(500).json({ error: 'INTERAC_PRIVATE_KEY env var not set' });
    }

    // ✅ Detect PKCS#1 vs PKCS#8 and give a clear error instead of a cryptic crash
    if (privatePem.includes('BEGIN RSA PRIVATE KEY')) {
      return res.status(500).json({
        error: 'Private key is PKCS#1 (RSA PRIVATE KEY). Convert it to PKCS#8 format first: openssl pkcs8 -topk8 -nocrypt -in key.pem -out key_pkcs8.pem',
      });
    }

    // ✅ importPKCS8 is now inside try/catch — throws here = caught below
    const privateKey = await importPKCS8(privatePem, 'RS256');

    const now = Math.floor(Date.now() / 1000);
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
      ui_locale:             'en-CA',
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

    if (sessionError) {
      console.error('Session insert error:', sessionError);
      return res.status(500).json({ error: 'Could not create session' });
    }

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
    // ✅ Any unhandled throw (importPKCS8, SignJWT, network, etc.) lands here
    //    and returns JSON so the client never sees raw "A server error..." text
    console.error('[interac-start] Unhandled error:', err);
    return res.status(500).json({
      error: 'Internal server error',
      detail: err.message,  // visible in client for easier debugging; remove in prod
    });
  }
}
