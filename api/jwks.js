import crypto from 'crypto';

const KID = 'petition-rp-2026';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  try {
    const b64 = process.env.INTERAC_PRIVATE_KEY_B64;
    if (!b64) return res.status(500).json({ error: 'INTERAC_PRIVATE_KEY_B64 not set' });

    const pem = Buffer.from(b64, 'base64').toString('utf8');

    // Derive the public key directly from the private key — always in sync
    const privateKeyObj = crypto.createPrivateKey(pem);
    const publicKeyObj  = crypto.createPublicKey(privateKeyObj);
    const jwk           = publicKeyObj.export({ format: 'jwk' });

    res.setHeader('Cache-Control', 'public, max-age=3600');
    return res.status(200).json({
      keys: [{
        kty: jwk.kty,
        use: 'sig',
        alg: 'RS256',
        kid: KID,
        n:   jwk.n,
        e:   jwk.e,
      }],
    });
  } catch (err) {
    console.error('[jwks] Error:', err);
    return res.status(500).json({ error: err.message });
  }
}
