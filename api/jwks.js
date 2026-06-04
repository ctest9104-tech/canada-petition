// GET /api/jwks
// Serves our RSA public key so Interac Hub can verify our signed JWTs.
// This key MUST match the INTERAC_PRIVATE_KEY environment variable in Vercel.
// Key pair generated: 2026-06-04

export default function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.setHeader('Access-Control-Allow-Origin', '*');

  return res.status(200).json({
    keys: [
      {
        kty: 'RSA',
        use: 'sig',
        alg: 'RS256',
        kid: 'petition-rp-2026',
        n: '1SgdJtogcpNZbRRKk-Z4vQulybZ3whEqS-cRHedxPDg5_5X63jLOOFDlc9cuvPU15euvCBdhOt-PlS4tM49Y09M14C0Do8WFcNAn09nuoU0A4ARRy_6Z9n0likVsFR9KoK34WK7jHOzxQJM0fDEYuSN7HOFzXRnRYgzJH-gqkIHyTPT07-dFflnT7CKqw3Ahrc16Qr9fMp7SMtqSnmYEqR1yZZITbaUHRGT9mMzSqzTgJLHW4lFfnyN2hAQToF0Wej6iQx9y4Tff1_DdXcgH7EZFXvpxUBa58mGcC0EJNCgfzEyqufAkalycZlKEP6g3FZD-_pw_JIcOOv0GCzL9wQ',
        e: 'AQAB'
      }
    ]
  });
}
