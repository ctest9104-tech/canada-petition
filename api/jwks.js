// GET /api/jwks
// Interac Hub fetches this to validate our signed request objects and client assertions.
// The public key values here MUST match the private key in INTERAC_PRIVATE_KEY env var.

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
        n: 'oBafeiLj41Cx5bIV4FKhwMj_CEACg8NKBvWsNFufG2vePbaDJHlJGEUjYgIG7uJcVQBRBhi1e2ZK1VBGG7Fmc1l3zNnME4ofl5Wuky8tTlMxWKj6Y1DvQvrYgCJ3Wz6yWrU7qh6RphGcEVHWPjW1JEwwvXd_BDocVYFkrGJXS7lB5UMoJ1ZLF4lDezYErWySyHGk3b-ITMICYy1GRTu4fLDrt4Z6CEjXcxfWsi0R-gGB2Ts6s3KxqRjCFuiwurE6GtbxEROue9NpwvuC2rnF-9ciqCF5vsDCep8ymU83qo1dDPFaPhJQNtRqlvCeKMrypUbyzNLoa6ACayVnAFay3w',
        e: 'AQAB'
      }
    ]
  });
}
