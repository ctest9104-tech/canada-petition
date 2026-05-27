import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { province } = req.body ?? {};
  if (!province) {
    return res.status(400).json({ error: 'Province is required' });
  }

  const validProvinces = [
    'Alberta','British Columbia','Manitoba','New Brunswick',
    'Newfoundland and Labrador','Nova Scotia','Ontario',
    'Prince Edward Island','Quebec','Saskatchewan',
    'Northwest Territories','Nunavut','Yukon'
  ];
  if (!validProvinces.includes(province)) {
    return res.status(400).json({ error: 'Invalid province' });
  }

  // Build a device fingerprint token from IP + User-Agent.
  // NOTE: In production replace this with a real Stripe Identity
  // or Interac Verified token for genuine one-person-one-vote enforcement.
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    ?? req.socket?.remoteAddress
    ?? 'unknown';
  const ua = req.headers['user-agent'] ?? '';
  const raw = `${ip}::${ua}`;
  const token = crypto.createHash('sha256').update(raw).digest('hex');

  const { error } = await supabase
    .from('signatures')
    .insert({ verification_token: token, province });

  if (error?.code === '23505') {
    return res.status(409).json({ error: 'Already signed from this device' });
  }
  if (error) {
    console.error('DB error:', error);
    return res.status(500).json({ error: 'Database error' });
  }

  return res.status(200).json({ success: true });
}
