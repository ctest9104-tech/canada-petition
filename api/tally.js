import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { count, error } = await supabase
    .from('signatures')
    .select('*', { count: 'exact', head: true });

  if (error) {
    return res.status(500).json({ error: 'Database error' });
  }

  // Province breakdown
  const { data: rows } = await supabase
    .from('signatures')
    .select('province');

  const byProvince = {};
  (rows ?? []).forEach(r => {
    byProvince[r.province] = (byProvince[r.province] ?? 0) + 1;
  });

  return res.status(200).json({ total: count ?? 0, byProvince });
}
