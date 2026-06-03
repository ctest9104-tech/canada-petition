// GET /api/audit
// Returns a tamper-evident summary for government verification.
// Calls the SECURITY DEFINER function in Postgres (service role not needed).

import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  try {
    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY   // read-only anon key is enough here
    );

    const { data, error } = await supabase.rpc('get_audit_summary');
    if (error) return res.status(500).json({ error: error.message });

    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Access-Control-Allow-Origin', '*');
    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
