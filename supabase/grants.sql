-- ════════════════════════════════════════════════════════════════════════════
-- Security Advisory Proxy — one-time Supabase privileges
-- Run in: Supabase dashboard → SQL Editor → New query → paste → Run
--
-- BEFORE RUNNING: confirm the backend uses the service_role (secret) key.
--   GET /db-health (with your access code) → stats.supabase_key_role must say
--   "service_role". If it says "anon", STOP — switch SUPABASE_KEY on Render to the
--   secret/service_role key first, or this script will lock the backend out.
--
-- What it does:
--   1. Gives service_role (the backend) explicit access to every public table,
--      sequence and function — needed once Supabase stops granting it implicitly.
--   2. Removes anon / authenticated access. The dashboard never talks to Supabase
--      directly, so nothing legitimate uses those roles. Replaces the old
--      /apply-grants endpoint, which granted anon full read/write/delete.
--   3. Locks exec_sql (runs arbitrary SQL) to service_role only.
-- Safe to run more than once.
-- ════════════════════════════════════════════════════════════════════════════

BEGIN;

-- 1. Backend role: explicit access to current and future objects
GRANT USAGE ON SCHEMA public TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO service_role;
GRANT USAGE, SELECT                  ON ALL SEQUENCES IN SCHEMA public TO service_role;
GRANT EXECUTE                        ON ALL FUNCTIONS IN SCHEMA public TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES    TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT                  ON SEQUENCES TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE                        ON FUNCTIONS TO service_role;

-- 2. Public API roles: no table access
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES    FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon, authenticated;

-- 3. exec_sql runs arbitrary SQL — service_role only (any overload, if it exists)
DO $$
DECLARE f regprocedure;
BEGIN
  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'public' AND p.proname = 'exec_sql'
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon, authenticated', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', f);
  END LOOP;
END $$;

COMMIT;

-- ── Verification (results appear below the editor) ──────────────────────────
-- Expect: one row per table with service_role_can_write = true and anon_can_read = false
SELECT c.relname                                              AS table_name,
       has_table_privilege('service_role', c.oid, 'INSERT')   AS service_role_can_write,
       has_table_privilege('anon',         c.oid, 'SELECT')   AS anon_can_read
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r','p')
ORDER BY 1;
