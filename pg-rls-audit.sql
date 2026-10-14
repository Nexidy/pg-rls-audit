-- pg-rls-audit.sql — a read-only audit of PostgreSQL row-level security and SECURITY DEFINER hygiene.
--
--   psql -X -d <database> -f pg-rls-audit.sql                        # roles treated as untrusted: anon,authenticated
--   psql -X -d <database> -v exposed_roles=web_anon,app_user -f pg-rls-audit.sql
--
-- It reads only the system catalogs (pg_class, pg_attribute, pg_policy, pg_proc, pg_rewrite, pg_depend) inside a
-- READ ONLY transaction: it cannot change a row, a policy or a setting. PostgreSQL 15+ (security_invoker views, regexp_count).
-- "Exposed" means PUBLIC or one of the exposed roles (Supabase's anon/authenticated by default) holds the privilege.

\if :{?exposed_roles}
\else
\set exposed_roles 'anon,authenticated'
\endif
\pset footer off
\set ON_ERROR_STOP on

BEGIN TRANSACTION READ ONLY;
SET LOCAL search_path = pg_catalog;

WITH RECURSIVE named AS (
    SELECT DISTINCT btrim(x) AS rolname FROM unnest(string_to_array(:'exposed_roles', ',')) x WHERE btrim(x) <> ''
), exposed AS (                                  -- the named roles AND every role whose privileges they inherit
    SELECT DISTINCT g.oid, g.rolname FROM named n JOIN pg_roles r ON r.rolname = n.rolname
    JOIN pg_roles g ON pg_has_role(r.oid, g.oid, 'USAGE')
), rel AS (
    SELECT c.oid, c.relkind, n.nspname, c.relname, c.relrowsecurity AS rls, c.relforcerowsecurity AS forced,
           coalesce(c.relacl, acldefault('r', c.relowner)) AS relacl, c.reloptions, o.rolsuper OR o.rolbypassrls AS owner_bypasses,
           c.relkind = 'v' AND EXISTS (SELECT 1 FROM unnest(c.reloptions) opt
                                       WHERE lower(opt) ~ '^security_invoker=(true|on|1|yes|y|t)$') AS invoker
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_roles o ON o.oid = c.relowner
    WHERE c.relkind IN ('r', 'p', 'v', 'm')
      AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_%'
), acl AS (                                      -- table-level ACLs, and column-level ones (GRANT SELECT (email) ...)
    SELECT r.oid, NULL::name AS col, r.relacl AS acl FROM rel r
    UNION ALL
    SELECT a.attrelid, a.attname, a.attacl FROM pg_attribute a JOIN rel r ON r.oid = a.attrelid
    WHERE a.attnum > 0 AND NOT a.attisdropped AND a.attacl IS NOT NULL
), grants AS (                                   -- table/view privileges held by PUBLIC or an exposed role, on the
    SELECT x.oid, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE e.rolname END AS who,   -- whole relation or some columns
           CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(e.rolname) END AS who_sql, a.privilege_type AS priv,
           a.privilege_type || CASE WHEN bool_or(x.col IS NULL) THEN ''          -- a table-level grant covers every column
               ELSE ' (' || string_agg(DISTINCT quote_ident(x.col), ', ') || ')' END AS priv_desc
    FROM acl x
    CROSS JOIN LATERAL aclexplode(x.acl) a
    LEFT JOIN exposed e ON e.oid = a.grantee
    WHERE a.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE') AND (a.grantee = 0 OR e.oid IS NOT NULL)
    GROUP BY x.oid, a.grantee, e.rolname, a.privilege_type
), pol AS (
    SELECT p.polrelid, p.polname, p.polpermissive,
           coalesce(pg_get_expr(p.polqual, p.polrelid), '') AS using_expr,
           coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') AS check_expr,
           0 = ANY (p.polroles) OR EXISTS (SELECT 1 FROM exposed e WHERE e.oid = ANY (p.polroles)) AS for_exposed
    FROM pg_policy p
), pol_cmd AS (                                  -- each PERMISSIVE policy, once per role and command it applies to
    SELECT p.polrelid, p.polname, CASE WHEN pr.oid = 0 THEN 'PUBLIC' ELSE coalesce(ro.rolname, pr.oid::text) END AS who, c.cmd
    FROM pg_policy p
    CROSS JOIN LATERAL unnest(p.polroles) pr(oid)
    LEFT JOIN pg_roles ro ON ro.oid = pr.oid
    CROSS JOIN LATERAL unnest(CASE p.polcmd WHEN 'r' THEN ARRAY['SELECT'] WHEN 'a' THEN ARRAY['INSERT']
                                            WHEN 'w' THEN ARRAY['UPDATE'] WHEN 'd' THEN ARRAY['DELETE']
                                            ELSE ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE'] END) c(cmd)   -- FOR ALL
    WHERE p.polpermissive
), overlap AS (                                  -- a role and a command that more than one permissive policy covers
    SELECT polrelid, who, cmd, string_agg(quote_ident(polname), ', ' ORDER BY polname) AS policies
    FROM pol_cmd GROUP BY polrelid, who, cmd HAVING count(*) > 1
), fn AS (
    SELECT p.oid, n.nspname, p.proname, pg_get_function_identity_arguments(p.oid) AS args, p.proconfig,
           p.proacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) a LEFT JOIN exposed e ON e.oid = a.grantee
                                       WHERE a.privilege_type = 'EXECUTE' AND (a.grantee = 0 OR e.oid IS NOT NULL))
               AS callable_by_exposed       -- a NULL acl means the default: EXECUTE granted to PUBLIC
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_%'
), dep AS (                                      -- a view or materialized view -> each relation its query reads
    SELECT DISTINCT rw.ev_class AS src, d.refobjid AS dst
    FROM pg_rewrite rw
    JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = rw.oid AND d.refclassid = 'pg_class'::regclass
    WHERE d.refobjid <> rw.ev_class
), reach AS (                                    -- followed through views stacked on views to any depth; path holds
    SELECT v.oid AS top, d.dst AS node, ARRAY[v.oid] AS path   -- the views walked so far, so a cycle stops
    FROM rel v JOIN dep d ON d.src = v.oid
    WHERE v.relkind IN ('v', 'm')
    UNION ALL
    SELECT r.top, d.dst, r.path || r.node
    FROM reach r JOIN rel n ON n.oid = r.node AND n.relkind IN ('v', 'm') JOIN dep d ON d.src = r.node
    WHERE d.dst <> ALL (r.path || r.node)
), view_on_table AS (                            -- every table a view reads, the chain it reads it through, and each
    SELECT r.top AS view_oid, t.rls,                                 -- owner-run view below the top one on that chain
           t.nspname = 'auth' AND t.relname = 'users' AS auth_users,      -- Supabase's table of every user
           NOT EXISTS (SELECT 1 FROM unnest(r.path) u(oid) JOIN rel m ON m.oid = u.oid WHERE NOT m.invoker)
               AS invoker_chain,                     -- every view on the chain, the top one too, reads as the caller
           format('%I.%I', t.nspname, t.relname) || coalesce(' via ' || (
               SELECT string_agg(format('%I.%I', m.nspname, m.relname), ' → ' ORDER BY u.i)
               FROM unnest(r.path[2:]) WITH ORDINALITY u(oid, i) JOIN rel m ON m.oid = u.oid), '') AS base,
           format('%I.%I', t.nspname, t.relname) AS base_name,
           CASE WHEN m.oid IS NOT NULL
                THEN format('ALTER VIEW %I.%I SET (security_invoker = true);', m.nspname, m.relname) END AS fix_below
    FROM reach r
    JOIN rel t ON t.oid = r.node AND t.relkind IN ('r', 'p')
    LEFT JOIN LATERAL unnest(r.path[2:]) u(oid) ON true
    LEFT JOIN rel m ON m.oid = u.oid AND m.relkind = 'v' AND NOT m.invoker
), findings AS (
    SELECT 1 AS sev, 'exposed_role_missing' AS check_name, coalesce(n.rolname, '(none named)') AS object,
           'no such role: nothing it can reach was checked' AS detail, 'pass -v exposed_roles=<existing roles>' AS fix
    FROM (SELECT NULL) one LEFT JOIN named n ON true
    WHERE n.rolname IS NULL OR NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = n.rolname)
    UNION ALL
    -- 1. an exposed role can read or write a table that has no row-level security at all
    SELECT 1, 'rls_off_exposed', format('%I.%I', r.nspname, r.relname),
           'RLS is OFF; ' || string_agg(DISTINCT g.who || ':' || g.priv_desc, ', '),
           format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY; then write its policies', r.nspname, r.relname)
    FROM rel r JOIN grants g ON g.oid = r.oid
    WHERE r.relkind IN ('r', 'p') AND NOT r.rls
      AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = r.oid)   -- has policies: policy_exists_rls_disabled
    GROUP BY r.nspname, r.relname

    UNION ALL  -- 1b. policies written, RLS left OFF: they do nothing. If an exposed role can also reach the table, this one
               --     row says so (rls_off_exposed stays silent: "write its policies" would be the wrong fix)
    SELECT 1, 'policy_exists_rls_disabled', format('%I.%I', r.nspname, r.relname),
           'RLS is OFF, so its policies do nothing: '
               || (SELECT string_agg(quote_ident(p.polname), ', ' ORDER BY p.polname) FROM pg_policy p WHERE p.polrelid = r.oid)
               || coalesce('; and every row is open to ' || (SELECT string_agg(DISTINCT g.who || ':' || g.priv_desc, ', ')
                                                              FROM grants g WHERE g.oid = r.oid), ''),
           format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY;', r.nspname, r.relname)
    FROM rel r
    WHERE r.relkind IN ('r', 'p') AND NOT r.rls AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = r.oid)

    UNION ALL  -- 2. a view that runs as its owner over an RLS table, readable by an exposed role: the policies are skipped
    --         (also through views stacked on views: v2 -> v1 -> secret with only v2 granted)
    SELECT 1, 'view_bypasses_rls', format('%I.%I', r.nspname, r.relname),
           'reads ' || string_agg(DISTINCT vr.base, ', ') || ' as its owner; readable by '
               || string_agg(DISTINCT g.who, ', '),
           format('ALTER VIEW %I.%I SET (security_invoker = true);', r.nspname, r.relname)
               || coalesce(' ' || string_agg(DISTINCT vr.fix_below, ' '), '')
    FROM rel r JOIN view_on_table vr ON vr.view_oid = r.oid AND vr.rls AND NOT vr.auth_users   -- that one: check 10
    JOIN grants g ON g.oid = r.oid AND g.priv = 'SELECT'
    WHERE r.relkind = 'v' AND NOT r.invoker
    GROUP BY r.nspname, r.relname

    UNION ALL  -- 2b. a view that runs as its owner over a table with RLS OFF, readable by an exposed role: every row of
               --     that table is served, even when the table itself is granted to no one
    SELECT 1, 'rls_off_via_view', format('%I.%I', r.nspname, r.relname),
           'reads ' || string_agg(DISTINCT vr.base, ', ') || ' as its owner, and RLS is OFF there; readable by '
               || string_agg(DISTINCT g.who, ', '),
           string_agg(DISTINCT format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY;', vr.base_name), ' ') || ' '
               || format('ALTER VIEW %I.%I SET (security_invoker = true);', r.nspname, r.relname)
               || coalesce(' ' || string_agg(DISTINCT vr.fix_below, ' '), '')
               || ' then write its policies and grant the view''s readers SELECT on what it reads'
    FROM rel r JOIN view_on_table vr ON vr.view_oid = r.oid AND NOT vr.rls AND NOT vr.auth_users
    JOIN grants g ON g.oid = r.oid AND g.priv = 'SELECT'
    WHERE r.relkind = 'v' AND NOT r.invoker
    GROUP BY r.nspname, r.relname

    UNION ALL  -- 3. a materialized view never applies RLS, so one over an RLS table must not be readable by clients
    SELECT 1, 'matview_bypasses_rls', format('%I.%I', r.nspname, r.relname),
           'materialized from ' || string_agg(DISTINCT vr.base, ', ') || ' (no RLS on a matview); readable by '
               || string_agg(DISTINCT g.who, ', '),
           format('REVOKE SELECT ON %I.%I FROM %s; serve it through a security_invoker view or a checked function',
                  r.nspname, r.relname, string_agg(DISTINCT g.who_sql, ', '))
    FROM rel r JOIN view_on_table vr ON vr.view_oid = r.oid AND vr.rls AND NOT vr.auth_users
    JOIN grants g ON g.oid = r.oid AND g.priv = 'SELECT'
    WHERE r.relkind = 'm'
    GROUP BY r.nspname, r.relname

    UNION ALL  -- 4. a permissive policy whose condition is literally true: OR-ed with the others, it opens every row
    SELECT 1, 'policy_always_true', format('%I.%I', r.nspname, r.relname) || ' / ' || quote_ident(p.polname),
           CASE WHEN p.using_expr = 'true' THEN 'USING (true)' ELSE 'WITH CHECK (true)' END
               || ' on a permissive policy that applies to an exposed role',
           'scope the condition (e.g. owner_id = (select auth.uid())), or make it RESTRICTIVE, or drop it'
    FROM pol p JOIN rel r ON r.oid = p.polrelid
    WHERE p.polpermissive AND p.for_exposed AND (p.using_expr = 'true' OR p.check_expr = 'true')

    UNION ALL  -- 5. authorization read from user metadata, which the user can edit
    SELECT 1, 'policy_trusts_user_metadata', format('%I.%I', r.nspname, r.relname) || ' / ' || quote_ident(p.polname),
           'the policy reads user_metadata — a value the signed-in user can change about themselves',
           'authorize from app_metadata or a table only the server writes'
    FROM pol p JOIN rel r ON r.oid = p.polrelid
    WHERE (p.using_expr || ' ' || p.check_expr) ~* '(raw_)?user_meta_?data'

    UNION ALL  -- 6. a SECURITY DEFINER function with no fixed search_path can be hijacked by an object earlier in the path
    SELECT 1, 'definer_without_search_path', format('%I.%I(%s)', f.nspname, f.proname, f.args),
           'SECURITY DEFINER and no search_path in its settings'
               || CASE WHEN f.callable_by_exposed THEN '; callable by an exposed role' ELSE '' END,
           format('ALTER FUNCTION %I.%I(%s) SET search_path = pg_catalog, pg_temp;', f.nspname, f.proname, f.args)
    FROM fn f
    WHERE NOT coalesce(EXISTS (SELECT 1 FROM unnest(f.proconfig) s WHERE s LIKE 'search\_path=%'), false)

    UNION ALL  -- 10. a view or materialized view over Supabase's auth.users (every user's email, phone, metadata) that an
               --     exposed role can read, with an owner-run view or a matview somewhere on the way: every user is served.
               --     Silent where no auth.users table exists; a chain of security_invoker views needs a grant on auth.users
    SELECT 1, 'auth_users_exposed', format('%I.%I', r.nspname, r.relname),
           'reads ' || string_agg(DISTINCT vr.base, ', ')
               || CASE WHEN r.relkind = 'm' THEN ' into a materialized view (no RLS)'
                       WHEN NOT r.invoker THEN ' as its owner' ELSE ' through an owner-run view below it' END
               || '; readable by ' || string_agg(DISTINCT g.who, ', '),
           format('REVOKE SELECT ON %I.%I FROM %s; serve clients only what they need from a table with RLS (e.g. a profiles table), never auth.users',
                  r.nspname, r.relname, string_agg(DISTINCT g.who_sql, ', '))
    FROM rel r JOIN view_on_table vr ON vr.view_oid = r.oid AND vr.auth_users AND NOT vr.invoker_chain
    JOIN grants g ON g.oid = r.oid AND g.priv = 'SELECT'
    WHERE r.relkind IN ('v', 'm')
    GROUP BY r.nspname, r.relname, r.relkind, r.invoker

    UNION ALL  -- 7. RLS enabled but not forced, with an owner that does not already bypass it: the owner's queries
               --    (and every SECURITY DEFINER function it owns) skip the policies
    SELECT 2, 'rls_not_forced', format('%I.%I', r.nspname, r.relname),
           'RLS is on but not FORCED; the table owner and its SECURITY DEFINER functions are exempt',
           format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY;', r.nspname, r.relname)
    FROM rel r
    WHERE r.relkind IN ('r', 'p') AND r.rls AND NOT r.forced AND NOT r.owner_bypasses

    UNION ALL  -- 8. auth.uid()/auth.jwt()/auth.role() evaluated once per row instead of once per statement
    SELECT 2, 'policy_per_row_auth_call', format('%I.%I', r.nspname, r.relname) || ' / ' || quote_ident(p.polname),
           'auth.*() called directly in the policy: evaluated for every row scanned',
           'wrap it: (select auth.uid()) — the planner then evaluates it once'
    FROM pol p JOIN rel r ON r.oid = p.polrelid
    WHERE regexp_count(p.using_expr || ' ' || p.check_expr, 'auth\.(uid|jwt|role)\(\)')
        > regexp_count(p.using_expr || ' ' || p.check_expr, 'SELECT \(*auth\.(uid|jwt|role)\(\)')

    UNION ALL  -- 11. more than one permissive policy for the same role and command: every row is checked against all of
               --     them, and a row passes when ANY of them passes — an OR that reads like an AND
    SELECT 2, 'multiple_permissive_policies',
           format('%I.%I', r.nspname, r.relname) || ' / ' || o.who || ' / '
               || string_agg(o.cmd, ', ' ORDER BY array_position(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE'], o.cmd)),
           'permissive policies ' || o.policies || ' all apply to ' || o.who || ' for '
               || string_agg(o.cmd, ', ' ORDER BY array_position(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE'], o.cmd))
               || ': each row evaluates every one, and passes if ANY passes (OR, not AND)',
           'merge them into one policy whose condition ORs theirs; a condition that must ALL hold belongs in a RESTRICTIVE policy'
    FROM overlap o JOIN rel r ON r.oid = o.polrelid
    GROUP BY r.nspname, r.relname, o.who, o.policies

    UNION ALL  -- 9. RLS on with no policy at all: every non-owner is denied every row — intended, or a forgotten policy?
    SELECT 3, 'rls_without_policies', format('%I.%I', r.nspname, r.relname),
           'RLS is on and the table has no policies: non-owners see nothing',
           'if clients should read it, write the policy; if not, this is fine'
    FROM rel r
    WHERE r.relkind IN ('r', 'p') AND r.rls AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = r.oid)
)
SELECT CASE sev WHEN 1 THEN 'HIGH' WHEN 2 THEN 'MEDIUM' ELSE 'LOW' END AS severity, check_name, object, detail, fix
FROM findings
ORDER BY sev, check_name, object;

SELECT count(*) FILTER (WHERE c.relkind IN ('r', 'p') AND c.relrowsecurity) AS tables_with_rls,
       count(*) FILTER (WHERE c.relkind IN ('r', 'p')) AS tables,
       (SELECT count(*) FROM pg_policy) AS policies,
       (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema')) AS security_definer_functions
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_%';

ROLLBACK;
