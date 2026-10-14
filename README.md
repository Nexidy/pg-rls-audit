# pg-rls-audit

![tests](https://github.com/Nexidy/pg-rls-audit/actions/workflows/test.yml/badge.svg)

A read-only audit of PostgreSQL row-level security and `SECURITY DEFINER` hygiene — the mistakes that pass every
test and still leak rows. One SQL file, plain `psql`, no dependencies, PostgreSQL 15+.

```sh
psql -X -d mydb -f pg-rls-audit.sql                                   # Supabase: anon,authenticated are untrusted
psql -X -d mydb -v exposed_roles=web_anon,app_user -f pg-rls-audit.sql   # PostgREST or your own roles
```

It reads only the system catalogs inside a `READ ONLY` transaction that ends in `ROLLBACK`: it cannot change a row,
a policy or a setting. Every finding comes with the statement that fixes it.

| Severity | Check | What it means |
|---|---|---|
| HIGH | `rls_off_exposed` | An untrusted role can read or write a table that has no row-level security at all. |
| HIGH | `view_bypasses_rls` | A view over an RLS table runs as its owner (no `security_invoker`), so the policies are skipped. |
| HIGH | `matview_bypasses_rls` | A materialized view never applies RLS; one built over an RLS table is readable by clients. |
| HIGH | `policy_always_true` | A permissive `USING (true)` / `WITH CHECK (true)` policy — OR-ed with the rest, it opens every row. |
| HIGH | `policy_trusts_user_metadata` | Authorization read from `user_metadata`, which the user can edit about themselves. |
| HIGH | `definer_without_search_path` | A `SECURITY DEFINER` function with no fixed `search_path` can be hijacked. |
| MEDIUM | `rls_not_forced` | RLS on but not `FORCE`d: the table owner and its definer functions are exempt. |
| MEDIUM | `policy_per_row_auth_call` | `auth.uid()` called directly in a policy is evaluated for every row; `(select auth.uid())` once. |
| LOW | `rls_without_policies` | RLS on with no policy: non-owners see nothing. Intended, or a forgotten policy? |

The last result set counts what it read: tables, tables with RLS, policies and `SECURITY DEFINER` functions.

**Tested** against a scratch database with one planted defect per check, each beside a clean look-alike (a
`security_invoker` view, a pinned definer, a wrapped `auth.uid()`) that must not be reported.

By [Nexidy](https://nexidy.com).

## Known limits

- A view over a table with RLS **off**, granted to an untrusted role while the table itself is not, is not reported.
- Views stacked on views are followed one level deep: `v2 → v1 → secret` is missed when only `v2` is granted.
- Column-level grants (`GRANT SELECT (email) ON t TO anon`) are not read — only table-level ACLs.

## Run the tests

`test/run_tests.py` builds a scratch database with one planted defect per check (and a clean look-alike beside each
one), runs `pg-rls-audit.sql` against it, and checks every finding and every silence. It talks to any PostgreSQL
15+ server through the usual `psql`/`createdb`/`dropdb` command-line tools and the standard libpq environment
variables — no server of its own, nothing installed beyond a PostgreSQL client.

```sh
PGHOST=localhost PGPORT=5432 PGUSER=postgres PGPASSWORD=postgres python3 test/run_tests.py
```

Exits `0` on a pass, `1` on any failed case, `77` if no server is reachable (createdb fails). Every database and
role it creates is name-tagged with the test's own PID and dropped on exit, so concurrent runs do not collide.
