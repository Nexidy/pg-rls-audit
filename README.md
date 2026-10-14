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
| HIGH | `rls_off_exposed` | An untrusted role can read or write a table that has no row-level security at all — through a table-level grant or a column-level one (`GRANT SELECT (email) ON t TO anon`). |
| HIGH | `policy_exists_rls_disabled` | A table has policies but row-level security is **off**, so they do nothing. Reported instead of `rls_off_exposed` when both apply: one row names the policies and the grants, one fix (`ENABLE ROW LEVEL SECURITY`). |
| HIGH | `rls_off_via_view` | A view runs as its owner over a table with RLS **off**: granting the view serves every row of that table, even though the table itself is granted to no one. |
| HIGH | `view_bypasses_rls` | A view over an RLS table runs as its owner (no `security_invoker`), so the policies are skipped. |
| HIGH | `matview_bypasses_rls` | A materialized view never applies RLS; one built over an RLS table is readable by clients. |
| HIGH | `auth_users_exposed` | A view or materialized view reads Supabase's `auth.users` — every user's email and phone — and an untrusted role can read it, with an owner-run view or a matview somewhere on the way (followed through stacked views). Silent where no `auth.users` table exists; reported instead of the generic view checks for that table. |
| HIGH | `policy_always_true` | A permissive `USING (true)` / `WITH CHECK (true)` policy — OR-ed with the rest, it opens every row. |
| HIGH | `policy_trusts_user_metadata` | Authorization read from `user_metadata`, which the user can edit about themselves. |
| HIGH | `definer_without_search_path` | A `SECURITY DEFINER` function with no fixed `search_path` can be hijacked. |
| MEDIUM | `rls_not_forced` | RLS on but not `FORCE`d: the table owner and its definer functions are exempt. |
| MEDIUM | `policy_per_row_auth_call` | `auth.uid()` called directly in a policy is evaluated for every row; `(select auth.uid())` once. |
| MEDIUM | `multiple_permissive_policies` | More than one permissive policy for the same role and command on one table: every row evaluates all of them, and a row passes if **any** passes — a cost, and an OR easily misread as an AND. Names the policies, the role and the command (`FOR ALL` counts for each command). |
| LOW | `rls_without_policies` | RLS on with no policy: non-owners see nothing. Intended, or a forgotten policy? |

Grants are read from both the table ACL and every column ACL, and views are followed through views and
materialized views stacked on each other to any depth (a cycle made with `CREATE OR REPLACE VIEW` stops the walk, it
does not loop): `v2 → v1 → secret` is reported on `v2` when only `v2` is granted, with the whole chain in the detail
and an `ALTER VIEW … SET (security_invoker = true)` for every owner-run link in the fix.

The last result set counts what it read: tables, tables with RLS, policies and `SECURITY DEFINER` functions.

**Tested** against a scratch database with one planted defect per check, each beside a clean look-alike (a
`security_invoker` view, a chain of `security_invoker` views, a pinned definer, a wrapped `auth.uid()`, a column
grant on a table with RLS on, the same policy on a table with RLS on, a `security_invoker` view over `auth.users` and
a look-alike `app.users`, a permissive policy beside a restrictive one or on another role or command) that must not
be reported — and a table with policies, RLS off and a grant, reported once, not twice.

By [Nexidy](https://nexidy.com).

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
