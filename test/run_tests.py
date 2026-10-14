#!/usr/bin/env python3
"""pg-rls-audit finds every defect it claims to, and nothing on the clean look-alikes.

A scratch database gets one planted defect per check, each beside a CLEAN look-alike (a
security_invoker view, a pinned definer, a wrapped auth.uid()) that must NOT be reported: a check
that fires on everything is as useless as one that fires on nothing. Roles are per-run names and
dropped at exit; nothing touches a database other than the scratch one this script creates.

Talks to PostgreSQL through plain libpq environment variables — PGHOST, PGPORT, PGUSER, PGPASSWORD
— and the `psql`/`createdb`/`dropdb` command-line tools. No other credentials, no `runuser`.
"""
import atexit
import os
import subprocess
import sys

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pg-rls-audit.sql")

PASS = FAIL = 0


def case(label, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("  ✅ " if ok else "  ❌ ") + label + ("" if ok else f" — {str(detail)[:400]}"))


def run(args, stdin=None):
    r = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout + r.stderr


tag = f"{os.getpid()}"
DB, ANON, AUTHD, OWNER, PARENT = (f"pgaudit_t_{tag}", f"pga_anon_{tag}", f"pga_auth_{tag}", f"pga_owner_{tag}",
                                  f"pga_parent_{tag}")


def cleanup():
    run(["dropdb", "--if-exists", "--force", DB])
    run(["psql", "-X", "-q", "-d", "postgres"],
        f"DROP ROLE IF EXISTS {ANON}; DROP ROLE IF EXISTS {AUTHD}; DROP ROLE IF EXISTS {OWNER}; "
        f"DROP ROLE IF EXISTS {PARENT};")


atexit.register(cleanup)
rc, out = run(["createdb", DB])
if rc:
    print(f"  ⚪ SKIP: no reachable PostgreSQL server to build a scratch database ({out.strip()[:200]})")
    sys.exit(77)
run(["psql", "-X", "-q", "-d", "postgres"],
    f"CREATE ROLE {ANON} NOLOGIN; CREATE ROLE {AUTHD} NOLOGIN; CREATE ROLE {OWNER} NOLOGIN; "
    f"CREATE ROLE {PARENT} NOLOGIN; GRANT {PARENT} TO {ANON};")

FIXTURE = f"""
CREATE SCHEMA app AUTHORIZATION {OWNER}; CREATE SCHEMA auth;
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT NULL::uuid $$;
CREATE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE AS $$ SELECT '{{}}'::jsonb $$;
GRANT USAGE ON SCHEMA auth TO {OWNER}, {ANON}, {AUTHD};
SET ROLE {OWNER};
-- clean: RLS on and forced, a wrapped auth.uid()
CREATE TABLE app.secret (id int, owner_id uuid);
ALTER TABLE app.secret ENABLE ROW LEVEL SECURITY; ALTER TABLE app.secret FORCE ROW LEVEL SECURITY;
CREATE POLICY own ON app.secret FOR SELECT TO {ANON} USING (owner_id = (select auth.uid()));
GRANT SELECT ON app.secret TO {ANON};
-- 1 rls_off_exposed
CREATE TABLE app.open_tbl (id int); GRANT SELECT, INSERT ON app.open_tbl TO {ANON};
-- 2 view_bypasses_rls · clean twin: security_invoker
CREATE VIEW app.leaky_view AS SELECT * FROM app.secret; GRANT SELECT ON app.leaky_view TO {ANON};
CREATE VIEW app.safe_view WITH (security_invoker = true) AS SELECT * FROM app.secret; GRANT SELECT ON app.safe_view TO {ANON};
CREATE VIEW app.safe_view_yes WITH (security_invoker = yes) AS SELECT * FROM app.secret; GRANT SELECT ON app.safe_view_yes TO {ANON};
CREATE TABLE app.jwtwrap (id int);
ALTER TABLE app.jwtwrap ENABLE ROW LEVEL SECURITY; ALTER TABLE app.jwtwrap FORCE ROW LEVEL SECURITY;
CREATE POLICY wrapped ON app.jwtwrap FOR SELECT TO {AUTHD} USING ((select auth.jwt() ->> 'role') = 'admin');
-- 3 matview_bypasses_rls
CREATE MATERIALIZED VIEW app.mv AS SELECT * FROM app.secret WITH NO DATA; GRANT SELECT ON app.mv TO {AUTHD};
-- 4 policy_always_true
CREATE TABLE app.notes (id int);
ALTER TABLE app.notes ENABLE ROW LEVEL SECURITY; ALTER TABLE app.notes FORCE ROW LEVEL SECURITY;
CREATE POLICY everyone ON app.notes FOR SELECT TO {ANON} USING (true);
-- 5 policy_trusts_user_metadata (+ 8, auth.jwt() unwrapped)
CREATE TABLE app.meta (id int);
ALTER TABLE app.meta ENABLE ROW LEVEL SECURITY; ALTER TABLE app.meta FORCE ROW LEVEL SECURITY;
CREATE POLICY admins ON app.meta FOR SELECT TO {AUTHD} USING ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
-- 8 policy_per_row_auth_call
CREATE TABLE app.perrow (id int, owner_id uuid);
ALTER TABLE app.perrow ENABLE ROW LEVEL SECURITY; ALTER TABLE app.perrow FORCE ROW LEVEL SECURITY;
CREATE POLICY mine ON app.perrow FOR SELECT TO {AUTHD} USING (owner_id = auth.uid());
-- 6 definer_without_search_path · clean twin: pinned
CREATE FUNCTION app.bad_definer() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
CREATE FUNCTION app.good_definer() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;
-- 7 rls_not_forced
CREATE TABLE app.unforced (id int); ALTER TABLE app.unforced ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON app.unforced FOR SELECT TO {AUTHD} USING (true);
-- 1b rls_off_exposed through role MEMBERSHIP (granted to a parent role the anon role inherits)
CREATE TABLE app.via_parent (id int); GRANT SELECT ON app.via_parent TO {PARENT};
-- 9 rls_without_policies
CREATE TABLE app.nopol (id int);
ALTER TABLE app.nopol ENABLE ROW LEVEL SECURITY; ALTER TABLE app.nopol FORCE ROW LEVEL SECURITY;
RESET ROLE;
"""
rc, out = run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", DB], FIXTURE)
case("the fixture builds", rc == 0, out)

sql = open(TOOL, encoding="utf-8").read()
rc, out = run(["psql", "-X", "-q", "-A", "-t", "-F", "|", "-v", f"exposed_roles={ANON}, {AUTHD}", "-d", DB], sql)
case("the audit runs to the end (exit 0)", rc == 0, out)
found = {(f[1], f[2]) for f in (ln.split("|") for ln in out.splitlines()) if len(f) == 5}

for check, obj in (("rls_off_exposed", "app.open_tbl"),
                   ("rls_off_exposed", "app.via_parent"),
                   ("view_bypasses_rls", "app.leaky_view"),
                   ("matview_bypasses_rls", "app.mv"),
                   ("policy_always_true", "app.notes / everyone"),
                   ("policy_trusts_user_metadata", "app.meta / admins"),
                   ("definer_without_search_path", "app.bad_definer()"),
                   ("rls_not_forced", "app.unforced"),
                   ("policy_per_row_auth_call", "app.perrow / mine"),
                   ("policy_per_row_auth_call", "app.meta / admins"),
                   ("rls_without_policies", "app.nopol")):
    case(f"⭐ finds {check} on {obj}", (check, obj) in found, sorted(found))

flagged = {o.split(" / ")[0].split("(")[0] for _, o in found}
case("⛔ the clean twins are never reported: app.secret, app.safe_view, app.safe_view_yes (security_invoker = yes), app.good_definer, app.jwtwrap",
     not ({"app.secret", "app.safe_view", "app.safe_view_yes", "app.good_definer", "app.jwtwrap"} & flagged), sorted(found))
case("⛔ a wrapped (select auth.uid()) is not a per-row call", ("policy_per_row_auth_call", "app.secret / own") not in found,
     sorted(found))
rc2, out2 = run(["psql", "-X", "-q", "-A", "-t", "-F", "|", "-v", f"exposed_roles=pga_typo_{tag}", "-d", DB], sql)
case("⭐ a misspelled role is reported as exposed_role_missing, never a silent clean run",
     f"exposed_role_missing|pga_typo_{tag}" in out2, out2[-300:])
rc3, out3 = run(["psql", "-X", "-q", "-A", "-t", "-d", DB],
                 sql.replace("BEGIN TRANSACTION READ ONLY;", "BEGIN TRANSACTION READ ONLY; SELECT 1/0;"))
case("⭐ an error EXITS NON-ZERO from the README's plain command (ON_ERROR_STOP is set in the file)", rc3 != 0,
     (rc3, out3[-200:]))
case("⭐ it can change nothing: the whole audit runs inside a READ ONLY transaction and rolls back",
     "BEGIN TRANSACTION READ ONLY;" in sql and sql.rstrip().endswith("ROLLBACK;"))

print(f"\n  {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
