-- Registry uniqueness at the DATABASE (EDR-INTAKE-01 amendment B4): products unique on
-- lower(name), projects on (product_id, lower(name)), releases on (project_id, version) —
-- exact, because a build string's case is not Themis's to fold. An index accelerates a query;
-- a constraint enforces an identity, which is what stops two concurrent registrations from
-- forking a Release.
--
-- This migration REFUSES; it never repairs. If a duplicate exists the pre-flight below fails
-- naming the offending groups, and nothing is merged, reassigned or deleted — re-pointing
-- projects, releases, evidence, findings and positions is an estate decision, not something a
-- migration may take while an operator watches a progress line.
--
-- One explicit transaction, and the FIRST statement after BEGIN is the table lock (B4,
-- revision 2): a duplicate inserted between the pre-flight query and an index build would turn
-- the named refusal into a bare 23505 from the build. SHARE ROW EXCLUSIVE conflicts with
-- ROW EXCLUSIVE, so every concurrent INSERT/UPDATE/DELETE on the three tables waits — and then
-- proceeds — while reads continue. Writes are therefore quiesced from the pre-flight through
-- the last index, and released at COMMIT. The indexes are built without CONCURRENTLY:
-- CONCURRENTLY is what cannot run inside a transaction, and a transaction is what makes the
-- pre-flight unraceable. BEGIN/COMMIT are written out so the transaction boundary does not
-- depend on how the driver sends the file.
--
-- Driver note. Registry applies this through golang-migrate's Postgres driver from
-- cmd/registry (THEMIS_REGISTRY_MIGRATE=1, bookkeeping in registry_schema_migrations). The
-- driver sends the file as one statement and does not open a transaction of its own, so the
-- explicit BEGIN/COMMIT here is the only one and executes as written. It does, however, mark
-- the version row dirty BEFORE running the file: if the pre-flight refuses, version 3 is left
-- `dirty` and a restart will not retry it. Recovery (resolve the named duplicates, force the
-- version back to 2, re-run) is INSTALLATION.md section 8, "If migration 000003 refuses".

BEGIN;

LOCK TABLE products, projects, releases IN SHARE ROW EXCLUSIVE MODE;

DO $$
DECLARE
    -- Ids listed per group; the remainder is counted, so a wide estate cannot turn one
    -- refusal into an unreadable error message.
    id_cap   CONSTANT int := 10;
    g        record;
    ids      text;
    extra    int;
    refusal  text := '';
BEGIN
    FOR g IN
        SELECT lower(name) AS dup_value, count(*) AS dup_rows, array_agg(id ORDER BY id) AS ids
          FROM products
         GROUP BY lower(name)
        HAVING count(*) > 1
         ORDER BY lower(name)
    LOOP
        ids := array_to_string(g.ids[1:id_cap], ', ');
        extra := g.dup_rows - least(g.dup_rows, id_cap);
        IF extra > 0 THEN
            ids := ids || format(', +%s more', extra);
        END IF;
        refusal := refusal || format(E'\n  products: lower(name)=%L rows=%s ids=[%s]',
                                     g.dup_value, g.dup_rows, ids);
    END LOOP;

    FOR g IN
        SELECT product_id, lower(name) AS dup_value, count(*) AS dup_rows,
               array_agg(id ORDER BY id) AS ids
          FROM projects
         GROUP BY product_id, lower(name)
        HAVING count(*) > 1
         ORDER BY product_id, lower(name)
    LOOP
        ids := array_to_string(g.ids[1:id_cap], ', ');
        extra := g.dup_rows - least(g.dup_rows, id_cap);
        IF extra > 0 THEN
            ids := ids || format(', +%s more', extra);
        END IF;
        refusal := refusal || format(E'\n  projects: product_id=%L lower(name)=%L rows=%s ids=[%s]',
                                     g.product_id, g.dup_value, g.dup_rows, ids);
    END LOOP;

    FOR g IN
        SELECT project_id, version AS dup_value, count(*) AS dup_rows,
               array_agg(id ORDER BY id) AS ids
          FROM releases
         GROUP BY project_id, version
        HAVING count(*) > 1
         ORDER BY project_id, version
    LOOP
        ids := array_to_string(g.ids[1:id_cap], ', ');
        extra := g.dup_rows - least(g.dup_rows, id_cap);
        IF extra > 0 THEN
            ids := ids || format(', +%s more', extra);
        END IF;
        refusal := refusal || format(E'\n  releases: project_id=%L version=%L rows=%s ids=[%s]',
                                     g.project_id, g.dup_value, g.dup_rows, ids);
    END LOOP;

    IF refusal <> '' THEN
        RAISE EXCEPTION
            'registry uniqueness pre-flight refused: duplicate rows exist, and this migration never merges, reassigns or deletes records (EDR-INTAKE-01 B4).%',
            refusal
            USING HINT = 'Resolve every group named above, then follow INSTALLATION.md section 8 ("If migration 000003 refuses") to clear the dirty version and re-run.';
    END IF;
END
$$ LANGUAGE plpgsql;

CREATE UNIQUE INDEX registry_products_name_key ON products (lower(name));
CREATE UNIQUE INDEX registry_projects_product_name_key ON projects (product_id, lower(name));
CREATE UNIQUE INDEX registry_releases_project_version_key ON releases (project_id, version);

COMMIT;
