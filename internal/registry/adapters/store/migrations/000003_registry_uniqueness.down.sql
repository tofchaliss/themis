-- Drops the three uniqueness indexes ONLY and touches no data (EDR-INTAKE-01 B4): a down
-- migration that deleted or merged rows to make room for the shape it is reverting to would be
-- the estate decision B4 refuses to take. An un-indexed registry is the pre-000003 shape, which
-- is why the name lookups abstain on >1 match rather than relying on the index being there.

DROP INDEX IF EXISTS registry_releases_project_version_key;
DROP INDEX IF EXISTS registry_projects_product_name_key;
DROP INDEX IF EXISTS registry_products_name_key;
