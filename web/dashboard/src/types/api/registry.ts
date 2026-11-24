// Generated from api/registry.openapi.yaml by scripts/gen-api.mjs. Do not edit.

export interface paths {
    "/products": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List products, optionally filtered by exact name.
         * @description The entry point for a human or a GUI (DASH-1). Without this, a release's posture is unreachable unless the caller already holds the UUID that `POST /releases` printed — which is exactly the coupling a read API exists to remove.
         */
        get: operations["listProducts"];
        put?: never;
        /**
         * Register a product; returns a stable Product ID.
         * @description Find-or-create (EDR-INTAKE-01 B4): uniqueness is enforced by the database on `lower(name)`, so registering a name that already exists returns the EXISTING id with `200` rather than failing or forking a second Product. Two concurrent callers get one row. The stored casing is the first caller's.
         */
        post: operations["registerProduct"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/products/{id}/projects": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the projects under a product. */
        get: operations["listProjectsOfProduct"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/projects/{id}/releases": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the releases under a project. */
        get: operations["listReleasesOfProject"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/projects": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Register a project under a product; returns a stable Project ID.
         * @description Find-or-create (EDR-INTAKE-01 B4): unique on `(product_id, lower(name))`, so the same project name already registered under this product returns the EXISTING id with `200`. The same name under a DIFFERENT product is a different Project.
         */
        post: operations["registerProject"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the releases of a project. */
        get: operations["listReleases"];
        put?: never;
        /**
         * Register a release under a project; returns a stable Release ID.
         * @description Find-or-create (EDR-INTAKE-01 B4): unique on `(project_id, version)`, so re-registering a version returns the EXISTING id with `200` — two bots building one version at the same moment get one Release. Version matching is EXACT, never case-folded: a version is a machine build string whose case Themis does not own, so `r1917.256` and `R1917.256` are two Releases.
         */
        post: operations["registerRelease"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get a release by ID. */
        get: operations["getRelease"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/projects/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get a project by ID (the upward hop of the name chain — release -> project -> product). */
        get: operations["getProject"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        /**
         * Rename a project. Admin key only.
         * @description Changes the project's NAME and nothing else (EDR-KERNEL-01 D5). Every other context refers to a project by its id and reads the name live from Registry, so findings, decisions, watches and tickets keep pointing at the same project. The name stays unique per product, case folded: a name another project of the same product already carries is `409`, and nothing changes. A change of case only (`alpha` → `Alpha`) is allowed. A CI job that finds-or-creates the project by name must be changed to the new name, or its next upload registers a new project under the old one.
         */
        patch: operations["renameProject"];
        trace?: never;
    };
    "/products/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get a product by ID (the top of the name chain). */
        get: operations["getProduct"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/customers": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Register a customer; returns a stable Customer ID. */
        post: operations["registerCustomer"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/products/{id}/microservices": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Register a microservice under a product; returns a stable Microservice ID. */
        post: operations["registerMicroservice"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/microservices/{id}/deployments": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Register a deployment of a microservice for a customer; returns a stable Deployment ID. */
        post: operations["registerDeployment"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/products/{id}/requirements": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** A product's CVSS security requirements (CR / IR / AR) — current record and history, newest first (EDR-SCORING-01 S3). */
        get: operations["getProductRequirements"];
        put?: never;
        /**
         * Record a change of a product's security requirements, with a reason and an actor. Admin, or a key scoped to the owning product.
         * @description Append-only: the change is a new record and the earlier ones stay. X means this level states nothing, so the metric falls through to the next level (Release, then Project, then Product). Scores are recalculated by Governance as new revisions; nothing is changed silently.
         */
        post: operations["postProductRequirements"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/projects/{id}/requirements": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** A project's CVSS security requirements (CR / IR / AR) — current record and history, newest first (EDR-SCORING-01 S3). */
        get: operations["getProjectRequirements"];
        put?: never;
        /**
         * Record a change of a project's security requirements, with a reason and an actor. Admin, or a key scoped to the owning product.
         * @description Append-only: the change is a new record and the earlier ones stay. X means this level states nothing, so the metric falls through to the next level (Release, then Project, then Product). Scores are recalculated by Governance as new revisions; nothing is changed silently.
         */
        post: operations["postProjectRequirements"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases/{id}/requirements": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** A release's CVSS security requirements (CR / IR / AR) — current record and history, newest first (EDR-SCORING-01 S3). */
        get: operations["getReleaseRequirements"];
        put?: never;
        /**
         * Record a change of a release's security requirements, with a reason and an actor. Admin, or a key scoped to the owning product.
         * @description Append-only: the change is a new record and the earlier ones stay. X means this level states nothing, so the metric falls through to the next level (Release, then Project, then Product). Scores are recalculated by Governance as new revisions; nothing is changed silently.
         */
        post: operations["postReleaseRequirements"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases/{id}/requirements/resolved": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** CR / IR / AR resolved for a release, each metric on its own (Release, then Project, then Product, then X), with the level it came from. */
        get: operations["getReleaseResolvedRequirements"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/products/{id}/tags": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** A product's own and effective tags (EDR-REMEDIATION-01 D7 — filters only, never a weight). */
        get: operations["getProductTags"];
        /** Replace a product's own tags. Admin, or a key scoped to the owning product. */
        put: operations["putProductTags"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/projects/{id}/tags": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** A project's own and effective tags (EDR-REMEDIATION-01 D7 — filters only, never a weight). */
        get: operations["getProjectTags"];
        /** Replace a project's own tags. Admin, or a key scoped to the owning product. */
        put: operations["putProjectTags"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases/{id}/tags": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** A release's own and effective tags (EDR-REMEDIATION-01 D7 — filters only, never a weight). */
        get: operations["getReleaseTags"];
        /** Replace a release's own tags. Admin, or a key scoped to the owning product. */
        put: operations["putReleaseTags"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/tagged-releases": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Every release whose effective tags carry the tag (own, project's or product's) — EDR-REMEDIATION-01 D7. */
        get: operations["listTaggedReleases"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases/{id}/blast-radius": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Count the unique customers a release reaches through the estate graph. */
        get: operations["getBlastRadius"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        RegisterProductRequest: {
            name: string;
        };
        RegisterProjectRequest: {
            product_id: string;
            name: string;
        };
        RenameProjectRequest: {
            name: string;
        };
        RegisterReleaseRequest: {
            project_id: string;
            version: string;
        };
        RegisterResponse: {
            id: string;
        };
        FindOrCreateResponse: {
            /** @description The surviving row's id — the existing one when `created` is false. */
            id: string;
            /** @description true when THIS request created the row (`201`), false when it already existed (`200`). It carries the same answer as the status code, so a client that reads one and a client that reads the other cannot be told different stories. */
            created: boolean;
        };
        Release: {
            id?: string;
            project_id?: string;
            version?: string;
        };
        /** @enum {string} */
        RequirementValue: "H" | "M" | "L" | "X";
        RequirementChange: {
            cr?: components["schemas"]["RequirementValue"];
            ir?: components["schemas"]["RequirementValue"];
            ar?: components["schemas"]["RequirementValue"];
            /** @description Why the requirements change. Required. */
            reason: string;
            /** @description Who decided the change. Required. */
            actor: string;
        };
        RequirementRecord: {
            /** @enum {string} */
            level: "product" | "project" | "release";
            entity_id: string;
            cr: components["schemas"]["RequirementValue"];
            ir: components["schemas"]["RequirementValue"];
            ar: components["schemas"]["RequirementValue"];
            reason: string;
            actor: string;
            /** @description The API key that recorded the change, when auth is on. */
            via?: string;
            /** Format: date-time */
            recorded_at: string;
        };
        RequirementHistory: {
            current?: components["schemas"]["RequirementRecord"];
            history: components["schemas"]["RequirementRecord"][];
        };
        ResolvedRequirement: {
            value: components["schemas"]["RequirementValue"];
            /**
             * @description The level the value came from; default when no level states it (X).
             * @enum {string}
             */
            level: "release" | "project" | "product" | "default";
        };
        ResolvedRequirements: {
            cr: components["schemas"]["ResolvedRequirement"];
            ir: components["schemas"]["ResolvedRequirement"];
            ar: components["schemas"]["ResolvedRequirement"];
            release?: components["schemas"]["RequirementRecord"];
            project?: components["schemas"]["RequirementRecord"];
            product?: components["schemas"]["RequirementRecord"];
        };
        TagSet: {
            /** @description The entity's own tags. */
            tags: string[];
            /** @description Own tags plus the parents' (a release adds its project's and product's). */
            effective: string[];
        };
        TagsPut: {
            /** @description Lower-cased, 1–64 characters of a-z, 0-9 and the marks colon, dot, underscore, slash, hyphen; at most 20. Replaces the set. */
            tags: string[];
        };
        ProductView: {
            id?: string;
            name?: string;
            tags?: string[];
        };
        ProjectView: {
            id?: string;
            product_id?: string;
            name?: string;
            tags?: string[];
        };
        ReleaseView: {
            id?: string;
            project_id?: string;
            version?: string;
            tags?: string[];
        };
        RegisterCustomerRequest: {
            name: string;
        };
        RegisterMicroserviceRequest: {
            name: string;
        };
        RegisterDeploymentRequest: {
            customer_id: string;
            environment: string;
        };
        BlastRadius: {
            release_id: string;
            unique_customers: number;
        };
        Problem: {
            title?: string;
            detail?: string;
        };
    };
    responses: {
        /** @description Error. */
        Problem: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["Problem"];
            };
        };
    };
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    listProducts: {
        parameters: {
            query?: {
                /** @description Exact product name. Absent = all products. */
                name?: string;
                /** @description Keep only entries carrying this tag in their effective tags (own plus parents'). EDR-REMEDIATION-01 D7. */
                tag?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProductView"][];
                };
            };
        };
    };
    registerProduct: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RegisterProductRequest"];
            };
        };
        responses: {
            /** @description Already registered — the existing id, unchanged. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FindOrCreateResponse"];
                };
            };
            /** @description Registered. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FindOrCreateResponse"];
                };
            };
            400: components["responses"]["Problem"];
            /** @description A product-scoped key may name only its own product (any case), which returns `200` with its existing id; it never creates a product, and every other name is this same `403` whether or not that product exists. */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listProjectsOfProduct: {
        parameters: {
            query?: {
                /** @description Exact project name. */
                name?: string;
                /** @description Keep only entries carrying this tag in their effective tags (own plus parents'). EDR-REMEDIATION-01 D7. */
                tag?: string;
            };
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProjectView"][];
                };
            };
            404: components["responses"]["Problem"];
        };
    };
    listReleasesOfProject: {
        parameters: {
            query?: {
                /** @description Exact release version — completes the product/project/version traversal a human actually has. */
                version?: string;
                /** @description Keep only entries carrying this tag in their effective tags (own plus parents'). EDR-REMEDIATION-01 D7. */
                tag?: string;
            };
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReleaseView"][];
                };
            };
            404: components["responses"]["Problem"];
        };
    };
    registerProject: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RegisterProjectRequest"];
            };
        };
        responses: {
            /** @description Already registered — the existing id, unchanged. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FindOrCreateResponse"];
                };
            };
            /** @description Registered. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FindOrCreateResponse"];
                };
            };
            400: components["responses"]["Problem"];
            /** @description A product-scoped key may register only under its own product. Another product, a product that does not exist and an empty id are one byte-identical answer, so the refusal says nothing about the rest of the estate. */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
            422: components["responses"]["Problem"];
        };
    };
    listReleases: {
        parameters: {
            query: {
                project: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Release"][];
                };
            };
            400: components["responses"]["Problem"];
        };
    };
    registerRelease: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RegisterReleaseRequest"];
            };
        };
        responses: {
            /** @description Already registered — the existing id, unchanged. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FindOrCreateResponse"];
                };
            };
            /** @description Registered. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FindOrCreateResponse"];
                };
            };
            400: components["responses"]["Problem"];
            /** @description A product-scoped key may register only under a project its own product owns. A foreign project and a project that does not exist are one byte-identical answer. */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
            422: components["responses"]["Problem"];
        };
    };
    getRelease: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Release"];
                };
            };
            404: components["responses"]["Problem"];
        };
    };
    getProject: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProjectView"];
                };
            };
            404: components["responses"]["Problem"];
        };
    };
    renameProject: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RenameProjectRequest"];
            };
        };
        responses: {
            /** @description Renamed (or the name was already this one); the project as it is now. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProjectView"];
                };
            };
            400: components["responses"]["Problem"];
            /** @description A key that is not admin. Renaming is an estate decision, not a CI bot's. */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
            404: components["responses"]["Problem"];
            /** @description Another project of the same product already has this name (case folded). */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getProduct: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProductView"];
                };
            };
            404: components["responses"]["Problem"];
        };
    };
    registerCustomer: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RegisterCustomerRequest"];
            };
        };
        responses: {
            /** @description Registered. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RegisterResponse"];
                };
            };
            400: components["responses"]["Problem"];
            /** @description Customers belong to no single product: only an admin key may register one. */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    registerMicroservice: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RegisterMicroserviceRequest"];
            };
        };
        responses: {
            /** @description Registered. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RegisterResponse"];
                };
            };
            400: components["responses"]["Problem"];
            /** @description A product-scoped key may register only under its own product (same answer for a foreign or missing product). */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
            422: components["responses"]["Problem"];
        };
    };
    registerDeployment: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RegisterDeploymentRequest"];
            };
        };
        responses: {
            /** @description Registered. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RegisterResponse"];
                };
            };
            400: components["responses"]["Problem"];
            /** @description A deployment links a product's microservice to a customer, which spans products: only an admin key may register one. */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
            422: components["responses"]["Problem"];
        };
    };
    getProductRequirements: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RequirementHistory"];
                };
            };
            404: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    postProductRequirements: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RequirementChange"];
            };
        };
        responses: {
            /** @description Recorded. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RequirementRecord"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getProjectRequirements: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RequirementHistory"];
                };
            };
            404: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    postProjectRequirements: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RequirementChange"];
            };
        };
        responses: {
            /** @description Recorded. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RequirementRecord"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getReleaseRequirements: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RequirementHistory"];
                };
            };
            404: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    postReleaseRequirements: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RequirementChange"];
            };
        };
        responses: {
            /** @description Recorded. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RequirementRecord"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getReleaseResolvedRequirements: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResolvedRequirements"];
                };
            };
            404: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getProductTags: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TagSet"];
                };
            };
            404: components["responses"]["Problem"];
        };
    };
    putProductTags: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TagsPut"];
            };
        };
        responses: {
            /** @description Stored. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TagSet"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
        };
    };
    getProjectTags: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TagSet"];
                };
            };
            404: components["responses"]["Problem"];
        };
    };
    putProjectTags: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TagsPut"];
            };
        };
        responses: {
            /** @description Stored. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TagSet"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
        };
    };
    getReleaseTags: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TagSet"];
                };
            };
            404: components["responses"]["Problem"];
        };
    };
    putReleaseTags: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TagsPut"];
            };
        };
        responses: {
            /** @description Stored. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TagSet"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
        };
    };
    listTaggedReleases: {
        parameters: {
            query: {
                tag: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReleaseView"][];
                };
            };
            400: components["responses"]["Problem"];
        };
    };
    getBlastRadius: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BlastRadius"];
                };
            };
            400: components["responses"]["Problem"];
        };
    };
}
