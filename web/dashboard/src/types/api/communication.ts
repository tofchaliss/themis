// Generated from api/communication.openapi.yaml by scripts/gen-api.mjs. Do not edit.

export interface paths {
    "/publications": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List recorded Publications for a Release. */
        get: operations["listPublications"];
        put?: never;
        /** Trigger materialization of a Position into a recorded Publication (human-triggered). */
        post: operations["createPublication"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/publications/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get a recorded Publication (payload regenerated if pruned). */
        get: operations["getPublication"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/previews": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Render a Position into an artifact without recording a Publication. */
        post: operations["previewPublication"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/rollups": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List a release's VEX rollups, newest first (the full supersession history - D5 keeps both). */
        get: operations["listRollups"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/rollups/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one recorded rollup (metadata + the rendered document). */
        get: operations["getRollup"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases/{id}/rollup-status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The worklist staleness row (D13.2): the current rollup for (release, format, audience) and its computed drift against the live posture - exact, not approximated, thanks to the recorded input set. Republishing stays a human act. */
        get: operations["getRollupStatus"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/callbacks/ci-rebuild": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** CI rebuild callback (EDR-DELIVERY-01 M2-7). The build job Themis asked for reports the intent it served, the NEW SBOM it uploaded and the image it built. Accepted only from a key holding the `delivery:callback` scope and no other; recorded as governed-external evidence on the intent. It changes no Finding, no Position and no posture. */
        post: operations["recordCIRebuildCallback"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/reports/remediation-metrics": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The remediation-metrics report (EDR-REMEDIATION-01 D6), rendered on request from Governance's figures — markdown for people (default) or JSON for tools. Stored nowhere. Time to remediation and time to resolution are reported as two labelled measures, never merged (D8 Q4). */
        get: operations["getRemediationMetricsReport"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/webhook-health": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Health of each webhook destination that has been sent to (EDR-REMEDIATION-01 D4): active, active_tmp (a failure, retrying), inactive_tmp (paused after repeated failures, tried again after paused_until) or inactive_permanent (an operator re-enables it with `deliveryctl webhook-enable`). Destinations are audience names; URLs are never returned. */
        get: operations["getWebhookHealth"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/publishable-positions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The analyst worklist — Positions ready to publish or gone stale. */
        get: operations["getPublishableQueue"];
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
        WebhookHealth: {
            destination: string;
            /** @enum {string} */
            state: "active" | "active_tmp" | "inactive_tmp" | "inactive_permanent";
            consecutive_failures: number;
            /** Format: date-time */
            paused_until?: string;
            /** Format: date-time */
            last_success_at?: string;
            /** Format: date-time */
            last_failure_at?: string;
            last_error?: string;
        };
        CIRebuildCallback: {
            /** @description The ci_rebuild intent this build served (THEMIS_INTENT_ID as the job received it). */
            intent_id: string;
            /** @description The Evidence id of the NEW SBOM the job uploaded. Required (RC-3). */
            sbom_id: string;
            /** @description The built image's digest. Required (RC-3). */
            image_digest: string;
            /** @description The job's own build identifier, as given. */
            build_id?: string;
            /** @description The revision built, as given. */
            git_ref?: string;
        };
        CIRebuildCallbackAck: {
            intent_id: string;
            sbom_id: string;
            /** Format: date-time */
            received_at: string;
        };
        /** @description The subject is a UNION (EDR-COMMUNICATION-01 D13.5): exactly one of finding_id (a per-Position artifact, D3) or release_id (the release-scoped VEX rollup, D13 - only artifact_type `vex` is valid there). Supplying both or neither is a 400. */
        CreatePublicationRequest: {
            finding_id?: string;
            /** @description The release whose rollup to materialize (D13): one multi-statement document over the whole posture - statements from Positions only, machine clearances as annotations, full coverage, recorded input set. Refused (422) when the Registry name chain cannot identify the product (fail-closed, D13.4). */
            release_id?: string;
            /** @description vex | advisory | notification | audit_report */
            artifact_type: string;
            /** @description openvex | cyclonedx-vex | csaf | markdown | json-report | text */
            format: string;
            audience?: string;
            channel?: string;
        };
        CreatePublicationResponse: {
            /** @description The new record's id - a per-Finding Publication for a finding_id subject, a release rollup for a release_id subject (fetch the latter via GET /rollups/{id}). */
            publication_id?: string;
        };
        RollupView: {
            id?: string;
            release_id?: string;
            /** @description The Registry-derived customer-facing product identity (D13.4). */
            product_purl?: string;
            format?: string;
            audience?: string;
            /** @description The snapshot's vintage (RFC3339) - also stated inside the document itself. */
            as_of?: string;
            statements?: number;
            withdrawn_excluded?: number;
            supersedes_id?: string;
            superseded_by?: string;
            created_at?: string;
            /** @description The rendered document (e.g. the OpenVEX JSON), verbatim. */
            payload?: string;
        };
        RollupStatus: {
            /** @description false when no rollup was ever published for this (release, format, audience). */
            found?: boolean;
            publication_id?: string;
            as_of?: string;
            statements?: number;
            /** @description true when the live posture differs from the rollup's recorded input set - any new or removed finding, changed decision, or annotation-only change. */
            stale?: boolean;
            /** @description Plain-language drift summary ("current", or "STALE - 1 changed decision(s), ..."). */
            summary?: string;
            drift?: {
                changed_decisions?: number;
                new_findings?: number;
                removed_findings?: number;
                /** @description Same decision, different annotation fingerprint - minor drift (D13.2). */
                annotation_only?: number;
            };
        };
        /** @description Same subject union as CreatePublicationRequest - exactly one of finding_id / release_id. */
        PreviewRequest: {
            finding_id?: string;
            release_id?: string;
            artifact_type: string;
            format: string;
        };
        PreviewResponse: {
            payload?: string;
        };
        PublicationView: {
            id?: string;
            artifact_type?: string;
            stance?: string;
            format?: string;
            audience?: string;
            channel?: string;
            position_version?: number;
            release_id?: string;
            finding_id?: string;
            faultline_id?: string;
            cve?: string;
            delivery_status?: string;
            superseded?: boolean;
            payload?: string;
        };
        QueueEntryView: {
            finding_id?: string;
            release_id?: string;
            faultline_id?: string;
            cve?: string;
            version?: number;
            stance?: string;
            stale?: boolean;
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
    listPublications: {
        parameters: {
            query: {
                release: string;
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
                    "application/json": components["schemas"]["PublicationView"][];
                };
            };
            500: components["responses"]["Problem"];
        };
    };
    createPublication: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CreatePublicationRequest"];
            };
        };
        responses: {
            /** @description Created. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CreatePublicationResponse"];
                };
            };
            400: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    getPublication: {
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
                    "application/json": components["schemas"]["PublicationView"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    previewPublication: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PreviewRequest"];
            };
        };
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PreviewResponse"];
                };
            };
            400: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    listRollups: {
        parameters: {
            query: {
                release: string;
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
                    "application/json": components["schemas"]["RollupView"][];
                };
            };
            500: components["responses"]["Problem"];
        };
    };
    getRollup: {
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
                    "application/json": components["schemas"]["RollupView"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    getRollupStatus: {
        parameters: {
            query?: {
                format?: string;
                audience?: string;
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
                    "application/json": components["schemas"]["RollupStatus"];
                };
            };
            500: components["responses"]["Problem"];
        };
    };
    recordCIRebuildCallback: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CIRebuildCallback"];
            };
        };
        responses: {
            /** @description Recorded (or already recorded for this intent and SBOM). */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CIRebuildCallbackAck"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            409: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getRemediationMetricsReport: {
        parameters: {
            query?: {
                /** @description Keep only this Product (id or name); the estate figures are always included. */
                product?: string;
                /** @description Keep only Findings on releases carrying this tag (EDR-REMEDIATION-01 D7), estate figures included. */
                tag?: string;
                /** @description markdown (default) or json. */
                format?: string;
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
                    "text/markdown": string;
                    "application/json": Record<string, never>;
                };
            };
            400: components["responses"]["Problem"];
            502: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getWebhookHealth: {
        parameters: {
            query?: never;
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
                    "application/json": components["schemas"]["WebhookHealth"][];
                };
            };
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getPublishableQueue: {
        parameters: {
            query?: never;
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
                    "application/json": components["schemas"]["QueueEntryView"][];
                };
            };
            500: components["responses"]["Problem"];
        };
    };
}
