// Generated from api/evidence.openapi.yaml by scripts/gen-api.mjs. Do not edit.

export interface paths {
    "/evidence": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List evidence filed against a release. */
        get: operations["listEvidence"];
        put?: never;
        /** Register an evidence document; returns a stable Evidence ID. */
        post: operations["registerEvidence"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/evidence/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get evidence facts by ID. */
        get: operations["getEvidence"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/evidence/{id}/inventory": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the canonical component inventory by evidence ID. */
        get: operations["getEvidenceInventory"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/evidence/{id}/document": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the raw stored document (bytes as UTF-8 text) + kind by evidence ID. Used by Knowledge to parse an uploaded VEX (Evidence serves the bytes, never parses them). */
        get: operations["getEvidenceDocument"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/intake": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * The single intake door (EDR-INTAKE-01 D1): submit an SBOM or a vulnerability report as the RAW body, with the metadata as query parameters.
         * @description The body IS the artifact — unwrapped, so `--data-binary @file` is the whole client and a 60 MB SBOM streams instead of being JSON-escaped into an envelope (see the change's design, "Why the body is raw and the metadata is query parameters"). `kind` and `format` are DETECTED from the body (D5a) and echoed back as `detected_kind` / `detected_format`.
         *
         *     Every outcome is a receipt (D9): `201`/`200` when the work finished inline, `202` when it exceeded `THEMIS_INTAKE_INLINE_BUDGET` and continues server-side, and a refusal naming itself from the closed taxonomy (D11). `POST /evidence` is unchanged and remains the raw, release-id-only door.
         */
        post: operations["submitIntake"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/intake/{intakeId}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one intake attempt's receipt (D9) — every intake is addressable, including a refused one. */
        get: operations["getIntakeReceipt"];
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
        RegisterEvidenceRequest: {
            /** @enum {string} */
            kind: "sbom" | "vex" | "scanner-report";
            /** @enum {string} */
            format?: "cyclonedx" | "spdx";
            spec_version?: string;
            subject_release_id: string;
            expected_checksum?: string;
            provenance_source?: string;
            provenance_image_digest?: string;
            /** @description The raw evidence document (UTF-8 text, e.g. an SBOM JSON). */
            document: string;
        };
        RegisterEvidenceResponse: {
            id: string;
            created: boolean;
        };
        EvidenceFacts: {
            id?: string;
            kind?: string;
            subject_release_id?: string;
            fingerprint?: string;
            trust_status?: string;
            provenance_source?: string;
            provenance_image_digest?: string;
            /** Format: date-time */
            filed_at?: string;
        };
        EvidenceSummary: {
            id?: string;
            kind?: string;
            fingerprint?: string;
            /** @description Who produced the document (e.g. the scanner tool name) — labeling only, never authority (EDR-GUI-01 D14). Empty when the uploader did not say. */
            provenance_source?: string;
            /** Format: date-time */
            filed_at?: string;
        };
        Document: {
            /** @description The evidence kind (sbom | vex | scanner-report). */
            kind: string;
            /** @description The raw stored document bytes as UTF-8 text. */
            document: string;
        };
        Inventory: {
            components?: components["schemas"]["Component"][];
            dependencies?: components["schemas"]["DependencyEdge"][];
        };
        Component: {
            purl?: string;
            name?: string;
            version?: string;
            ecosystem?: string;
            source?: string;
        };
        DependencyEdge: {
            from?: string;
            to?: string;
            relationship?: string;
        };
        Problem: {
            title?: string;
            detail?: string;
            supported_formats?: string[];
        };
        /**
         * @description The CLOSED taxonomy of intake refusals (EDR-INTAKE-01 D11), identical to `internal/evidence/domain.RejectReason`. Adding a value is a contract change with a guard test: a consumer that knew 6 of 15 reasons reported "no reason given" for the other nine (#116).
         *
         *     There is deliberately no `inventory_not_ready`: Evidence has no window in which it holds an SBOM whose inventory is pending, so the value could never fire, and a closed enum with a dead value is worse than no value (D6).
         *
         *     The last four are the 2026-10-12 amendment's (B2/B4/B5 and its status-code table), appended so no existing value moves.
         * @enum {string}
         */
        RejectReason: "unknown_release" | "no_inventory_for_release" | "unrecognised_format" | "declared_format_mismatch" | "malformed_body" | "source_invalid" | "schema_invalid" | "empty_report" | "observed_at_underivable" | "observed_at_invalid" | "conversion_failed" | "checksum_mismatch" | "duplicate_other_release" | "payload_too_large" | "too_many_records" | "unauthorized" | "create_release_conflict" | "incomplete_release_triple" | "ambiguous_name" | "build_id_invalid";
        /**
         * @description Where one intake attempt has got to (D9). The ladder is forward-only and its three terminals are `filed`, `rejected` and `failed`.
         * @enum {string}
         */
        ReceiptStatus: "accepted" | "validating" | "converting" | "registering" | "filed" | "rejected" | "failed";
        /** @description Who answers "did the work land" (D10). The receipt is terminal at `filed` and does NOT claim correlation is complete — Knowledge owns correlation, and asking Evidence to poll it would invent the coupling the bus exists to avoid. */
        NextCheck: {
            /** @enum {string} */
            what: "unresolved" | "posture";
            url: string;
        };
        /** @description The record of one intake attempt. Every intake is addressable, including a refused one: a rejected receipt is the thing that was missing on 2026-10-05. */
        IntakeReceipt: {
            intake_id: string;
            status: components["schemas"]["ReceiptStatus"];
            reason?: components["schemas"]["RejectReason"];
            /** @description The refusal's or failure's elaboration. NEVER concatenated with `reason`: a consumer switches on the reason and displays the detail (the 2026-09-22 lesson). */
            detail?: string;
            /** @description The filed document's identity. Present only when the status is `filed`. */
            evidence_id?: string;
            /** @description False when filing resolved to the document already held (a dedup, D8). */
            created?: boolean;
            /** @description Empty when the attempt was refused before the release was resolved. */
            release_id?: string;
            /** @description What the body was identified as (D5a) — `sbom` or `vuln-report`. */
            detected_kind?: string;
            /** @description The dialect (`spdx`, `cyclonedx`, `curated`, `trivy`, `grype`, `nessus`, `nessus-csv`, `cortex-json`, `cortex-csv`). A `nessus` SBOM is filed as the CycloneDX document it converts to. */
            detected_format?: string;
            /** @description Source records the conversion CONSIDERED. Reported beside `findings_skipped`, never alone: "427 of 427" and "427 of 500" must not look alike. */
            findings_total?: number;
            findings_skipped?: number;
            /** @description Components the filed SBOM's canonical inventory carries. */
            components?: number;
            /** @description Package lines a converted SBOM left out because no identity could be read for them (another vendor's package, an OS Themis does not map, a name that does not split) — EDR-INTAKE-01 2026-10-26 P4. Zero for an SBOM filed as submitted. */
            components_skipped?: number;
            /** @description Hand-installed components a converted SBOM filed beside the packages — software no package manager owns, found by the scanner's detection plugins under the EDR-INTAKE-01 2026-10-27 H1 rule (a path outside the rpm trees, no package mark, no RPM of that product). Zero for every other submission. */
            components_unmanaged?: number;
            /** @description Lowercase-hex SHA-256 of the SUBMITTED bytes (which, for a converted submission, are not the filed bytes). */
            source_digest?: string;
            /** @description The converter and its version (`cortex@1`); empty for a pass-through. */
            converted_by?: string;
            /** @description The `build_id` THIS attempt submitted (B5). A receipt records an attempt and the evidence row records what was filed, so on a byte-identical retry — which dedups and keeps the FIRST upload's provenance — the two differ by design. */
            build_id?: string;
            /** Format: date-time */
            created_at?: string;
            /** Format: date-time */
            updated_at?: string;
            status_url: string;
            /** @description Present on a `202` — how long to wait before reading `status_url`. */
            retry_after_seconds?: number;
            /** @description Present on a terminal `filed` receipt, and omitted entirely when the base URLs are unset — never a broken URL. */
            next_checks?: components["schemas"]["NextCheck"][];
        };
        /** @description A refusal, naming itself. `reason` and `detail` are TWO fields and are never concatenated (D9/D11). */
        IntakeProblem: {
            title: string;
            status: number;
            reason?: components["schemas"]["RejectReason"];
            detail: string;
            /** @description The receipt this refusal was recorded on — readable at `GET /intake/{intakeId}`. */
            intake_id?: string;
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
        /** @description The intake refused the submission, by name. Nothing was filed — stages 1-6 are side-effect-free, so the attempt leaves a `rejected` receipt and nothing else (D13). */
        IntakeProblem: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["IntakeProblem"];
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
    listEvidence: {
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
                    "application/json": components["schemas"]["EvidenceSummary"][];
                };
            };
            400: components["responses"]["Problem"];
        };
    };
    registerEvidence: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RegisterEvidenceRequest"];
            };
        };
        responses: {
            /** @description Already registered (idempotent — byte-identical upload to the SAME release). */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RegisterEvidenceResponse"];
                };
            };
            /** @description Registered (new). */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RegisterEvidenceResponse"];
                };
            };
            400: components["responses"]["Problem"];
            /** @description Byte-identical content is already filed against a DIFFERENT release — this release received nothing (D3 note; a new build needs its own document). */
            409: {
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
    getEvidence: {
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
                    "application/json": components["schemas"]["EvidenceFacts"];
                };
            };
            404: components["responses"]["Problem"];
        };
    };
    getEvidenceInventory: {
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
                    "application/json": components["schemas"]["Inventory"];
                };
            };
            404: components["responses"]["Problem"];
        };
    };
    getEvidenceDocument: {
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
                    "application/json": components["schemas"]["Document"];
                };
            };
            404: components["responses"]["Problem"];
        };
    };
    submitIntake: {
        parameters: {
            query?: {
                /** @description The release this document is about, named directly. Wins over the triple. */
                release_id?: string;
                /** @description With `project` and `version`, names the release by its triple — resolved READ-ONLY (D7). Intake never creates Registry identity. */
                product?: string;
                project?: string;
                version?: string;
                /** @description With the WHOLE triple (`product`, `project`, `version`), find-or-create the Release instead of refusing an unknown version (EDR-INTAKE-01 B2). Rejected alongside `release_id` (`create_release_conflict`) and with an incomplete triple (`incomplete_release_triple`). Products and Projects are still resolved read-only — intake creates versions, never identity. */
                create_release?: boolean;
                /** @description D6's deliberate override: file a vulnerability report for a release with no SBOM-derived inventory. Recorded in provenance, so a release in that state says so. */
                allow_without_sbom?: boolean;
                /** @description The kind the caller declares the body to be (D5a). Checked against the body, never obeyed over it: a body that cannot be the declared kind is `declared_format_mismatch`. A Nessus `.nessus` export is both, so this picks the road (2026-10-26 P1): omitted or `sbom` files its package list as the release's SBOM; `vuln-report` files its findings. */
                kind?: "sbom" | "vuln-report";
                /** @description RFC 3339 assertion about WHICH observation this is (D3). Omitted, the timestamp is derived from the submitted data; it is never the upload time. A Nessus CSV carries no scan date, so it needs this (2026-10-26 C3). */
                observed_at?: string;
                /** @description Lowercase-hex SHA-256 of the SUBMITTED bytes. Verified at the border, because for a converted submission the filed bytes are not the submitted ones (D2). */
                expected_checksum?: string;
                /** @description Who produced the document — labeling only, never authority. */
                provenance_source?: string;
                provenance_image_digest?: string;
                /** @description Which pipeline run produced this document — stored as artifact provenance and echoed on the receipt (EDR-INTAKE-01 B5). Deliberately inert: nothing reads it for dedup, correlation or current-SBOM selection. The bound is 256 **Unicode code points**, not bytes, so the spec and the code count the same thing; over the bound or not valid UTF-8 is `build_id_invalid`, refused and never truncated. */
                build_id?: string;
            };
            header?: {
                /** @description Client-asserted retry identity (D12). The same key within the receipt TTL returns the ORIGINAL receipt instead of starting new work. */
                "Idempotency-Key"?: string;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": string;
                "text/csv": string;
                "application/xml": string;
                "application/octet-stream": string;
            };
        };
        responses: {
            /** @description Filed inline, resolving to the document already held — a byte-identical re-submission to the SAME release (D8). `created` is false. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IntakeReceipt"];
                };
            };
            /** @description Filed inline, a new evidence document. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IntakeReceipt"];
                };
            };
            /** @description Over the inline budget (D9): the receipt is returned immediately and the work continues server-side. Come back to `status_url`. */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IntakeReceipt"];
                };
            };
            400: components["responses"]["IntakeProblem"];
            401: components["responses"]["IntakeProblem"];
            404: components["responses"]["IntakeProblem"];
            409: components["responses"]["IntakeProblem"];
            413: components["responses"]["IntakeProblem"];
            415: components["responses"]["IntakeProblem"];
            422: components["responses"]["IntakeProblem"];
            /** @description Themis could not carry the attempt out — a statement about Themis, not about the document, so the receipt is `failed` and carries no reason. */
            500: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IntakeProblem"];
                };
            };
            /** @description The bounded intake backlog is full. Nothing was filed and NO receipt was created, so the whole request is safe to retry after `Retry-After`. This is a service condition, not a document refusal, so it carries no reason from the closed taxonomy. */
            503: {
                headers: {
                    /** @description Seconds to wait before retrying. */
                    "Retry-After"?: number;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getIntakeReceipt: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                intakeId: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The receipt as it stands. Terminal at `filed` — which does NOT claim correlation is complete; `next_checks` names who answers that (D10). */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IntakeReceipt"];
                };
            };
            404: components["responses"]["Problem"];
        };
    };
}
