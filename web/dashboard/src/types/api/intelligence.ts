// Generated from api/intelligence.openapi.yaml by scripts/gen-api.mjs. Do not edit.

export interface paths {
    "/capabilities/{id}/invoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Invoke a named capability reactively (synchronous). */
        post: operations["invokeCapability"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/similar": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Past Enterprise Positions that resemble this Finding (semantic precedent, no AI).
         * @description The Operational Semantic Index (KS2, Δ3a) served directly to a human. It answers "what have we already decided that looks like this?" — semantically similar PAST Positions, typically on a DIFFERENT CVE affecting the same component, ranked by cosine similarity.
         *
         *     This is the same retrieval seam `recommend_position` grounds on. Serving both from one service is deliberate: an engineer and the model must never be shown different answers to the same question.
         *
         *     **No model runs.** There is no prompt, no token spend, no budget ceiling and nothing to hallucinate — so unlike `/capabilities/{id}/invoke` this endpoint does not have a "declined" outcome. An empty list means no precedent was found, which on a young deployment is the ordinary answer.
         *
         *     **Read-only and advisory** (output class Information, EDR-TRUST-01 T7): it proposes no stance, reaches no Position, and nothing here needs accepting. Themis stays authoritative — every result points back to the Position it was derived from, and the index is a derived, rebuildable lens over that truth, never truth itself.
         *
         *     Contradictory results are a feature, not a fault. Where the enterprise ruled the same shape of problem two different ways, both appear — which is precisely the case in which `recommend_position` honestly declines, and precisely what a human needs to see.
         */
        get: operations["getSimilarFindings"];
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
        SimilarFindings: {
            /** @description The subject Finding the query was composed from. */
            finding_id: string;
            /** @description Ranked precedent, most similar first. Empty when none was found. */
            precedents: components["schemas"]["PrecedentPosition"][];
        };
        /** @description One past Enterprise Position, retrieved as precedent. Every field traces back to a Position that Themis owns — this is a lens over KS1, not a record in its own right. */
        PrecedentPosition: {
            /** @description The Release the past decision was taken on. */
            release_id: string;
            /** @description The decided stance (e.g. affected, not_affected, accepted_risk). */
            stance: string;
            /** @description CVE of the precedent decision. It usually DIFFERS from the subject's CVE — matching across CVEs on a shared component is the whole point of semantic precedent. */
            source_cve?: string;
            /** @description Representative component of the precedent decision. */
            component?: string;
            /** @description Why that decision was taken, passed through the node's redaction boundary before leaving the process. The stored Position is never modified by redaction. */
            rationale?: string;
            /**
             * Format: double
             * @description Cosine similarity in [0,1] for a semantically retrieved precedent. 0 marks an exact-CVE match, which is found by lookup rather than by similarity and therefore has no meaningful score — not "least similar".
             */
            score?: number;
            /**
             * Format: double
             * @description G-AI-3 delta signal - posture overlap in [0,1] between the precedent's release and the subject's, from the deterministic comparison read (EDR-GOVERNANCE-01 D16): persisting / (fixed + new + persisting). Absent when the comparison could not be computed - an unknown delta leaves the precedent unweighted, never penalized. The ranking you receive is already weighted by it (down-weight only, never dropped).
             */
            release_overlap?: number;
        };
        /** @description An answer rendered for a human (EDR-TRUST-01 T7). It is **ephemeral**: it is not recorded as enterprise truth, there is nothing to accept or reject, and no Governance stage follows it — which is why Grounding Verification is its only gate and is treated as load-bearing. */
        InformationResponse: {
            /** @description The originating capability ref, e.g. "plan_remediation@v1". */
            capability?: string;
            /** @description What the answer is about — a Release id for a release-scoped capability. */
            subject_id?: string;
            /** @description The answer itself. Any identifier the prose names that was NOT in the model's grounding is flagged inline with an `[UNVERIFIED MENTIONS ...]` caveat rather than carried in a separate field — prose cannot be schema-checked, and a caveat stored elsewhere is one a reader can miss (TRUST-8). */
            information?: string;
            /**
             * @description How many past Enterprise Positions grounded this recommendation — semantic neighbours retrieved from the Operational Semantic Index (Delta-3a) plus any exact-CVE fallback.
             *     It is the only externally visible evidence that the retrieval plane contributed at all. A caller comparing two recommendations cannot otherwise tell whether the enterprise's own decision history was consulted, which makes the claim that it changes outcomes unfalsifiable from outside.
             */
            precedents_used?: number;
            /** @description Which plan step produced it, e.g. "llm:information" or "rule:nothing-outstanding". */
            decided_by?: string;
            correlation_id?: string;
        };
        /** @description Invoke a capability against a Selection - a user-addressable entry point plus the identifiers picked (EDR-TRUST-01 T9). Supply either `subject` or the deprecated `finding_id`; `subject` wins if both are present. */
        InvokeRequest: {
            subject?: components["schemas"]["Selection"];
            /**
             * @deprecated
             * @description Deprecated alias for `subject: {type: finding, ids: [<id>]}`. Accepted for one release so existing callers keep working while they migrate; remove after.
             */
            finding_id?: string;
            /** @description Optional correlation id for telemetry; generated if absent. */
            correlation_id?: string;
        };
        /** @description What the capability is invoked against. `ids` is a set because a user may pick several things of one kind (e.g. several Findings for a VEX draft); how many a given capability accepts is that capability's declared cardinality, enforced before any grounding is assembled. */
        Selection: {
            /**
             * @description The user-addressable entry point. Not a domain entity - see EDR-TRUST-01 T9.
             * @enum {string}
             */
            type: "finding" | "release";
            ids: string[];
        };
        Proposal: {
            capability?: string;
            finding_id?: string;
            stance?: string;
            confidence?: number;
            evidence?: components["schemas"]["Evidence"][];
            reasoning?: string;
            /** @description Identifier-shaped tokens the free-text `reasoning` names that the authoritative grounding does NOT contain (EDR-TRUST-01 T8). ADVISORY — the proposal's structured `evidence` already passed Grounding Verification, so this does not invalidate it; it marks that the narrative cites ids nobody supplied, which is the failure a reviewer cannot see. Absent/empty means no ids were invented, NOT that the narrative is true — prose is not verifiable and is never claimed to be. */
            rationale_warnings?: string[];
            provider?: string;
            model?: string;
            /**
             * @description How many past Enterprise Positions grounded this recommendation — semantic neighbours retrieved from the Operational Semantic Index (Delta-3a) plus any exact-CVE fallback.
             *     The only externally visible evidence that the retrieval plane contributed. Without it a caller cannot tell whether the enterprise's own decision history was consulted, which leaves the claim that it changes outcomes unfalsifiable from outside.
             */
            precedents_used?: number;
            /** @description Which plan step decided — "rule:<stance>" or "llm:<stance>". */
            decided_by?: string;
            correlation_id?: string;
        };
        Evidence: {
            kind?: string;
            ref?: string;
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
    invokeCapability: {
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
                "application/json": components["schemas"]["InvokeRequest"];
            };
        };
        responses: {
            /** @description The capability's result. Which shape depends on the capability's declared OUTPUT CLASS (EDR-TRUST-01 T7): a **Decision** capability returns a validated advisory `Proposal` that may enter Governance; an **Information** capability returns an `InformationResponse` — an answer rendered for a human that is ephemeral and can never become enterprise truth. The two are distinguished by which field is present. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Proposal"] | components["schemas"]["InformationResponse"];
                };
            };
            /** @description No proposal (declined, ungrounded, or unavailable) — a safe outcome. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    getSimilarFindings: {
        parameters: {
            query?: {
                /** @description Maximum neighbours to return (1-50). Omitted uses the node's configured default. */
                k?: number;
                /** @description Keep the subject's own Release in the candidate set. Off by default: a Finding is not precedent for itself, and its siblings on the same Release were usually decided in one sitting. Set it to ask the different question "what else did we decide on this release?". */
                include_same_release?: boolean;
            };
            header?: never;
            path: {
                /** @description Finding id — the subject whose Assessment projection composes the query. */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Ranked precedent, most similar first. An empty list means none was found. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SimilarFindings"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
}
