// Generated from api/governance.openapi.yaml by scripts/gen-api.mjs. Do not edit.

export interface paths {
    "/findings": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get a Finding by its (Release, Faultline) business key. */
        get: operations["getFindingByKey"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get a Finding by its identity (with Position history + Proposals). */
        get: operations["getFinding"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/position": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get a Finding's current (or a specific) Enterprise Position version. */
        get: operations["getPosition"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/watches": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Every Watch (EDR-INCIDENT-01 D2), newest first. A Watch is a named, operator-owned list of CVE and vendor advisory ids whose per-(release, CVE) state is computed on read. Read scope. */
        get: operations["listWatches"];
        put?: never;
        /** Create a Watch from a name and pasted identifiers (CVE-… and RHSA-/RHBA-/RHEA-… ids, any separator, any case). Write scope. Tokens not recognised are returned, never silently dropped; a text with none recognised is refused. The creator is the authenticated key, or `created_by` when the node runs without auth. */
        post: operations["createWatch"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/watches/{watchId}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** One Watch as stored (its identifiers and the CVE set they last resolved to). */
        get: operations["getWatch"];
        put?: never;
        post?: never;
        /** Delete a Watch whole. Admin scope. Nothing else changes - a Watch holds no truth. */
        delete: operations["deleteWatch"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/watches/{watchId}/identifiers": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Append identifiers to a Watch (append-only: add, never drop). Write scope. Returns the Watch with how many were new and which tokens were not recognised. */
        post: operations["addWatchIdentifiers"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/watches/{watchId}/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The Watch's table, computed NOW (EDR-INCIDENT-01 D2): one row per (release, CVE) over every release that has a Finding for any watched CVE. State: not_affected (no component matches, or a not_affected Position stands) · open_no_fix · open_fix_available · fixed (every occurrence cleared by evidence) · accepted (accepted_risk / mitigated / deferred stands) · unknown (no card for the CVE, or the advisory resolved to nothing). Nothing is stored but the CVE set the identifiers resolved to. Read scope. 503 when the Knowledge seam is not configured: "cannot tell" must not read as "nothing is affected". */
        get: operations["getWatchStatus"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/scope-targets": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Preview who a decision of the given scope on this Finding would reach now (EDR-SYNC-01 D7): the same CVE, the same component, undecided, on the releases of the same project or product. Read scope. 503 when no Registry seam is configured (the owners cannot be resolved, and "nobody" must not be answered for "cannot tell"). */
        get: operations["getScopeTargets"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/proposals": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Raise a Governance Proposal against a Finding (proposer only, no authority). */
        post: operations["raiseProposal"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/proposals/{proposalId}/accept": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Accept a proposal, establishing a new Enterprise Position (authorized decider only). */
        post: operations["acceptProposal"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/proposals/{proposalId}/reject": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Reject a proposal (authorized decider only). */
        post: operations["rejectProposal"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/resolve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Close a Finding's concern (reopenable). */
        post: operations["resolveFinding"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/reopen": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Reopen a Monitoring/Resolved Finding for further investigation. */
        post: operations["reopenFinding"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/archive": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Archive a Finding (terminal — release retired). */
        post: operations["archiveFinding"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/commissions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Commission governed AI-runtime work against a Finding BEFORE it runs (EDR-HARNESS-01 D-C-1). An authenticated human authority act: records the exact method and deployment identities the runtime must execute under; changes no investigation stage. Returns the Themis-minted commission id the runtime carries verbatim. */
        post: operations["commissionFinding"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/commissions/{commissionId}/withdraw": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Withdraw a commission (forward-only, D-C-3). Historical executions under it stay inspectable evidence; future proposals citing it are refused. */
        post: operations["withdrawCommission"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/recommend": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** On-demand — ask the Intelligence Gateway for an advisory position recommendation. Records an AI proposal (never auto-accepted); AI absence/failure yields 204. */
        post: operations["recommendPosition"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/assessment": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Domain Projection - everything needed to assess one Finding: the release-scoped concern plus what is known about the CVE it rests on (EDR-TRUST-01 T10). Named for the business view, never for a consumer; a dashboard, a report and the AI Runtime all read the same projection. Deterministic and self-contained, so it replays as a test fixture. The knowledge half is best-effort - an unreachable Knowledge degrades to the Finding alone rather than failing the projection. */
        get: operations["getFindingAssessment"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/severity": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The severity of one Finding as a person decides it (EDR-SCORING-01 section 7.1): the original score and vector, the owner-set severity in force (if any) and the history of every owner-set severity. Read scope. */
        get: operations["getFindingSeverity"];
        /** Set the owner-set severity of one Finding (OS1-OS4). Admin only. The body gives a reason and exactly one of a level or a changed CVSS 3.0 / 3.1 vector; Themis computes the score either way. From the moment it is saved the owner-set score is what priority, the remediation deadline and the lists read; the original is kept beside it. `apply_to` sets the same on other Findings of the same CVE in the same product, all or nothing; one that already has an owner-set severity is replaced (its record stays in the history). */
        put: operations["setFindingSeverity"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/severity/remove": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Remove the owner-set severity of one Finding (OS2). Admin only. The original score counts again; the record stays in the history. 404 when there is none to remove. */
        post: operations["removeFindingSeverity"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/severity/keep": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Keep the owner-set severity after the original changed (OS6). Admin only. The severity is not touched; the record notes who kept it and when, and the original they saw becomes what the next change is measured against. 404 when there is none in force, 409 when the original did not change. */
        post: operations["keepFindingSeverity"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/severity/preview": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Compute what a level or a changed vector would give on this Finding. Records nothing. Read scope. */
        post: operations["previewFindingSeverity"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/severity/targets": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The pick list of an owner-set severity (OS3): every other Finding of the same CVE in the same product, with the owner-set severity it carries now. Never another product. 503 when no Registry seam is configured. */
        get: operations["getFindingSeverityTargets"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{id}/score": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** How Themis got this score (EDR-SCORING-01 S4, shadow): the Finding roll-up and, per current component, the newest ComponentAssessment revision with its complete candidate snapshot (every source publication with its applicability, class, disposition and reason; the identity roles; outcome, conditions, score status; metrics with state; CR / IR / AR with level), plus the revision history. Read only. Nothing reads these numbers for priority or SLA yet. 200 with no rollup means "not yet assessed". */
        get: operations["getFindingScore"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases/{releaseId}/posture": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List all Findings + current Positions for a Release (posture rollup). */
        get: operations["getReleasePosture"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases/{releaseId}/upload-outcome": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** What the Release's most recent new SBOM changed (EDR-REMEDIATION-01 D3) — new, reappeared, no longer present and unchanged, against the SBOM filed immediately before it. A report, never a state. 404 when no outcome has been stated for this Release yet. */
        get: operations["getReleaseUploadOutcome"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases/{releaseId}/compare/{candidateId}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Diff two releases' postures by CVE — fixed / new / persisting (EDR-GOVERNANCE-01 D16, IDEA-1's read half). "Fixed" is absence proven by new evidence, so the read refuses (422) when either release has no evidence filed, and refuses (502) when Evidence cannot be asked — it never fails open. */
        get: operations["compareReleases"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/events/release-evaluated": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Cursor read of the release-evaluated event feed (EDR-DELIVERY-01 M2-4). Rows strictly after the `after` sequence, in sequence order; `limit` defaults to 100 and is clamped to 500. At-least-once — a subscriber deduplicates on `event_id` and stores `next` as its cursor. Read scope. */
        get: operations["getReleaseEvaluatedEvents"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/metrics/remediation": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Remediation metrics (EDR-REMEDIATION-01 D6), estate-wide and per Product: open Findings by age band and severity, the share within SLA and the number breached now, mean time to decision, and two remediation measures kept apart — time to remediation (creation to the first evaluated SBOM that no longer carried it, counted only when a person decided afterwards, D8 Q4) and time to resolution (creation to a person resolving it). Read scope. */
        get: operations["getRemediationMetrics"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/sla-policy": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The SLA policy (EDR-REMEDIATION-01 D1) - days to fix per severity bucket with an enforce switch, for the estate and any per-Product overrides. With nothing stored the estate reads the shipped defaults (7 / 30 / 90 / 180 days, all enforced). Read scope. */
        get: operations["getSLAPolicy"];
        /** Store the estate SLA policy (scope omitted or empty) or one Product's override (scope = the Product id). Admin scope only. A deadline already running for a Finding moves with the policy, because the due date is derived, never stored; the frozen severity bucket does not move (D8 Q1). */
        put: operations["putSLAPolicy"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/rebuild-policy": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The installation rebuild policy (EDR-REBUILD-01 D2) - the fixed-field record that says when an image rebuild is worth asking for. With nothing stored it reads the shipped defaults at version 0. Read scope. Step R1 stores the record only - nothing is evaluated against a Release and no build is asked for yet. */
        get: operations["getRebuildPolicy"];
        /** Store a new version of the installation rebuild policy. Admin scope only, and the change must name its actor (D9). Every field is required - a switch left out is refused, never read as off. Each change adds one to the version and is kept in the history. */
        put: operations["putRebuildPolicy"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/rebuild-policy/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Every stored version of the installation rebuild policy, newest first, with who changed it and when (EDR-REBUILD-01 D9). Empty when the policy was never set. Read scope. */
        get: operations["getRebuildPolicyHistory"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/rebuild-policies": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Every rebuild policy in force in the installation on one page (EDR-REBUILD-01 D11 item 3) - the installation policy first, then the Product policies, then the Release policies. Read scope. */
        get: operations["listRebuildPolicies"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/products/{productId}/rebuild-policy": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The rebuild policy stored for this Product (EDR-REBUILD-01 D11). 404 when the Product has none and takes the installation policy. Read scope. */
        get: operations["getProductRebuildPolicy"];
        /** Store a new version of this Product's rebuild policy. The record is whole - it takes no single field from the level above (D11 item 2). Admin scope, or that Product's own `product:<id>` key. The change must name its actor and carry every field. A Product policy can lower the mode and can never lift it above the installation policy's (D17). */
        put: operations["putProductRebuildPolicy"];
        post?: never;
        /** Remove this Product's rebuild policy, so the Product takes the installation policy again. Admin scope, or that Product's own `product:<id>` key. The removal is kept in the history with its actor. 404 when there is none. */
        delete: operations["deleteProductRebuildPolicy"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/products/{productId}/rebuild-policy/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Every version of this Product's rebuild policy, newest first, removals included. Read scope. */
        get: operations["getProductRebuildPolicyHistory"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases/{releaseId}/rebuild-policy": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The rebuild policy stored for this Release (EDR-REBUILD-01 D11). 404 when the Release has none and takes its Product's policy or the installation policy. Read scope. */
        get: operations["getReleaseRebuildPolicy"];
        /** Store a new version of this Release's rebuild policy. The record is whole - it takes no single field from the level above (D11 item 2). Admin scope, or the `product:<id>` key of the Product that owns the Release. The change must name its actor and carry every field. A Release policy can lower the mode and can never lift it above the installation policy's (D17). */
        put: operations["putReleaseRebuildPolicy"];
        post?: never;
        /** Remove this Release's rebuild policy, so the Release takes its Product's policy or the installation policy again. Admin scope, or the `product:<id>` key of the Product that owns the Release. The removal is kept in the history with its actor. 404 when there is none. */
        delete: operations["deleteReleaseRebuildPolicy"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases/{releaseId}/rebuild-policy/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Every version of this Release's rebuild policy, newest first, removals included. Read scope. */
        get: operations["getReleaseRebuildPolicyHistory"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases/{releaseId}/rebuild-policy/in-force": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The rebuild policy that applies to this Release and the level it comes from - the Release's own, else its Product's, else the installation's (EDR-REBUILD-01 D11 item 3) - with the highest mode the policies allow (D17). 503 when the Release's Product cannot be read from Registry - the installation policy is never shown in place of a Product policy that could not be looked up. Read scope. */
        get: operations["getReleaseRebuildPolicyInForce"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/faultlines/{faultlineId}/findings": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Every release's Finding for one Faultline (one CVE), as posture rows (EDR-GUI-02 D13).
         * @description The cross-release read behind the GUI's per-CVE releases dropdown: one row per release the CVE is filed under, each the same row that release's posture serves (priority, SLA, components, decision), plus release_id, decided_by_kind and decided_at. Read scope. An unknown Faultline answers an empty list. Release names are Registry's, not here.
         */
        get: operations["getFaultlineFindings"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/faultlines/{faultlineId}/blast-radius": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the Releases affected by a Faultline (blast-radius rollup). */
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
        FindingView: {
            id?: string;
            release_id?: string;
            faultline_id?: string;
            cve?: string;
            stage?: string;
            components?: components["schemas"]["Component"][];
            current_position?: components["schemas"]["PositionView"];
            disposition_stale?: components["schemas"]["DispositionStale"];
            positions?: components["schemas"]["PositionView"][];
            proposals?: components["schemas"]["ProposalView"][];
            /** @description Authority records for governed AI-runtime work against this Finding (EDR-HARNESS-01). Append-only; open or withdrawn. Never served to the runtime's model (the harness read door projects them out). */
            commissions?: components["schemas"]["CommissionView"][];
        };
        CommissionView: {
            id?: string;
            skill?: string;
            composition_sha256?: string;
            anchor?: string;
            artifact_sha256?: string;
            commissioned_kind?: string;
            commissioned_id?: string;
            premise_stage?: string;
            premise_position_version?: number;
            rationale?: string;
            /** Format: date-time */
            raised_at?: string;
            /** @description open | withdrawn */
            state?: string;
            withdrawn_kind?: string;
            withdrawn_id?: string;
            /** Format: date-time */
            withdrawn_at?: string;
            withdrawal_rationale?: string;
        };
        CommissionRequest: {
            /** @description runtime method name@version (opaque to Themis) */
            skill: string;
            composition_sha256: string;
            /** @description runtime deployment name@version (opaque to Themis) */
            anchor: string;
            artifact_sha256: string;
            rationale?: string;
            /** @description DEVELOPMENT commissioner identity, used only when inbound auth is disabled (recorded with a `dev:` prefix). Ignored when the request is authenticated: the recorded actor is derived from the API key's principal as `key:<key-id>` (EDR-SECURITY-01 D10). */
            actor_id?: string;
        };
        CommissionResponse: {
            commission_id?: string;
        };
        WithdrawCommissionRequest: {
            rationale?: string;
            /** @description DEVELOPMENT identity; ignored when authenticated. */
            actor_id?: string;
        };
        /** @description harness-execution/v1 — the immutable evidence a proposal rests on when its basis is a commissioned AI-runtime execution (EDR-HARNESS-01 D-I-5). Every field was DERIVED by Themis's own intake CLI from the runtime record; Governance validates the shape and the correspondence to the cited commission, and never re-reads the runtime record. */
        HarnessExecutionEvidence: {
            commission_id: string;
            anchor_hash: string;
            anchor: string;
            anchor_state_at_intake: string;
            task_id: string;
            /** Format: int64 */
            artifact_bound_seq: number;
            artifact_object_id: string;
            verified_member_path: string;
            verified_member_sha256: string;
            skill: string;
            skill_composition_sha256: string;
            contract: string;
            contract_sha256: string;
            contract_state_at_intake: string;
            /** @description consistent-pass */
            reconstruction: string;
            /** @description l5-witnessed (Position-eligible) */
            production_witness: string;
            constitution_hash: string;
            harness_module: string;
            delegation_count: number;
            delegation_seqs: number[];
            /** @description Identifiers from the RECORDED Finding bytes the execution read (dependency PURL, CVE); Business-Verified against the Finding. */
            business_refs: string[];
        };
        /** @description Present when the current SUPPRESSING Position has been re-surfaced (EDR-GOVERNANCE-01 D14, RF-2): its premise drifted (KEV, a public exploit, an EPSS rise) or its review-by date passed, and nobody has re-decided since. While present, residual_priority equals effective_priority — the Finding is back in the queue — and `reason` says why in words. A new accepted proposal clears it. Absent = not re-surfaced. */
        DispositionStale: {
            /** Format: date-time */
            since: string;
            reason: string;
        };
        PositionView: {
            version?: number;
            stance?: string;
            rationale?: string;
            actor_kind?: string;
            actor_id?: string;
            accepted_proposal_id?: string;
            faultline_ref?: string;
            /** Format: date-time */
            established_at?: string;
            /**
             * Format: date-time
             * @description The date this decision asked to be revisited; absent when none was agreed.
             */
            review_by?: string;
            /** @description The accountable owner of an accepted risk (EDR-REMEDIATION-01 D2); absent when none. */
            owner?: string;
            /**
             * @description How an accepted risk is handled (D2); absent when not stated.
             * @enum {string}
             */
            treatment?: "accept" | "transfer" | "avoid" | "mitigate_later";
            /** @description Reference (URL or document id) to the justification (D2). Stored as text, never fetched. */
            proof?: string;
            /**
             * @description How wide the decider said this decision reaches (EDR-SYNC-01 D1); release when not stated.
             * @enum {string}
             */
            scope?: "release" | "project" | "product";
            /** @description Set on a Position Governance applied from a scoped decision elsewhere (D3): the Finding the person decided on. Absent on a Position the person established directly. */
            propagated_from_finding_id?: string;
            /** @description The source Position's version, beside propagated_from_finding_id. */
            propagated_from_version?: number;
        };
        /** @description Who a decision of the given scope on this Finding would reach NOW (EDR-SYNC-01 D7): the preview shown before the person clicks. Findings born later are reached at their evaluation and are not counted here. */
        ScopeTargetsView: {
            finding_id?: string;
            /** @enum {string} */
            scope?: "release" | "project" | "product";
            count?: number;
            /** @description How many distinct projects the targets span. */
            projects?: number;
            /** @description Only with `all=true` - how many of the targets a decision can be copied to. */
            copyable?: number;
            /** @description Only with `all=true` - how many of the copyable targets carry a decision a copy would replace. */
            decided?: number;
            targets?: components["schemas"]["ScopeTargetView"][];
        };
        ScopeTargetView: {
            finding_id?: string;
            release_id?: string;
            product_id?: string;
            project_id?: string;
            /** @description The product's name as Registry holds it (blank when unknown) — what a person reads; the ids above are what scope is decided on. */
            product_name?: string;
            project_name?: string;
            /** @description The target release's version. */
            version?: string;
            /**
             * @description artifact = the same purls; component = the same packages at other versions (EDR-ROLLFORWARD-01 D3). vulnerability (only with `all=true`) = the same CVE on a different component: listed, never copied to.
             * @enum {string}
             */
            level?: "artifact" | "component" | "vulnerability";
            /** @description Only with `all=true`: the decision this Finding carries now. Absent when it has none. A copy to it adds a new Position version; this one stays in the history. */
            decision?: {
                stance?: string;
                decided_by_kind?: string;
                decided_by_id?: string;
                /** Format: date-time */
                decided_at?: string;
            };
        };
        ProposalView: {
            id?: string;
            proposer_kind?: string;
            proposer_id?: string;
            stance?: string;
            rationale?: string;
            /** Format: date-time */
            raised_at?: string;
            status?: string;
            decided_kind?: string;
            decided_id?: string;
            /** @description The commission the cited execution ran under (EDR-HARNESS-01); empty for non-harness proposals. */
            commission_id?: string;
            harness_evidence?: components["schemas"]["HarnessExecutionEvidence"];
            /**
             * @description The trust class of the evidence this proposal rests on (EDR-TRUST-01 T2/T3) — `observed`, `asserted` or `inferred`. It is the field the constitutional check (T4) turns on: an `inferred` proposal can never be auto-accepted by any policy.
             *     Surfaced because a human exercising the decision T4 reserves for them was shown two proposals that looked equally authoritative, with nothing to say that one rested on re-derivable fact and the other on a model's reasoning. A guarantee nobody can see is one nobody can act on. Additive/optional on v1 — an older client ignores it.
             */
            evidence_trust?: string;
        };
        FixedVersion: {
            /** @description The package the fix is published for — the SOURCE package for distro components. */
            package?: string;
            version?: string;
            /** @description The world the fix is published in (rpm | apk | pypi | ...), as the feed stated it; empty when the source did not say. Carried so a consumer can pair each fix with the occurrence it actually applies to (EDR-VERDICT-01 D8 - "update the RPM" and "upgrade the pip install" are different work) without guessing from version shape. */
            ecosystem?: string;
        };
        Component: {
            purl?: string;
            name?: string;
            version?: string;
            ecosystem?: string;
            /** @description The upstream SOURCE-package name for distro components (python3-pyyaml -> PyYAML); empty for non-distro. It is the only key that joins a component to its published fix, because feeds attribute fixes to the source package while a PURL carries the binary one, and neither is derivable from the other (AI-GROUND-1). */
            source?: string;
            /**
             * @description Why this component matched (EDR-CORRELATION-01 D3): `carrier` - evidence says it carries the flaw; `scope` - it was in a distro advisory's rebuild set with no such evidence; empty - unknown, which every consumer treats as `carrier`.
             *     A module-stream advisory rebuilds every RPM in the stream and lists them all as affected, so without this a CPython flaw reads as a vulnerability of python3-pyyaml. The component is kept either way - replacing a superseded build is real work - but an upgrade plan and the AI's grounding use carriers only.
             */
            claim_class?: string;
            /** @description Which engine produced this match (KN-SCAN-2): `discovery` - feed correlation against the release inventory, including the re-discovery sweep; `scanner/<name>` - an uploaded scanner report (bare `scanner` when the report names no engine); empty - unknown (the match predates the field). Display provenance ONLY - it never enters a decision, a policy, or the AI's grounding; authority stays with the trust class and the source tier. */
            detection_origin?: string;
            /**
             * @description The occurrence verdict, mirrored from Knowledge (EDR-VERDICT-01 D2/D5): `cleared_vendor_fix` - the installed build provably carries the vendor's fix; `open` or absent - a live occurrence (absent = the row predates the field, which reads as open - the fail-safe direction). This is the MACHINE's "handled"; a human's "handled" is the Position, and the two never mix.
             * @enum {string}
             */
            verdict_state?: "open" | "cleared_vendor_fix";
            /**
             * @description Evidence strength behind a clearance (EDR-VERDICT-01 D3, EDR-TRUST-01 vocabulary): `observed` - direct evidence (the component's own version against the vendor bound, or an explicit SBOM ownership relationship); `inferred` - a same-inventory match Themis worked out itself, always labeled as such. Present only when cleared.
             * @enum {string}
             */
            verdict_grade?: "observed" | "inferred";
            /** @description Plain-language premise of the verdict (e.g. "vendor fix 0:39.2.0-9.el8_10 present"), stated by Knowledge and rendered verbatim - a clearance nobody can read the reason for is one nobody can audit. */
            verdict_reason?: string;
        };
        /** @description One owner-set severity (EDR-SCORING-01 section 7.1). */
        OwnerSeverity: {
            /**
             * @description How it was given - a picked level, or changed CVSS metric values.
             * @enum {string}
             */
            kind: "level" | "vector";
            /**
             * @description The picked level, or the CVSS rating of the computed score for a vector.
             * @enum {string}
             */
            level: "none" | "low" | "medium" | "high" | "critical";
            /** @description The changed vector; absent for a level (a level has no vector). */
            vector?: string;
            /**
             * Format: double
             * @description The score Themis computed (0.0 - 10.0).
             */
            score: number;
            /**
             * Format: double
             * @description The original score when this was set; absent when there was none.
             */
            original_score?: number;
            reason: string;
            set_by: string;
            /** Format: date-time */
            set_at: string;
            /** @description The Finding this came from, when it came through the pick list or with a copied decision. */
            picked_from?: string;
            /** @description The vector selected for the original when this was set. */
            original_vector?: string;
            /** @description Present on the severity in force when the original changed since it was set or last kept (OS6): what changed, in words. The severity stays in force until a person keeps it, changes it or removes it. */
            review_reason?: string;
            /**
             * Format: date-time
             * @description When a person last kept it after the original changed.
             */
            kept_at?: string;
            kept_by?: string;
            /**
             * Format: date-time
             * @description History only - when it stopped being in force.
             */
            ended_at?: string;
            ended_by?: string;
            /** @enum {string} */
            end_cause?: "replaced" | "removed";
        };
        FindingSeverity: {
            finding_id: string;
            cve: string;
            /**
             * Format: double
             * @description The original score (source Base), unchanged by any owner-set severity.
             */
            original_score?: number;
            original_severity?: string;
            /** @description The vector Themis selected for the original, where one exists. The form for changed metrics starts from it. */
            original_vector?: string;
            owner?: components["schemas"]["OwnerSeverity"];
            history: components["schemas"]["OwnerSeverity"][];
        };
        SetSeverityRequest: {
            actor_id: string;
            /** @description Required - why this severity is right for the product. */
            reason: string;
            /** @description none | low | medium | high | critical. The score is the original moved into the level's band by the shortest way. Give this or `vector`, not both. */
            level?: string;
            /** @description A CVSS 3.0 / 3.1 vector with the changed metric values. The calculator scores it. */
            vector?: string;
            /** @description Other Finding ids to set the same severity on (GET .../severity/targets lists them). Each must be a Finding of the same CVE in the same product, or the whole request is refused (400) and nothing is recorded. */
            apply_to?: string[];
        };
        SetSeverityResult: {
            /** @description How many Findings got the severity, this one included. */
            applied: number;
            /** @description How many of them already had an owner-set severity. */
            replaced: number;
            severity: components["schemas"]["FindingSeverity"];
        };
        SeverityPreview: {
            /** @enum {string} */
            kind: "level" | "vector";
            level: string;
            /** Format: double */
            score: number;
            vector?: string;
            /** Format: double */
            original_score?: number;
        };
        SeverityTarget: {
            finding_id: string;
            release_id: string;
            product_id?: string;
            project_id?: string;
            product_name?: string;
            project_name?: string;
            version?: string;
            owner?: components["schemas"]["OwnerSeverity"];
        };
        SeverityTargets: {
            finding_id: string;
            count: number;
            /** @description How many of the targets carry an owner-set severity now. */
            with_owner_severity: number;
            targets: components["schemas"]["SeverityTarget"][];
        };
        FindingScore: {
            finding_id: string;
            cve: string;
            rollup?: components["schemas"]["FindingScoreRollup"];
            components: components["schemas"]["ComponentScoreRevision"][];
            history: components["schemas"]["ScoreRevisionSummary"][];
        };
        FindingScoreRollup: {
            revision: number;
            cause: string;
            /** Format: date-time */
            recorded_at: string;
            /** @description The roll-up (EDR 6): state (no_components, no_carrier, no_open_occurrences, unavailable, scored), score and band, score_status, contributors, at_maximum, scoring_coverage and assessment_finality ({numerator, denominator, value}), unassessed components with their reason. */
            snapshot: {
                [key: string]: unknown;
            };
        };
        ComponentScoreRevision: {
            purl: string;
            revision: number;
            cause: string;
            /** Format: date-time */
            recorded_at: string;
            /** @description The complete ComponentAssessment snapshot (EDR 8.1): eligibility, outcome, conditions, diagnostic flags, score status and unscored reason, the three scores and the assessment vector, contributing and competing identities, relations, representative, identity roles, every candidate with its disposition, reason and contribution, temporal metrics with state, CR / IR / AR with level, and the policy and calculator versions. */
            snapshot: {
                [key: string]: unknown;
            };
        };
        ScoreRevisionSummary: {
            purl: string;
            revision: number;
            cause: string;
            score_status: string;
            /** Format: double */
            score?: number;
            /** Format: date-time */
            recorded_at: string;
        };
        FindingAssessment: {
            finding?: components["schemas"]["FindingView"];
            knowledge?: components["schemas"]["FaultlineKnowledge"];
            /** @description The RELEASE'S own product placement (EDR-VEX-02 D12), the side every vendor statement below was compared against: `enterprise-linux 8` for RHEL and its rebuilds, `alpine 3.20`, `debian 12`. Absent when the release could not be placed (every statement then reads `not_comparable`). Lets a consumer fold statements about other product families and say "no statement covers this release" only when the vendor speaks about the release's own family. */
            release_scope?: {
                family?: string;
                major?: string;
            };
            /** @description The card's vendor VEX statements, each beside Themis's own determination of whether it covers THIS release (EDR-VEX-02 D2). Present so a BLOCKED statement still reaches the reviewer: a statement whose scope does not cover the release raises no Proposal, and without this it would vanish from the view rather than being visibly inapplicable. */
            vendor_statements?: components["schemas"]["VendorStatement"][];
            attribution?: components["schemas"]["Attribution"];
        };
        /** @description BOTH SIDES of the carrier question for this Finding (EDR-ATTRIBUTION-01 D10/D11/D14): what the card says carries the flaw, what is installed here, and whether Themis could relate the two. A read-time PROJECTION over facts both contexts already hold — no column, no event, nothing stored (D3). Absent when Knowledge's enrichment was unavailable when the projection was built. */
        Attribution: {
            /**
             * @description `attributed` — at least one installed component acts as a carrier (unknown counts as carrier: absence of attribution evidence must never hide a live vulnerability). `unresolved` — the Attribution Gap: components ARE recorded and every one is scope-class, so nothing installed is evidenced to carry the flaw. An OBSERVATION about the evidence, never a verdict that the release is unaffected — the measured proof is a `requests` flaw whose only components are python3-ply and python3-pyyaml, legitimate bystanders every one. `no_components` — the Finding lists no components at all, which is not a gap.
             * @enum {string}
             */
            status?: "attributed" | "unresolved" | "no_components";
            /** @description The products the card's sources say carry the flaw, verbatim. EMPTY means no source named one, which is a materially different gap from "carrier named, none matched" — the two are counted apart deliberately. */
            carriers?: string[];
            /** @description The installed components this Finding matched, by name — the other side. */
            components?: string[];
            /** @description Why the two sides could not be related, in plain language. Per-Finding DATA, and populated only when status is `unresolved`. What evidence would RESOLVE the gap is deliberately NOT here: it is identical on every instance, so it is documentation (EDR-ATTRIBUTION-01), and a field whose value never varies carries no information. */
            unresolved_because?: string[];
        };
        /** @description One vendor statement as EVIDENCE, beside Themis's separate conclusion. The three concepts never collapse into one field: `status`/`justification` are the vendor's own words, verbatim; `scope_family`/`scope_major` are the product the VENDOR said it covers; and `applicability` is Themis's determination. Nothing here rewrites the vendor's statement. */
        VendorStatement: {
            package?: string;
            /**
             * @description The VENDOR'S assertion, from the closed set (EDR-VEX-02 D13). Never carries Themis's conclusion. Only an applicable `not_affected` can have become a Proposal (D15); every other status is information for the engineer.
             * @enum {string}
             */
            status?: "not_affected" | "affected" | "fixed" | "under_investigation" | "will_not_fix" | "fix_deferred" | "out_of_support";
            /** @description The vendor's stated reason, verbatim. */
            justification?: string;
            /** @description On a `fixed` statement, the advisory that shipped the fix (D14). Absent otherwise. */
            advisory?: string;
            /** @description On a `fixed` statement, the build the advisory shipped. Absent otherwise. */
            fixed_version?: string;
            /** @description Product family the vendor scoped it to, e.g. `enterprise-linux`. Empty = no readable scope. */
            scope_family?: string;
            /** @description Major version of that family, e.g. `8`. Empty = no readable scope. */
            scope_major?: string;
            /** @description The SECOND facet the raise rule asks (EDR-VEX-02 D23): whether the statement's `package` is one of this Finding's components, by the same test the raise uses. An `applicable` statement with `covers_component: false` applies to the release and is about another package — it clears nothing here and was never proposed. */
            covers_component?: boolean;
            /**
             * @description THEMIS'S determination for this release's PRODUCT SCOPE. Only `applicable` can have become a Proposal — and only when `covers_component` is also true; every other value is non-clearing. `not_applicable` — the vendor's scope was positively established and does not cover this release. A product mismatch, never uncertainty. `unknown` — the VENDOR'S STATEMENT could not be placed: no CPE, or one that cannot be classified. A feed-quality gap from which nothing follows. `not_comparable` — the vendor's scope WAS placed, but this RELEASE could not be, so no comparison is possible. The measured case is a Maven or PyPI component, which carries no distribution build, against a perfectly clear Red Hat product scope. The last two were one value until 2026-09-21, and separating them is the point: a reviewer dismisses "the vendor spoke about a builder image and this is a Java library" instantly, while an unreadable CPE permits no conclusion at all. Because `not_comparable` describes the release rather than the statement, it appears identically on EVERY statement of an affected Finding — that repetition is the signal.
             * @enum {string}
             */
            applicability?: "applicable" | "not_applicable" | "unknown" | "not_comparable";
        };
        /** @description What Knowledge knows about the CVE, read over its read API. Absent fields mean the enrichment was unavailable when the projection was built. */
        FaultlineKnowledge: {
            faultline_id?: string;
            cve?: string;
            /** @description The winning source's short account of WHAT the CVE is, carried from Knowledge's reconciled view — so the human judging a proposal and the AI grounding on this projection read the same sentence. Descriptive only; nothing decides on it. */
            summary?: string;
            severity?: string;
            cvss_score?: number;
            epss?: number;
            kev?: boolean;
            exploit_public?: boolean;
            affected_ranges?: string[];
            /** @description The products the card's sources say CARRY the flaw (EDR-CORRELATION-01 D4), read from Knowledge unchanged. Governance classifies nothing with them — Knowledge already matched this Finding's components against exactly this list and the result is each component's claim class. See `attribution` for the derived, per-Finding answer. */
            carrier_products?: string[];
            /** @description Fix versions published for THIS Finding's components — selected from the card, not the card's flat cross-package union (EDR-TRUST-01 T9). Empty when the card holds fixes that cannot be attributed to this component; see unattributed_fixes. */
            fixed_versions?: string[];
            /** @description The same selection with package attribution intact. */
            fixes?: {
                package?: string;
                version?: string;
            }[];
            /** @description How many of the card's fix versions could NOT be tied to this Finding's components. Non-zero with an empty fixed_versions means "fixes exist but none is attributable here" — materially different from "no fix published", and the two must not be confused by a consumer. */
            unattributed_fixes?: number;
            /**
             * @description Trust class of the sources contributing the ranges (EDR-TRUST-01 T2/T3).
             * @enum {string}
             */
            range_trust?: "observed" | "asserted" | "inferred";
        };
        /** @description The cross-release posture diff (D16). fixed rows carry the BASELINE's state (a fix closes the question forward, it never rewrites history); new and persisting carry the CANDIDATE's. Each bucket is sorted by residual_priority then effective_priority, descending. */
        ReleaseComparison: {
            baseline_release_id?: string;
            candidate_release_id?: string;
            fixed?: components["schemas"]["PostureEntry"][];
            new?: components["schemas"]["PostureEntry"][];
            persisting?: components["schemas"]["PostureEntry"][];
        };
        ReleaseEvaluatedEventsPage: {
            items: components["schemas"]["ReleaseEvaluatedEvent"][];
            /**
             * Format: int64
             * @description The cursor for the following call — the last item's seq, or the caller's own cursor when the page is empty.
             */
            next: number;
        };
        ReleaseEvaluatedEvent: {
            /** Format: int64 */
            seq: number;
            /** @description The bus envelope id of the same fact — the subscriber's dedup key. */
            event_id: string;
            /** @description governance.release_evaluated */
            name: string;
            /** Format: date-time */
            occurred_at: string;
            /** @description The governance.release_evaluated.v1 payload exactly as published. */
            body: {
                [key: string]: unknown;
            };
        };
        UploadOutcome: {
            /** @description The SBOM this outcome describes. */
            sbom_id: string;
            /** Format: date-time */
            evaluated_at: string;
            new: number;
            reappeared: number;
            /** @description Open Findings none of whose components is in this SBOM. They stay open with their Positions. */
            no_longer_present: number;
            unchanged: number;
            /** @description Findings in neither SBOM (e.g. from a scanner report), or resolved / archived. */
            not_judged: number;
            new_cves?: string[];
            reappeared_cves?: string[];
            no_longer_present_cves?: string[];
            /** @description False on the Release's first SBOM, where everything present is new. */
            has_baseline: boolean;
        };
        MeanDays: {
            mean_days: number;
            /** @description How many Findings the mean is over; 0 means no sample (mean_days is then 0). */
            count: number;
        };
        RemediationMetrics: {
            /** @description The Product name; empty for the estate. */
            scope: string;
            open: number;
            /** @description Age band (0-7, 8-30, 31-90, over-90 days) to severity bucket to count. */
            open_by_age: {
                [key: string]: {
                    [key: string]: number;
                };
            };
            sla_applicable: number;
            within_sla: number;
            breached_now: number;
            within_sla_share: number;
            time_to_decision: components["schemas"]["MeanDays"];
            time_to_remediation: components["schemas"]["MeanDays"];
            time_to_resolution: components["schemas"]["MeanDays"];
        };
        RemediationReport: {
            /** Format: date-time */
            generated_at: string;
            estate: components["schemas"]["RemediationMetrics"];
            products: components["schemas"]["RemediationMetrics"][];
            /** @description The Registry could not be read; only the estate figures are given. */
            products_unavailable: boolean;
            /** @description Findings whose release the Registry estate does not list. */
            unattributed: number;
        };
        SLATarget: {
            /** @description Days to fix, counted from the start of the SLA period. */
            days: number;
            /** @description When false the bucket has no deadline (state not_applicable). */
            enforce: boolean;
        };
        SLAPolicyPut: {
            /** @description Empty or omitted = the estate policy; otherwise the Product id this override is for. */
            scope?: string;
            critical: components["schemas"]["SLATarget"];
            high: components["schemas"]["SLATarget"];
            medium: components["schemas"]["SLATarget"];
            low: components["schemas"]["SLATarget"];
            /** @description The person changing the policy, recorded beside it. */
            updated_by: string;
        };
        SLAPolicyRecord: {
            scope: string;
            critical: components["schemas"]["SLATarget"];
            high: components["schemas"]["SLATarget"];
            medium: components["schemas"]["SLATarget"];
            low: components["schemas"]["SLATarget"];
            /**
             * Format: date-time
             * @description Absent for the shipped defaults (nothing stored yet).
             */
            updated_at?: string;
            updated_by?: string;
        };
        SLAPolicySet: {
            estate: components["schemas"]["SLAPolicyRecord"];
            overrides: components["schemas"]["SLAPolicyRecord"][];
        };
        RebuildPolicyPut: {
            /** @description Count a Finding only when a fixed version is known for its component. */
            fix_required: boolean;
            /**
             * @description The lowest severity that counts.
             * @enum {string}
             */
            severity_floor: "low" | "medium" | "high" | "critical";
            /** @description Count a known-exploited Finding whatever its severity. */
            count_known_exploited: boolean;
            /** @description Do not count a Finding decided not_affected or accepted_risk. */
            skip_decided: boolean;
            /** @description Do not count scope-class components; unknown counts as carrier. */
            carrier_only: boolean;
            /**
             * Format: int64
             * @description The shortest time between two rebuild requests for one Release. 0 = none.
             */
            cool_down_seconds: number;
            /**
             * @description off = no rebuild is asked for; ask = a person is told and a person starts the build; auto = the request is sent without asking.
             * @enum {string}
             */
            mode: "off" | "ask" | "auto";
            /** @description The person changing the policy, recorded with the version. */
            updated_by: string;
        };
        RebuildPolicyRecord: {
            /**
             * @description The level this policy sits at (D11).
             * @enum {string}
             */
            scope_kind: "installation" | "product" | "release";
            /** @description Empty for the installation policy; otherwise the Product id or the Release id. */
            scope_id: string;
            /** @description Only in a history: true on the entry that records the removal of a Product or Release policy. Its values are the removed policy's, its actor and time the removal's. */
            removed?: boolean;
            /** @description Counts the changes from 1. 0 = nothing stored, the shipped defaults are in force. */
            version: number;
            /** @description Count a Finding only when a fixed version is known for its component. */
            fix_required: boolean;
            /**
             * @description The lowest severity that counts.
             * @enum {string}
             */
            severity_floor: "low" | "medium" | "high" | "critical";
            /** @description Count a known-exploited Finding whatever its severity. */
            count_known_exploited: boolean;
            /** @description Do not count a Finding decided not_affected or accepted_risk. */
            skip_decided: boolean;
            /** @description Do not count scope-class components; unknown counts as carrier. */
            carrier_only: boolean;
            /**
             * Format: int64
             * @description The shortest time between two rebuild requests for one Release. 0 = none.
             */
            cool_down_seconds: number;
            /**
             * @description off = no rebuild is asked for; ask = a person is told and a person starts the build; auto = the request is sent without asking.
             * @enum {string}
             */
            mode: "off" | "ask" | "auto";
            /**
             * Format: date-time
             * @description Absent for the shipped defaults (nothing stored yet).
             */
            updated_at?: string;
            updated_by?: string;
        };
        RebuildPolicyInForce: {
            release_id: string;
            /** @description The Product that owns the Release, as Registry names it. */
            product_id: string;
            policy: components["schemas"]["RebuildPolicyRecord"];
            /**
             * @description The installation policy's mode - the ceiling nothing below can lift (D17).
             * @enum {string}
             */
            installation_mode: "off" | "ask" | "auto";
            /**
             * @description The highest mode the policies allow for this Release - the lower of the installation policy's mode and the mode of the policy in force.
             * @enum {string}
             */
            mode_ceiling: "off" | "ask" | "auto";
            /**
             * @description Which of the two set mode_ceiling.
             * @enum {string}
             */
            mode_set_by: "installation" | "policy";
            /** @description Whether the Release's tags were read. Always false until step R2. A tag can only lower mode_ceiling, and a Release with no rebuild tag takes no part at all (D4, D17), so mode_ceiling is not yet the effective mode. */
            tags_applied: boolean;
        };
        SLAAcceptancePeriod: {
            /** Format: date-time */
            start: string;
            /**
             * Format: date-time
             * @description Absent while the acceptance still holds.
             */
            end?: string;
            position_version: number;
        };
        /** @description The Finding's remediation clock (EDR-REMEDIATION-01 D1). Derived on every read, never stored; a breach changes nothing about the Finding (S1). Restarting after an acceptance never hides elapsed time: age_days and days_under_acceptance count from creation (S2). */
        SLAStatus: {
            /**
             * @description within / due_soon (inside 7 days) / breached while running; paused under a valid accepted_risk or deferred Position; met / missed once a not_affected or mitigated Position, or the resolved / archived stage, stopped it; not_applicable with no severity and no CISA date, or an unenforced bucket.
             * @enum {string}
             */
            state: "within" | "due_soon" | "breached" | "paused" | "met" | "missed" | "not_applicable";
            /** @description The severity bucket frozen when the Finding first had a score (D8 Q1). */
            bucket: string;
            /** @description Today's bucket from the current base score. */
            current_bucket?: string;
            /** @description Severity changed since the clock started; the deadline still follows `bucket`. */
            bucket_changed: boolean;
            /** Format: date-time */
            period_start: string;
            /**
             * Format: date-time
             * @description Absent when paused or not applicable.
             */
            due?: string;
            /** @description Whole days to `due`; negative when breached. */
            days_left?: number;
            /** @description CISA's KEV due date was earlier than the policy's and is the deadline. */
            kev_due_applied: boolean;
            /** Format: date-time */
            stopped_at?: string;
            /** @description Whole days since the Finding was created. */
            age_days: number;
            /** @description Whole days spent under a valid acceptance, all periods summed. */
            days_under_acceptance: number;
            acceptance_periods?: components["schemas"]["SLAAcceptancePeriod"][];
        };
        PostureEntry: {
            finding_id?: string;
            /** @description The Release this Finding is filed under. Always set; it matters on the cross-release read (GET /faultlines/{faultlineId}/findings), where rows come from many releases. */
            release_id?: string;
            /** @description Who established the current Position (absent when none): `human` (a named person) or `policy` / `system` (a rule). The GUI shows MANUAL / AUTO (EDR-GUI-02 D13). An AI or vendor proposal is never a decider: it waits for a person. */
            decided_by_kind?: string;
            /**
             * Format: date-time
             * @description When the current Position was established (absent when none).
             */
            decided_at?: string;
            /**
             * Format: double
             * @description The source's own CVSS Base score from the newest stored assessment (EDR-SCORING-01) - the highest over the open carrier components, else over every current component. Absent when this Finding has no assessment yet.
             */
            original_score?: number;
            /** @description The CVSS qualitative rating of original_score (critical | high | medium | low | none). */
            original_severity?: string;
            /**
             * Format: double
             * @description Themis's score after the assessment - the roll-up's highest Environmental score. Present only when score_state is scored.
             */
            expert_score?: number;
            /** @description The CVSS qualitative rating of expert_score. */
            expert_severity?: string;
            /** @description final or provisional when expert_score is set (EDR-SCORING-01 D5). */
            expert_status?: string;
            /** @description The owner-set severity in force (EDR-SCORING-01 section 7.1); absent when none. While it is set, base_score and both priorities are computed from its score, and original_score still shows what the source said. */
            owner_severity?: components["schemas"]["OwnerSeverity"];
            /** @description The assessment roll-up state (scored | no_components | no_carrier | no_open_occurrences | unavailable); absent when no assessment is stored. */
            score_state?: string;
            faultline_id?: string;
            cve?: string;
            stage?: string;
            stance?: string;
            has_position?: boolean;
            /** @description The current Position's version when has_position (absent/0 otherwise) - the handle a release-scoped snapshot records so its staleness is exactly computable (EDR-COMMUNICATION-01 D13.2). */
            position_version?: number;
            /** @description The current Position's own rationale (absent when none) - carried onto a release rollup's statements as status notes (EDR-COMMUNICATION-01 D13). */
            position_rationale?: string;
            disposition_stale?: components["schemas"]["DispositionStale"];
            sla?: components["schemas"]["SLAStatus"];
            /** @description The release components this Finding was opened for, each carrying the SOURCE package a fix is published under. Present on the rollup so a release-scoped consumer can group by "what do I upgrade" without one read per Finding (EDR-TRUST-01 T10 — the projection is a reusable business view, and the grouping is a GROUP BY, not reasoning). */
            components?: components["schemas"]["Component"][];
            /** @description Knowledge's EXPLOITABILITY band (critical | high+ | high | elevated | informational) — not raw CVSS. `critical` means CVSS>=9 AND KEV-listed; `high+` means CVSS>=9 with a public exploit. Carried here so "which of these are critical?" is one read (DASH-2) rather than one Knowledge call per Faultline. */
            band?: string;
            /** @description Fix versions published for THIS Finding's own components — selected, never the card's cross-package union, which is what led a recommendation to cite another package's version (AI-GROUND-1). Empty means none is attributable to these components. */
            fixes?: components["schemas"]["FixedVersion"][];
            /** @description CVE-intrinsic composite priority (0-100), from Knowledge (C6). */
            base_score?: number;
            /** @description Enterprise blast-radius amplification (1.0-2.0x) from the estate graph (C2); 1.0 when the estate is empty/unreachable. */
            blast_multiplier?: number;
            /** @description base_score x blast_multiplier - how bad this is here, INDEPENDENT of what was decided about it (EDR-GOVERNANCE-01 D14). NOT clamped (D17/GOV-15): a ranking number, not a percentage - range 0-200 (multiplier saturates at 2.0x). A clamp is not order-preserving, and at a saturated estate it flattened every base >= 50 to 100. */
            effective_priority?: number;
            /** @description effective_priority x stance_weight(stance) - the number to SORT a triage queue by (D14). Unclamped like effective_priority (D17); weight <= 1.0 keeps it <= effective. not_affected and accepted_risk weigh 0, mitigated 0.5 (configurable), deferred 0.9, and affected / under_investigation / no-position 1.0. A dispositioned Finding drops out of the queue without losing the intrinsic severity that effective_priority still reports. */
            residual_priority?: number;
            /**
             * @description Trust class of the evidence the current Position rested on, when weaker than 'observed' (EDR-TRUST-01 T12) - e.g. an acceptance leaning on a vendor's Asserted not_affected. Absent means no Position, or one resting on observed evidence. Derived from the accepted proposal, never stored as state.
             * @enum {string}
             */
            reservation?: "asserted" | "inferred";
            /** @description How many CARRIER occurrences are still open (EDR-VERDICT-01 D7) - the number that decides queue membership. Scope-class rows never count. When components exist and this reads 0, every carrier is cleared by a vendor fix and effective_priority / residual_priority read 0 - the Finding has left the ranked queue without any row being deleted. One live carrier keeps FULL urgency however many cleared rows sit beside it: priorities are never discounted proportionally. */
            open_carriers?: number;
        };
        RaiseProposalRequest: {
            stance: string;
            rationale?: string;
            /** @description human | ai (defaults to human). system/policy are internal only. */
            proposer_kind?: string;
            proposer_id?: string;
            evidence?: components["schemas"]["HarnessExecutionEvidence"];
            /** @description With `evidence`: the trust class the intake DERIVED from the execution facts (always `inferred` for harness-execution/v1). Governance refuses a class other than the derived one (D-I-5) — trust is a property of evidence, never an assertion. */
            evidence_trust?: string;
        };
        RaiseProposalResponse: {
            proposal_id?: string;
        };
        WatchCreate: {
            name: string;
            /** @description Pasted text - CVE and advisory ids separated by whitespace, commas or semicolons. */
            identifiers: string;
            /** @description Who creates it, used only when the node runs without auth (the key wins otherwise). */
            created_by?: string;
            /** @description The D2a flag; recorded, not yet acted on. */
            notify?: boolean;
        };
        WatchIdentifiersAdd: {
            identifiers: string;
        };
        WatchView: {
            id: string;
            name: string;
            created_by: string;
            /** Format: date-time */
            created_at: string;
            identifiers: string[];
            /** @description The CVE set the identifiers resolved to at the last status read. */
            resolved_cves: string[];
            /** Format: date-time */
            resolved_at?: string;
            notify: boolean;
        };
        WatchCreated: {
            watch: components["schemas"]["WatchView"];
            /** @description How many identifiers were new. */
            added: number;
            /** @description Tokens that are neither a CVE nor a known advisory id form. */
            rejected: string[];
        };
        WatchIdentifierView: {
            id: string;
            /** @enum {string} */
            kind: "cve" | "advisory" | "";
            cves: string[];
            resolved: boolean;
        };
        WatchRowView: {
            release_id?: string;
            product_id?: string;
            project_id?: string;
            product_name?: string;
            project_name?: string;
            version?: string;
            cve: string;
            faultline_id?: string;
            finding_id?: string;
            /** @enum {string} */
            state: "not_affected" | "open_no_fix" | "open_fix_available" | "fixed" | "accepted" | "unknown";
            /** @description The standing Position's stance, blank when undecided. */
            stance?: string;
            /** @description The open components' package names. */
            packages: string[];
            /** @description The recorded fix versions that apply to those packages. */
            fixes: string[];
            /**
             * Format: date-time
             * @description When the release's newest evidence was filed - the last proof.
             */
            last_evidence_at?: string;
            last_evidence_kind?: string;
        };
        WatchStatusView: {
            watch: components["schemas"]["WatchView"];
            /** Format: date-time */
            generated_at: string;
            identifiers: components["schemas"]["WatchIdentifierView"][];
            rows: components["schemas"]["WatchRowView"][];
            /** @description Rows per state. */
            counts: {
                [key: string]: number;
            };
            /** @description The D5 sentence - fix available is the vendor's statement; patched is proven only by new evidence. */
            note?: string;
        };
        DecisionRequest: {
            /** @description The DEVELOPMENT decider identity, used only when inbound auth is disabled, where it is recorded with a `dev:` prefix marking it unverified. When the request is authenticated it is IGNORED and the recorded actor is derived from the API key's principal as `key:<key-id>` — a value the server cannot verify must never overwrite one it can (EDR-SECURITY-01 D10). The `dev:` marker is applied to whatever arrives, so sending `key:…` yields `dev:key:…` and cannot forge authenticated provenance. */
            actor_id: string;
            /** @description human (default). Only a human decider is accepted via the API. */
            actor_kind?: string;
            /**
             * Format: date-time
             * @description Optional review-by date for a SUPPRESSING decision (not_affected / accepted_risk). When set, the disposition sweep re-surfaces the Finding once it passes — the time-based counterpart to signal drift (GOV-14b). An accepted risk with no signal movement is not thereby still acceptable: the compensating control may be gone, the component may have moved, the person who accepted it may have left. Absent means NO date was agreed, which is not the same as "never expires" — nothing invents a deadline the decider did not set. Fourteen days before it, governance.review_due_soon.v1 is announced once.
             */
            review_by?: string;
            /** @description The accountable owner of the risk (EDR-REMEDIATION-01 D2) — often not the person accepting it. REQUIRED when a person accepts an accepted_risk proposal (D8 Q3; 400 otherwise). Allowed only on accepted_risk and deferred. */
            owner?: string;
            /**
             * @description How the accepted risk is being handled (D2). Allowed only on accepted_risk and deferred.
             * @enum {string}
             */
            treatment?: "accept" | "transfer" | "avoid" | "mitigate_later";
            /** @description A reference (URL or document id) to the justification (D2). Stored as text, never fetched. Allowed only on accepted_risk and deferred. Changing the owner, treatment or proof later is a new Position version: raise a proposal with the same stance and accept it with the new terms. */
            proof?: string;
            /**
             * @description How wide this decision reaches (EDR-SYNC-01 D1). `release` (default) is this Finding only. `project` / `product` make Governance establish the SAME Position, recorded against the same decider, on every Finding of the same CVE that carries the same component (same purls, or the same packages at other versions) on the releases of the same project / of every project of the same product — within a sweep (minutes), and on Findings that open later. A different component is never synced; a Finding that already has a Position is never overwritten. GET /findings/{id}/scope-targets previews who it reaches.
             * @enum {string}
             */
            scope?: "release" | "project" | "product";
            /** @description Finding ids this decision is copied to, once (EDR-SYNC-01 D9, D11). Each must be another Finding of the same CVE in the same product that carries the same component; one that is not refuses the whole request (400) and nothing is recorded. Governance establishes the SAME Position on each, recorded against the same decider, within a sweep (about a minute). A target that already has a Position gets a new version (the earlier one stays in the history). One-time: later Findings and later changes of this decision do not follow. Not allowed together with scope `project` / `product` (400). GET /findings/{id}/scope-targets?scope=product&all=true lists what can be picked. */
            copy_to?: string[];
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
    parameters: {
        WatchId: string;
        FindingId: string;
        ProposalId: string;
    };
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    getFindingByKey: {
        parameters: {
            query: {
                release: string;
                faultline: string;
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
                    "application/json": components["schemas"]["FindingView"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    getFinding: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
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
                    "application/json": components["schemas"]["FindingView"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    getPosition: {
        parameters: {
            query?: {
                version?: number;
            };
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
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
                    "application/json": components["schemas"]["PositionView"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    listWatches: {
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
                    "application/json": components["schemas"]["WatchView"][];
                };
            };
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    createWatch: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["WatchCreate"];
            };
        };
        responses: {
            /** @description Created. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WatchCreated"];
                };
            };
            400: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getWatch: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                watchId: components["parameters"]["WatchId"];
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
                    "application/json": components["schemas"]["WatchView"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    deleteWatch: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                watchId: components["parameters"]["WatchId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Deleted. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    addWatchIdentifiers: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                watchId: components["parameters"]["WatchId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["WatchIdentifiersAdd"];
            };
        };
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WatchCreated"];
                };
            };
            400: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getWatchStatus: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                watchId: components["parameters"]["WatchId"];
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
                    "application/json": components["schemas"]["WatchStatusView"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getScopeTargets: {
        parameters: {
            query: {
                scope: "release" | "project" | "product";
                /** @description The pick list of a decision copy (EDR-SYNC-01 D10). With `all=true` (scope must be `product`) the answer lists EVERY other Finding of the same CVE in the same product, decided or not, each with its level (`vulnerability` = a different component, cannot be copied to) and the decision it carries now. */
                all?: boolean;
            };
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
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
                    "application/json": components["schemas"]["ScopeTargetsView"];
                };
            };
            400: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    raiseProposal: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RaiseProposalRequest"];
            };
        };
        responses: {
            /** @description Created. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RaiseProposalResponse"];
                };
            };
            400: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    acceptProposal: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
                proposalId: components["parameters"]["ProposalId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["DecisionRequest"];
            };
        };
        responses: {
            /** @description Accepted. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    rejectProposal: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
                proposalId: components["parameters"]["ProposalId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["DecisionRequest"];
            };
        };
        responses: {
            /** @description Rejected. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    resolveFinding: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Resolved. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            409: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    reopenFinding: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Reopened. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            409: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    archiveFinding: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Archived. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            409: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    commissionFinding: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CommissionRequest"];
            };
        };
        responses: {
            /** @description Created. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CommissionResponse"];
                };
            };
            400: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            409: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    withdrawCommission: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
                commissionId: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["WithdrawCommissionRequest"];
            };
        };
        responses: {
            /** @description Withdrawn. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            409: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    recommendPosition: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description An advisory AI proposal was recorded. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RaiseProposalResponse"];
                };
            };
            /** @description No proposal (AI disabled, unavailable, or declined) — a safe outcome. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    getFindingAssessment: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
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
                    "application/json": components["schemas"]["FindingAssessment"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    getFindingSeverity: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
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
                    "application/json": components["schemas"]["FindingSeverity"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    setFindingSeverity: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SetSeverityRequest"];
            };
        };
        responses: {
            /** @description Saved. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SetSeverityResult"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    removeFindingSeverity: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    actor_id: string;
                };
            };
        };
        responses: {
            /** @description Removed. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FindingSeverity"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    keepFindingSeverity: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    actor_id: string;
                };
            };
        };
        responses: {
            /** @description Kept. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FindingSeverity"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            409: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    previewFindingSeverity: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    level?: string;
                    vector?: string;
                };
            };
        };
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SeverityPreview"];
                };
            };
            400: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getFindingSeverityTargets: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
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
                    "application/json": components["schemas"]["SeverityTargets"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getFindingScore: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: components["parameters"]["FindingId"];
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
                    "application/json": components["schemas"]["FindingScore"];
                };
            };
            404: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getReleasePosture: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                releaseId: string;
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
                    "application/json": components["schemas"]["PostureEntry"][];
                };
            };
            500: components["responses"]["Problem"];
        };
    };
    getReleaseUploadOutcome: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                releaseId: string;
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
                    "application/json": components["schemas"]["UploadOutcome"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    compareReleases: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description The baseline release (the one that shipped). */
                releaseId: string;
                /** @description The candidate release (the build that claims to fix things). */
                candidateId: string;
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
                    "application/json": components["schemas"]["ReleaseComparison"];
                };
            };
            422: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            502: components["responses"]["Problem"];
        };
    };
    getReleaseEvaluatedEvents: {
        parameters: {
            query?: {
                /** @description The sequence cursor; everything later than it is returned. Omitted = from the start. */
                after?: number;
                /** @description Page size; default 100, values above 500 are clamped. */
                limit?: number;
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
                    "application/json": components["schemas"]["ReleaseEvaluatedEventsPage"];
                };
            };
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getRemediationMetrics: {
        parameters: {
            query?: {
                /** @description Keep only this Product (id or name, case-insensitive). The estate figures always cover everything. */
                product?: string;
                /** @description Keep only Findings on releases carrying this tag in their effective tags (EDR-REMEDIATION-01 D7: tags filter, never weight). Applies to the estate figures too. 503 when the Registry estate cannot be read. */
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
                    "application/json": components["schemas"]["RemediationReport"];
                };
            };
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getSLAPolicy: {
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
                    "application/json": components["schemas"]["SLAPolicySet"];
                };
            };
            500: components["responses"]["Problem"];
        };
    };
    putSLAPolicy: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SLAPolicyPut"];
            };
        };
        responses: {
            /** @description Stored. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SLAPolicyRecord"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
        };
    };
    getRebuildPolicy: {
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
                    "application/json": components["schemas"]["RebuildPolicyRecord"];
                };
            };
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    putRebuildPolicy: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RebuildPolicyPut"];
            };
        };
        responses: {
            /** @description Stored. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RebuildPolicyRecord"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getRebuildPolicyHistory: {
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
                    "application/json": components["schemas"]["RebuildPolicyRecord"][];
                };
            };
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    listRebuildPolicies: {
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
                    "application/json": components["schemas"]["RebuildPolicyRecord"][];
                };
            };
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getProductRebuildPolicy: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                productId: string;
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
                    "application/json": components["schemas"]["RebuildPolicyRecord"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    putProductRebuildPolicy: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                productId: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RebuildPolicyPut"];
            };
        };
        responses: {
            /** @description Stored. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RebuildPolicyRecord"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    deleteProductRebuildPolicy: {
        parameters: {
            query: {
                /** @description The person removing the policy, recorded with the removal. */
                updated_by: string;
            };
            header?: never;
            path: {
                productId: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Removed. The body is the history entry of the removal. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RebuildPolicyRecord"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getProductRebuildPolicyHistory: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                productId: string;
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
                    "application/json": components["schemas"]["RebuildPolicyRecord"][];
                };
            };
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getReleaseRebuildPolicy: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                releaseId: string;
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
                    "application/json": components["schemas"]["RebuildPolicyRecord"];
                };
            };
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    putReleaseRebuildPolicy: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                releaseId: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RebuildPolicyPut"];
            };
        };
        responses: {
            /** @description Stored. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RebuildPolicyRecord"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    deleteReleaseRebuildPolicy: {
        parameters: {
            query: {
                /** @description The person removing the policy, recorded with the removal. */
                updated_by: string;
            };
            header?: never;
            path: {
                releaseId: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Removed. The body is the history entry of the removal. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RebuildPolicyRecord"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getReleaseRebuildPolicyHistory: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                releaseId: string;
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
                    "application/json": components["schemas"]["RebuildPolicyRecord"][];
                };
            };
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getReleaseRebuildPolicyInForce: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                releaseId: string;
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
                    "application/json": components["schemas"]["RebuildPolicyInForce"];
                };
            };
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getFaultlineFindings: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                faultlineId: string;
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
                    "application/json": components["schemas"]["PostureEntry"][];
                };
            };
            500: components["responses"]["Problem"];
        };
    };
    getBlastRadius: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                faultlineId: string;
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
                    "application/json": string[];
                };
            };
            500: components["responses"]["Problem"];
        };
    };
}
