// Generated from api/knowledge.openapi.yaml by scripts/gen-api.mjs. Do not edit.

export interface paths {
    "/faultlines": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get a Faultline by canonical CVE. */
        get: operations["getFaultlineByCVE"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/faultlines/by-advisory": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The cards whose vendor statements carry an advisory id (EDR-INCIDENT-01 D2), in CVE order. The alias is the `advisory` of a `fixed` statement (EDR-VEX-02 D14), so an advisory Themis has not seen on any card is an empty list - a Watch then says "unknown" rather than guessing. 503 when the lookup is not wired. */
        get: operations["getFaultlinesByAdvisory"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/faultlines/recent": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The newest CARDED Faultlines by card-creation time, newest first (GUI-16). A pure read over the estate's own cards — never a mirror of the world's CVE feed (EDR-KNOWLEDGE-01 D5). `limit` defaults to 50 and is clamped at 200. */
        get: operations["getRecentFaultlines"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/faultlines/published-recently": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** CVEs the world published in the last `days` days (default 7, clamped at 30), fetched LIVE from the per-CVE source and shown, never stored (GUI-16 layer 2; "Gathering Is Not Knowing", EDR-KNOWLEDGE-01 D5). Each row says whether the estate already holds a card; an operator's gather on a row is the one act that creates one. 503 when no source is wired. */
        get: operations["getPublishedRecently"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/psirt/alerts": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The PSIRT early alert (EDR-PSIRT-01 P2): CVEs the world published in the last `days` days (default 7, clamped at 30) with an original (source) score at or above `min_severity` (critical | high | medium | low; default high), each with the product components it MAY hit by name match (Q1; version ignored). Read LIVE from NVD, gaps filled from CVE.org, stored nowhere (EDR-KNOWLEDGE-01 D5). No Themis score: the team assesses after the alert and the engine decides. Unscored CVEs are not listed. 503 when no source is wired; 502 when the world source fails. */
        get: operations["getPSIRTAlerts"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/psirt/bulletins": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The PSIRT bulletin register (EDR-PSIRT-01 revision 3): every live bulletin, newest report date first. A bulletin is what an admin wrote about an issue (an id, a title, links, a note, at most one CVE), so storing it keeps EDR-KNOWLEDGE-01 D5. 503 when no register is wired on this node. */
        get: operations["listBulletins"];
        put?: never;
        /** Add a bulletin (admin only, R2). The report date defaults to today. 400 on invalid input, 403 for a non-admin key, 409 when a live bulletin already has this bulletin ID or CVE. */
        post: operations["createBulletin"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/psirt/bulletins/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Replace a bulletin's fields (admin only). An absent report date keeps the one it had. The change is kept in the bulletin's history. */
        put: operations["updateBulletin"];
        post?: never;
        /** Remove a bulletin from the register (admin only). It is a tombstone: its history stays readable. */
        delete: operations["removeBulletin"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/psirt/bulletins/{id}/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Every change of one bulletin, oldest first, a removed one included. */
        get: operations["getBulletinHistory"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/faultlines/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get a Faultline by its identity. */
        get: operations["getFaultlineById"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/faultlines/{id}/releases": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the releases affected by a Faultline (rollup projection). */
        get: operations["getFaultlineReleases"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/faultlines/{id}/ratings": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Source CVSS ratings of a Faultline's CVE, one row per publication (EDR-SCORING-01 S2).
         * @description Source truth only. Every publication any source carried for this CVE, with its derived status (active, superseded, withdrawn), Themis's own validation of its vector, and its assessment identity under the latest grouping. Nothing here is selected or decided; selection belongs to Governance. 503 when this node records no ratings.
         */
        get: operations["getFaultlineRatings"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/faultlines/gather": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * On-demand fetch of ONE CVE's facts through the wired per-CVE sources (G-AI-1).
         * @description The explicit, operator-triggered half of "the AI asks, the feeds gather": consults each wired per-CVE source (NVD, and Red Hat's Security Data since EDR-INCIDENT-01 D4 — so today's advisory bounds reach a card now, not after the next sweep) for a CVE the scheduled feeds may not have ingested yet, and folds what they return as ORDINARY source Proposals - same ACLs, same reconciliation precedence, same "Gathering Is Not Knowing" boundary as any feed. Unlike the scheduled sweeps this needs no enable flag: the authenticated POST is the opt-in. A write-scoped key is required (it records Proposals).
         */
        post: operations["gatherCVE"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/feeds": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Tier-aware feed-health snapshot (signals_stale flag + per-feed status). */
        get: operations["getFeedHealth"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/sanity": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * The fan-out guard's standing flags (KN-SANITY-1).
         * @description Components whose discovery answered a version Themis cannot parse with at least the configured number of distinct CVEs — the shape of a false-positive class. Measurements with a name on them; nothing here was dropped or decided. Empty with header `X-Themis-Sanity: not-wired` when the guard is not configured.
         */
        get: operations["getSanityFlags"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/releases/{releaseId}/fix-verdicts": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * For every live occurrence of one release, whether a published fix exists that the install has not picked up (EDR-REBUILD-01 D19, D30).
         * @description Serves the RECORDED occurrence verdict, so a consumer in another context never orders version strings itself. `fix` is `known` when the occurrence is open and below at least one vendor bound for its own package and world, `none` when there is nothing to pick up (already cleared, or compared with no bound on record), and `unknown` when Themis could not compare (an ecosystem the fixed-verdict does not cover, or an rpm build that names no EL stream). Unknown is not a known fix. Read-only; a release with no match is an empty list. 503 when the read is not wired.
         */
        get: operations["getReleaseFixVerdicts"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/scanner-reports/{evidenceId}/unresolved": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Components a scanner report NAMED but whose identity could not be established.
         * @description EDR-IDENTITY-01 D6. An observation whose purl is absent or unusable is resolved onto the release's own component when exactly one matches by name+version; anything else abstains and is reported here. These observations do NOT reach the Governance posture, so they are neither findings nor bystanders — they are evidence Themis holds and cannot yet identify.
         *
         *     Recomputed on demand from immutable evidence rather than stored: D5 deliberately keeps the observed identifier out of Knowledge's rows, so this reads the report and the release inventory back through the SAME code path the ingest uses. The answer therefore cannot drift from the behaviour it describes.
         */
        get: operations["getUnresolvedComponents"];
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
        PublishedCVE: {
            cve: string;
            /** Format: date-time */
            published: string;
            summary?: string;
            severity?: string;
            cvss_score?: number;
            /** @description Whether the estate already holds a card for this CVE. */
            carded: boolean;
            /**
             * Format: date-time
             * @description When the source last changed its record (NVD lastModified). Absent when the source states none; never the time Themis fetched it (EDR-PSIRT-01 P1).
             */
            modified?: string;
            /** @description The CWE ids the source states for the flaw, normalized ("CWE-787"), sorted by number. NVD placeholders such as NVD-CWE-noinfo are not CWE ids and are left out. */
            cwes?: string[];
            /** @description A short issue-type word from Themis's fixed CWE table (EDR-PSIRT-01 choice 6, table version in issue_type_table), for example "Code execution" or "Denial of service"; "Other" for CWEs the table does not map. Absent when the source states no CWE. A display label only: nothing decides on it. Always show the cwes beside it. */
            issue_type?: string;
            /** @description The version of the CWE-to-issue-type table that produced issue_type. */
            issue_type_table?: string;
            /** @description The application products the source says carry the flaw (NVD CPE application parts). Empty for a record NVD has not analysed yet. The PSIRT alert matches these names against product component names (EDR-PSIRT-01 Q1). */
            affected_products?: string[];
        };
        PSIRTAlerts: {
            alerts: components["schemas"]["PSIRTAlert"][];
            /** @description The product inventory could not be read (Registry or Evidence unreachable, or not wired). Rows are still listed, but none carries matches, so the page must not read "no product hit". */
            estate_unavailable: boolean;
            /** @description Rows that needed a CVE.org lookup (NVD had no score or no affected names) beyond the per-read cap; those rows are shown as NVD gave them. */
            lookups_skipped: number;
            /** @description The oldest CVEs of the window that were not read, because the window holds more than the read's page budget. The read keeps the newest, which an alert is about. */
            older_not_read: number;
            /** @description The version of the CWE-to-issue-type table behind every issue_type. */
            issue_type_table: string;
        };
        PSIRTAlert: {
            cve: string;
            /** Format: date-time */
            published: string;
            /**
             * Format: date-time
             * @description The source's last change; absent when not stated.
             */
            modified?: string;
            summary?: string;
            /** @description The highest source CVSS Base score seen (owner choice A). */
            original_score: number;
            /** @description The CVSS qualitative rating of original_score. */
            original_severity: string;
            /** @description Where original_score came from (nvd | cve.org). */
            score_source: string;
            cwes?: string[];
            /** @description Short issue-type word from the fixed CWE table; absent when no CWE is stated. */
            issue_type?: string;
            /** @description The normalized affected names the match used (NVD CPE products, CVE.org CNA affected). */
            affected_products?: string[];
            /** @description The product components the CVE may hit. Empty means no name matched, never "not affected". */
            matches: components["schemas"]["PSIRTMatch"][];
            /** @description Whether the estate already holds a card for this CVE (it is already in the engine). */
            carded: boolean;
            bulletin?: components["schemas"]["BulletinRef"];
        };
        BulletinInput: {
            /** @description The team's bulletin number (at most 64 characters). */
            bulletin_id: string;
            /** @description At most 300 characters. */
            title: string;
            /** @description The bulletin's page (an absolute http or https link), or empty. */
            bulletin_url?: string;
            /** @description The TSN or alert page (an absolute http or https link), or empty. */
            alert_url?: string;
            /** @description Free text, at most 4000 characters. */
            note?: string;
            /** @description The one CVE the bulletin is about, or empty for a risk with no CVE. */
            cve?: string;
            /**
             * Format: date
             * @description The day it was reported; absent means today on a create, unchanged on an edit.
             */
            report_date?: string;
        };
        Bulletin: {
            id: string;
            bulletin_id: string;
            title: string;
            bulletin_url: string;
            alert_url: string;
            note: string;
            cve: string;
            /** Format: date */
            report_date: string;
            /** @description Derived (R6), never typed. Vulnerability when a CVE is given, Risk when not. */
            type: string;
            /** Format: date-time */
            created_at: string;
            created_by: string;
            /** Format: date-time */
            updated_at: string;
            updated_by: string;
        };
        BulletinChange: {
            /** Format: date-time */
            at: string;
            actor: string;
            /** @description created | updated | removed. */
            action: string;
            before?: components["schemas"]["Bulletin"];
            after?: components["schemas"]["Bulletin"];
        };
        BulletinRef: {
            id: string;
            bulletin_id: string;
            title: string;
            bulletin_url: string;
        };
        PSIRTMatch: {
            product_id: string;
            product_name: string;
            component: string;
            /** @description What tied the CVE to the component: "themis" when the Themis engine already filed it against a release of the product (exact, version-aware); otherwise the affected name that matched ("vendor:product" for a match on a path's last segment). */
            matched_on: string;
        };
        RecentFaultline: {
            /**
             * Format: date-time
             * @description When the card was created — the moment the CVE entered the estate's knowledge.
             */
            created_at: string;
            card: components["schemas"]["FaultlineView"];
        };
        FaultlineView: {
            id?: string;
            cve?: string;
            stage?: string;
            view?: components["schemas"]["EnterpriseView"];
            proposals?: components["schemas"]["ProposalProvenance"][];
        };
        EnterpriseView: {
            severity?: string;
            /** @description The winning source's short account of WHAT this vulnerability is (e.g. NVD's English description or OSV's summary), chosen by the same precedence rule as the headline severity but in an independent race. Bounded at ingestion. Descriptive only — no verdict consumes it, and it carries no trust class for exactly that reason. */
            summary?: string;
            /** @description Which source won the summary (explainability, mirrors severity_source). */
            summary_source?: string;
            cvss_score?: number;
            cvss_vector?: string;
            severity_source?: string;
            affected_ranges?: string[];
            /** @description The same ranges WITH the ecosystem and package each was published for (KN-RANGE-ECO-1). A consumer judging ONE component selects the statements of its ecosystem (and package, when named); a statement with no ecosystem applies to all; a card with no statements is judged on `affected_ranges` as before. */
            affected_range_statements?: components["schemas"]["RangeStatement"][];
            /** @description Flat union of every fix version on the card, across ALL affected packages. Use it for "is a fix published?" and NEVER to decide about one component — a version here may belong to a different package entirely. Use `fixes` for that. */
            fixed_versions?: string[];
            /** @description Fix versions ATTRIBUTED to the package each applies to. One CVE routinely affects many packages (a RHEL module advisory can name hundreds), and only this form can answer "what fixes MY component?". `package` is absent when the source did not say — NVD's CPE data and scanner reports state a fix without naming the package — and an unattributed fix must never satisfy a per-component verdict. */
            fixes?: components["schemas"]["FixedVersion"][];
            epss?: number;
            kev?: boolean;
            /**
             * Format: date
             * @description When CISA listed the CVE in its Known Exploited Vulnerabilities catalogue (EDR-REMEDIATION-01 D5). Absent when not stated.
             */
            kev_added?: string;
            /**
             * Format: date
             * @description CISA's remediation due date for the CVE. Absent when not stated. Governance's SLA takes the earlier of this and its own deadline.
             */
            kev_due?: string;
            /** @description CISA marks the CVE as known to be used in ransomware campaigns. */
            kev_ransomware?: boolean;
            exploit_public?: boolean;
            /** @description Deterministic exploitability level (critical | high+ | high | elevated | informational). */
            priority?: string;
            /** @description CVE-intrinsic composite priority score, 0-100 (severity baseline + EPSS + KEV; excludes release-scoped blast). */
            score?: number;
            /**
             * @description Trust class of the sources that contributed the affected ranges / fixed versions (EDR-TRUST-01 T2/T3). Absent when no range evidence contributed. Per field-group, not per card - a vendor statement elsewhere must not downgrade public ranges.
             * @enum {string}
             */
            range_trust?: "observed" | "asserted" | "inferred";
            /** @description The products the flaw-describing sources say CARRY the flaw (EDR-CORRELATION-01 D4) — the union across sources, normalized. This is the OTHER SIDE of a correlation: a component matched against these is a `carrier`, one that matched none is `scope` (it was in the rebuild set). Carried on the read API so a consuming context can NAME the carrier when no component matched it, instead of leaving a reviewer to infer the fact from a claim class (EDR-ATTRIBUTION-01 D10). Empty means no source named a carrier at all, which is a materially different gap from "carrier named, none matched". */
            carrier_products?: string[];
            /** @description Vendor VEX applicability statements held on the card (carried, not applied — Governance decides whether to honor a not_affected for a release). */
            applicabilities?: components["schemas"]["Applicability"][];
        };
        SourceRatings: {
            cve: string;
            observations: components["schemas"]["SourceObservation"][];
            ratings: components["schemas"]["SourceRating"][];
        };
        /** @description A source's own timestamp kept as received, its UTC reading, and how it was read. */
        SourceTime: {
            original?: string;
            /** Format: date-time */
            instant?: string;
            /** @enum {string} */
            interpretation?: "zone_stated" | "zone_assumed_utc" | "unparseable";
        };
        SourceObservation: {
            id: string;
            source: string;
            feed: string;
            document_ref: string;
            revision?: string;
            /** @description The canonical content fingerprint; identifies the revision when the source states none. */
            fingerprint?: string;
            updated_at?: components["schemas"]["SourceTime"];
            complete: boolean;
            applicability?: string[];
            severity_word?: string;
            /** Format: date-time */
            first_observed_at: string;
        };
        SourceRating: {
            id: string;
            observation_id: string;
            source: string;
            feed: string;
            assessor: string;
            /** @description The assessor under the linking policy's alias table (one key per organisation, e.g. nvd@nist.gov and NVD both read nvd). Consumers compare assessors by this key. */
            assessor_key?: string;
            publisher?: string;
            nvd_type?: string;
            cvss_version: string;
            vector: string;
            stated_score?: number;
            severity_word?: string;
            asserted_context?: string;
            inherited_context?: string;
            effective_context?: string;
            /** Format: date-time */
            recorded_at: string;
            /** @enum {string} */
            status: "active" | "superseded" | "withdrawn";
            status_event?: components["schemas"]["SourceRatingEvent"];
            validation?: components["schemas"]["RatingValidation"];
            identity?: components["schemas"]["AssessmentIdentity"];
        };
        SourceRatingEvent: {
            /** @enum {string} */
            kind: "superseded" | "withdrawn";
            caused_by: string;
            replaced_by?: string;
            source_time?: components["schemas"]["SourceTime"];
            /** Format: date-time */
            learned_at: string;
        };
        RatingValidation: {
            calculator_version: string;
            spec_version?: string;
            /** @enum {string} */
            result: "valid" | "invalid_vector" | "unsupported_cvss_version";
            reason?: string;
            base_score?: number;
            temporal_score?: number;
            /** @enum {string} */
            stated_comparison?: "equal" | "differs" | "not_stated";
            /** Format: date-time */
            validated_at?: string;
        };
        AssessmentIdentity: {
            key: string;
            linked?: boolean;
            ambiguous_link?: boolean;
        };
        FixedVersion: {
            package?: string;
            version?: string;
            /** @description Canonical ecosystem the fix was published for (rpm, apk, npm, ...). Absent when the source did not say; a consumer must treat an absent ecosystem as matching any component (only positive evidence of mismatch excludes). */
            ecosystem?: string;
        };
        FixVerdict: {
            faultline_id: string;
            cve: string;
            purl: string;
            /** @description The component version the occurrence was judged with. */
            version: string;
            ecosystem: string;
            /** @description The recorded occurrence verdict (`open` or `cleared_vendor_fix`). */
            state: string;
            /** @enum {string} */
            fix: "known" | "none" | "unknown";
            /** @description The vendor fix bounds the open occurrence is below; empty unless `fix` is `known`. */
            behind: string[];
        };
        SanityFlag: {
            release_id: string;
            purl: string;
            version?: string;
            ecosystem?: string;
            /** @description Distinct CVEs the feed returned for this component in one discovery. */
            cves: number;
            reason: string;
            /** Format: date-time */
            flagged_at: string;
        };
        RangeStatement: {
            /** @description Canonical ecosystem key (rpm, apk, deb, go, pypi, npm, ...); absent when the source did not say. */
            ecosystem?: string;
            /** @description The package the range was published for; absent when the source did not say. */
            package?: string;
            range: string;
        };
        Applicability: {
            package?: string;
            /**
             * @description The VENDOR'S assertion, from the closed set (EDR-VEX-02 D13): the OpenVEX four plus Red Hat's `will_not_fix`, `fix_deferred` and `out_of_support`. Never carries Themis's determination.
             * @enum {string}
             */
            status?: "not_affected" | "affected" | "fixed" | "under_investigation" | "will_not_fix" | "fix_deferred" | "out_of_support";
            justification?: string;
            /** @description On a `fixed` statement, the advisory that shipped the fix (D14). Absent otherwise. */
            advisory?: string;
            /** @description On a `fixed` statement, the build the advisory shipped (a NEVRA or a module stream id). Absent otherwise. */
            fixed_version?: string;
            /** @description The product FAMILY the vendor said this statement covers, classified from the source document's structured CPE (EDR-VEX-02 D5) — e.g. `enterprise-linux` for Red Hat Enterprise Linux and its 1:1 rebuilds. Part of the vendor's statement, NOT a conclusion about it. Empty means the vendor supplied no readable scope, which a consumer MUST read as applicability `unknown` (epistemic uncertainty), never as a product mismatch. */
            scope_family?: string;
            /** @description The major version of that family, e.g. `8`. Empty carries the same meaning as an empty `scope_family`. */
            scope_major?: string;
        };
        ProposalProvenance: {
            source?: string;
            kind?: string;
            /** Format: date-time */
            observed_at?: string;
        };
        FeedHealthReport: {
            /** @description True when any Tier-1 (critical) feed is stale — the platform's signals are unreliable. */
            signals_stale?: boolean;
            feeds?: components["schemas"]["FeedHealthEntry"][];
            /** @description Sources of Tier-2 feeds currently failing (degraded, non-blocking). */
            degraded_feeds?: string[];
        };
        FeedHealthEntry: {
            source?: string;
            tier?: number;
            /** @description healthy | stale | degraded | informational. */
            status?: string;
            consecutive_failures?: number;
            /** Format: date-time */
            last_success_at?: string | null;
        };
        Problem: {
            title?: string;
            detail?: string;
        };
        UnresolvedComponentsReport: {
            evidence_id: string;
            release_id: string;
            /** @description Observations that reached an identity — either their own or an unambiguous twin's. */
            resolved: number;
            /** @description Observations retained and counted, with no identity established. */
            unresolved: number;
            components: components["schemas"]["UnresolvedComponent"][];
        };
        UnresolvedComponent: {
            name: string;
            version: string;
            ecosystem?: string;
            /** @description Which scanner engine observed it (`scanner/<name>`). */
            origin?: string;
            /** @description The identifier the report offered, verbatim and unmodified — empty when it offered none. Never synthesized: EDR-IDENTITY-01 D3 forbids manufacturing a purl, because a purl TYPE is an ecosystem claim. */
            observed_purl?: string;
            /**
             * @description `no_candidate` — nothing on the release matches this name+version (the common case is a scanner-only release, which has no SBOM and therefore never a twin). `ambiguous` — several distinct identities match, which is exactly where a guess would be wrong, so no tie-break is invented.
             * @enum {string}
             */
            reason: "no_candidate" | "ambiguous";
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
    getFaultlineByCVE: {
        parameters: {
            query: {
                cve: string;
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
                    "application/json": components["schemas"]["FaultlineView"];
                };
            };
            400: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
        };
    };
    getFaultlinesByAdvisory: {
        parameters: {
            query: {
                id: string;
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
                    "application/json": components["schemas"]["FaultlineView"][];
                };
            };
            400: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getRecentFaultlines: {
        parameters: {
            query?: {
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
                    "application/json": components["schemas"]["RecentFaultline"][];
                };
            };
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getPublishedRecently: {
        parameters: {
            query?: {
                days?: number;
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
                    "application/json": components["schemas"]["PublishedCVE"][];
                };
            };
            502: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getPSIRTAlerts: {
        parameters: {
            query?: {
                days?: number;
                min_severity?: string;
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
                    "application/json": components["schemas"]["PSIRTAlerts"];
                };
            };
            502: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    listBulletins: {
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
                    "application/json": components["schemas"]["Bulletin"][];
                };
            };
            503: components["responses"]["Problem"];
        };
    };
    createBulletin: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BulletinInput"];
            };
        };
        responses: {
            /** @description Created. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Bulletin"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            409: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    updateBulletin: {
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
                "application/json": components["schemas"]["BulletinInput"];
            };
        };
        responses: {
            /** @description OK. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Bulletin"];
                };
            };
            400: components["responses"]["Problem"];
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            409: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    removeBulletin: {
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
            /** @description Removed. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            403: components["responses"]["Problem"];
            404: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getBulletinHistory: {
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
                    "application/json": components["schemas"]["BulletinChange"][];
                };
            };
            503: components["responses"]["Problem"];
        };
    };
    getFaultlineById: {
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
                    "application/json": components["schemas"]["FaultlineView"];
                };
            };
            404: components["responses"]["Problem"];
        };
    };
    getFaultlineReleases: {
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
                    "application/json": string[];
                };
            };
        };
    };
    getFaultlineRatings: {
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
                    "application/json": components["schemas"]["SourceRatings"];
                };
            };
            404: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    gatherCVE: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    /** @description The CVE id to gather (e.g. CVE-2026-12345). */
                    cve: string;
                };
            };
        };
        responses: {
            /** @description The gather ran; each wired source reports found / recorded / withdrawn / error independently. found=false everywhere is an honest answer (the world has nothing yet), not a failure. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        cve: string;
                        /** @description The card the facts folded into, when one exists after the gather. */
                        faultline_id?: string;
                        sources: {
                            source: string;
                            found?: boolean;
                            /** @description a NEW Proposal folded; a restatement reads false */
                            recorded?: boolean;
                            withdrawn?: boolean;
                            /** @description per-source failure - reported, never fatal to the gather */
                            error?: string;
                        }[];
                    };
                };
            };
            400: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            /** @description No per-CVE source is wired on this node. */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getFeedHealth: {
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
                    "application/json": components["schemas"]["FeedHealthReport"];
                };
            };
        };
    };
    getSanityFlags: {
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
                    "application/json": components["schemas"]["SanityFlag"][];
                };
            };
        };
    };
    getReleaseFixVerdicts: {
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
                    "application/json": components["schemas"]["FixVerdict"][];
                };
            };
            400: components["responses"]["Problem"];
            500: components["responses"]["Problem"];
            503: components["responses"]["Problem"];
        };
    };
    getUnresolvedComponents: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description The scanner-report evidence id returned by the upload. */
                evidenceId: string;
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
                    "application/json": components["schemas"]["UnresolvedComponentsReport"];
                };
            };
            /** @description No such evidence document. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
            /** @description The document is not a scanner report, so it has no observations to resolve. */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
            500: components["responses"]["Problem"];
        };
    };
}
