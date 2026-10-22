# DefectDojo vs Themis — capability comparison and port candidates

Status: research note, 2026-10-22. Not a decision. Anything ranked below as "port" still goes through
the normal gate (EDR or amendment first, "Must ask" items in CLAUDE.md).

Sources: DefectDojo official docs (docs.defectdojo.com, read 2026-10-22, docs version 3.x) and the
`master` branch of github.com/DefectDojo/django-DefectDojo as of the same day. GitHub links point at
`master`, not a pinned commit, and carry no line numbers (the files were read through a fetch tool that
did not expose them). Pin a commit before quoting any of them in an EDR.

Short names used below: `DD` = DefectDojo; `DDsrc` = `https://github.com/DefectDojo/django-DefectDojo/blob/master`;
`DDdocs` = `https://docs.defectdojo.com`.

## 1. Summary

DefectDojo is a general application-security findings manager. It takes reports from several hundred
scanners (SAST, DAST, SCA, cloud, pentest notes), puts them in a hierarchy (Organization, formerly
Product Type → Asset, formerly Product → Engagement → Test → Finding), removes duplicates by a hash per
parser, and tracks each Finding through a set of status flags (active, verified, false positive, out of
scope, risk accepted, mitigated). On top of that it has SLAs per severity, risk acceptances that expire,
Jira sync in both directions, notifications over mail, Slack, Teams and webhooks, and metrics pages.
Themis is narrower and deeper. It handles software supply chain risk only (SBOMs, scanner reports, VEX).
It keeps one enterprise card per CVE (Faultline), correlates releases against live feeds within a
relevance bound, and records decisions as append-only Positions that only a human or a narrow policy
can establish. It publishes VEX, and it runs a rebuild loop per release.

The two overlap on ingest, deduplication, triage state, risk acceptance, Jira, mail and per-product
access. In that overlap DD is broader and more mature in four places: parser breadth, SLA policy,
notification channels, and metrics. Themis is deliberately different in four others: Positions instead
of flags, no auto-close on absence, vendor VEX as information rather than truth, and one ticket per
release. **Is there something worth porting? Yes, but only ideas, and mostly in Governance and
Communication:** an SLA policy, a few risk-acceptance fields (owner, treatment, warning before expiry),
the reimport outcome vocabulary, a webhook channel that tracks its own health, richer KEV fields, and DD's
parser field mappings as a reference for new intake dialects. DD's core triage model should not be
ported. Its flags, auto-close and Jira-driven status changes contradict Themis doctrine.

## 2. Capability matrix

Themis column: **have** / **partial** / **missing**, with the file or decision that proves it.

| Capability | DefectDojo (source) | Themis |
| --- | --- | --- |
| Hierarchy | Organization → Asset → Engagement (Interactive or CI/CD) → Test → Finding. Older Product Type/Product names remain behind `ENABLE_V3_ORGANIZATION_ASSET_RELABEL` ([DDdocs/asset_modelling/os_hierarchy/os__asset_hierarchy/](https://docs.defectdojo.com/asset_modelling/os_hierarchy/os__asset_hierarchy/); [DDsrc/dojo/metrics/urls.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/metrics/urls.py)) | **have**, different shape: Product → Project → Release, plus the estate graph Product → Microservice → Deployment → Customer (`api/registry.openapi.yaml`; EDR-ESTATE-01 D2). There is no Engagement or Test level. Evidence documents per release play the Test role (EDR-INTAKE-01 D8). |
| Finding identity | One Finding per parsed row per Test, deduplicated later (`dojo/finding/models.py`) | **have**, structural: one Finding per (Release, Faultline) (EDR-GOVERNANCE-01 D1), and one Faultline per canonical CVE with aliases (EDR-KNOWLEDGE-01 D1). |
| Global vulnerability record | New `Vulnerability` model: one row per id string (CVE, GHSA), EPSS/KEV cached on it, linked to Findings in order through `FindingVulnerabilityReference`. Aliases are not modelled, and ids are stored as supplied. The old `Vulnerability_Id` is frozen and marked "NO LONGER READ OR WRITTEN" ([DDsrc/dojo/vulnerability/models.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/vulnerability/models.py); [DDsrc/dojo/finding/models.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/finding/models.py)) | **have**, further along: the Faultline is one card per canonical CVE, aliases are normalized, sources write append-only Proposals, and the reconciled view and lifecycle are deterministic (EDR-KNOWLEDGE-01 D1, D2, D7). |
| Deduplication | Per-parser algorithm: `hash_code`, `unique_id_from_tool`, `unique_id_from_tool_or_hash_code`, or `legacy` (title, CWE, line, file path, description). Hash fields are set per scanner in `HASHCODE_FIELDS_PER_SCANNER`, and `service` is always included. Scope is the Asset, optionally narrowed to an Engagement. Cross-tool dedup is listed as a Pro feature ([DDdocs/triage_findings/finding_deduplication/about_deduplication/](https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/); [DDsrc/dojo/settings/settings.dist.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py)) | **have**, different mechanism: identical evidence bytes dedupe by SHA-256 (EDR-EVIDENCE-01 D3), and findings dedupe by design because every scanner's row for one CVE on one release lands on the same (Release, Faultline) Finding. Cross-tool dedup therefore costs nothing in Themis. |
| Reimport semantics | Matches by the parser's algorithm, then sorts results into four buckets: new, reactivated, closed and untouched. `close_old_findings` (default true in the API) marks unmatched Findings inactive and mitigated, with the note "Mitigated by <type> re-upload". `do_not_reactivate` keeps closed Findings closed when they reappear ([DDsrc/dojo/importers/default_reimporter.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/importers/default_reimporter.py); [DDdocs/import_data/import_intro/reimport/](https://docs.defectdojo.com/import_data/import_intro/reimport/)) | **partial**: several SBOMs per release are kept (EDR-INTAKE-01 D8), and the release comparison exists (`GET /releases/{id}/compare/{candidate}`, EDR-GOVERNANCE-01 D16; baseline N-M2e). Nothing closes on absence. That gap is the open, design-gated **EV-CURRENT-SBOM-1** (`docs/BACKLOG.md`). |
| Status model | Independent booleans: `active`, `verified`, `false_p`, `duplicate`, `out_of_scope`, `risk_accepted`, `under_review`, `is_mitigated`. `status()` joins whichever are set ("Inactive, Mitigated"…) ([DDsrc/dojo/finding/models.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/finding/models.py)) | **have**, deliberately different: the Finding lifecycle (Identified → Under Investigation → Position Established → Monitoring → Resolved → Archived, EDR-GOVERNANCE-01 D7) is kept apart from append-only Position versions (D2, D3). Stances: `affected`, `not_affected`, `under_investigation`, `mitigated`, `accepted_risk`, `deferred` (`internal/governance/domain/stance.go`). |
| False-positive history | Marked EXPERIMENTAL. A new Finding matching an earlier false positive in the same Asset is set false positive. An optional retroactive mode rewrites other matches with no preview ([DDdocs/…/false_positive_history/](https://docs.defectdojo.com/triage_findings/finding_deduplication/false_positive_history/)) | **have**, stricter: roll-forward *proposes* a sibling release's human judgement on Inferred evidence, and no policy can accept that proposal (EDR-ROLLFORWARD-01 D1, D2, D4). |
| Risk acceptance | `Risk_Acceptance` holds: `owner`; `recommendation` and `decision`, each one of Accept/Avoid/Mitigate/Fix/Transfer; free-text details; a proof file; `expiration_date`; `expiration_date_warned` and `expiration_date_handled`; `reactivate_expired` (default true); `restart_sla_expired`. A job runs every 3 hours ([DDsrc/dojo/risk_acceptance/models.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/risk_acceptance/models.py); settings.dist.py `risk_acceptance_expiration_handler`) | **partial**: `accepted_risk` stance with rationale, `review_by`, premise snapshot (`DecidedWith`), drift + review-by sweep → `disposition_stale` (EDR-GOVERNANCE-01 D14, RF-2; `internal/governance/domain/disposition.go`). Missing: named owner distinct from decider, treatment type (transfer/avoid), proof attachment, pre-expiry warning. |
| SLA | Per-Asset config with days for each severity (defaults 7/30/90/120), an enforce flag per severity, and `restart_sla_on_reactivation`. The clock starts when the Finding is created and keeps counting negative after a breach. "Mitigated within SLA" is shown per Finding. A daily job (`compute-sla-age-and-notify`, 07:30) sends breach notifications ([DDsrc/dojo/models.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/models.py) `SLA_Configuration`; [DDdocs/asset_modelling/os_hierarchy/os__sla_configuration/](https://docs.defectdojo.com/asset_modelling/os_hierarchy/os__sla_configuration/)) | **missing**: filed as **REP-1a** ("fix-within-N-days per severity: the policy config does not exist; timestamps do", `docs/BACKLOG.md`). |
| Planned remediation | `planned_remediation_date`, `planned_remediation_version`, `fix_available`, `fix_version` on the Finding (`dojo/finding/models.py`) | **partial**: published fix version and vendor `fixed` statement with advisory/build (EDR-VEX-02 D14); target-release planning is a named gap in **REP-2**. |
| Jira | One issue per Finding (default), one per Finding Group, or an Epic per Engagement. "Push All Issues" pushes active and verified Findings automatically. A webhook brings changes back: the close transition marks the Finding mitigated, reopen makes it active, a mapped Resolution sets risk accepted or false positive, and comments become notes ([DDdocs/connectors/os_jira/os__jira_guide/](https://docs.defectdojo.com/connectors/os_jira/os__jira_guide/)) | **have**, deliberately one-way: one ticket per Release, listing CVE ids for Critical and High only, updated in place. "No Themis state follows from a Jira transition" (EDR-DELIVERY-01 RC-2, D-N-7; `internal/communication/adapters/delivery/jira.go`). |
| Notifications | 18 event types, including `scan_added`, `scan_added_empty`, `sla_breach`, `sla_breach_combined` (one message per product), `risk_acceptance_expiration`, `jira_update` and `review_requested`. Channels: alert, mail, Slack, Teams, webhooks, each set globally, per user or per product. A webhook records its own health (`active`, `active_tmp`, `inactive_tmp`, `inactive_permanent`, plus first and last error) ([DDsrc/dojo/notifications/models.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/notifications/models.py); [DDdocs/admin/notifications/about_notifications/](https://docs.defectdojo.com/admin/notifications/about_notifications/)) | **partial**: decision mail, evaluation mail and dead-letter mail over SMTP (`mail.go`); a cursor feed of release-evaluated events (`GET /events/release-evaluated`, N-M2d); `disposition_stale.v1` event. No Slack/Teams/generic webhook channel, no per-user subscription. |
| Metrics and reports | Metrics views by Organization, Asset tag counts, critical Assets, a simple view and per-engineer views. A report builder. The SLA dashboards are Pro ([DDsrc/dojo/metrics/urls.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/metrics/urls.py); [DDdocs/metrics_reports/dashboards/](https://docs.defectdojo.com/metrics_reports/dashboards/)) | **partial**: release posture with `effective_priority` and `residual_priority` (D14, D17), product traversal (DASH-1), VEX rollup per release (EDR-COMMUNICATION-01 D13), Prometheus metrics. The named report set (REP-1) and the workflow-state metrics page (REP-2) are filed and not built. |
| EPSS / KEV | Fields: `epss_score`, `epss_percentile`, `known_exploited`, `ransomware_used`, `kev_date`, plus `kev_due_date` on Vulnerability. Automatic daily enrichment is documented as **Pro**; a Finding with several CVEs takes the highest EPSS among them ([DDdocs/triage_findings/finding_scoring/epss_kev/](https://docs.defectdojo.com/triage_findings/finding_scoring/epss_kev/); `dojo/vulnerability/models.py`) | **have** (EPSS + KEV bool + ExploitDB, relevance-bounded sweep, `THEMIS_EPSSKEV_ENABLED`; `internal/knowledge/adapters/feed/epsskev.go`), and the signals feed drift detection (D14). Missing: KEV date added, due date, ransomware flag. |
| Component / purl | Free-text `component_name` and `component_version` on the Finding. Some parsers derive them from a purl. Component-level grouping exists ([DDsrc/dojo/finding/models.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/finding/models.py)) | **have**, stronger: a canonical inventory per evidence document, purl-first identity that abstains on ambiguity (EDR-INTAKE-01 D4, EDR-IDENTITY-01 D6), carrier/scope claim class (EDR-CORRELATION-01 D3), verdict per occurrence (EDR-VERDICT-01). |
| Parser breadth | About 360 entries on the supported-tools page; the page also claims "500+ security reports". A Generic Findings Import format is offered, and the Universal Parser is Pro ([DDdocs/supported_tools/](https://docs.defectdojo.com/supported_tools/)) | **partial**: four dialects (curated, Trivy, Grype, Cortex) plus CycloneDX/SPDX SBOMs and CSAF/OpenVEX (`internal/evidence/adapters/report/`; EDR-INTAKE-01 D4). |
| Finding groups | `Finding_Group` within one Test, grouped by `component_name`, `component_name+component_version`, `file_path`, `finding_title` or `vuln_id_from_tool`. A group can become one Jira issue ([DDsrc/dojo/finding/helper.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/finding/helper.py)) | **have** in effect: Release is the ticket unit (RC-2), and `plan_remediation` groups Findings by package upgrade through a deterministic `GROUP BY` (CLAUDE.md, Intelligence). |
| Authorization | Open source 3.x uses Authorized Users lists per Organization or Asset, with no roles; staff and superusers bypass the lists. Pro has five roles (Reader, Writer, Maintainer, Owner, API Importer) and custom roles. The open-source `roles_permissions.py` still defines the roles, but its own comment says nothing reads them ([DDdocs/admin/user_management/os__authorized_users/](https://docs.defectdojo.com/admin/user_management/os__authorized_users/); [DDsrc/dojo/authorization/roles_permissions.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/authorization/roles_permissions.py)) | **have** for machines: API keys with a closed set of scopes (`admin`, `read`, `product:<id>`, `delivery:callback`), enforced at mint time and at read time, with a product-confined write path that fails closed (EDR-SECURITY-01 D4, EDR-DELIVERY-01 D1–D5). The principal is the audit actor (D10). Human roles are thin: the dashboard has a password login only. |
| Tags | Tags on Assets, Engagements, Tests and Findings, set at import or by bulk edit. An optional setting copies Asset tags down to everything beneath (`enable_product_tag_inheritance`). Tag counts appear in metrics ([DDdocs/asset_modelling/tags/os__tagging_objects/](https://docs.defectdojo.com/asset_modelling/tags/os__tagging_objects/)) | **missing** (no tag field in any greenfield OpenAPI spec). Partly covered by the estate graph (customer, deployment). |
| Benchmarks | OWASP ASVS v3.1 checklist per Asset, scored at levels 1–3 ([DDdocs/asset_modelling/os_hierarchy/benchmarks/](https://docs.defectdojo.com/asset_modelling/os_hierarchy/benchmarks/)) | **missing**, out of scope (see 3.13). |
| Endpoints | Hosts and URLs affected by a Finding, with status per endpoint. Pro replaces them with "Locations" (os__asset_hierarchy page) | **missing**, out of scope (no DAST or infrastructure findings). |
| VEX | No VEX status model. Out-of-scope and false-positive flags are the nearest thing (no DD source found for VEX import or export semantics) | **have**, central: vendor statements are kept whole with closed status and applicability (EDR-VEX-01, EDR-VEX-02 D1–D24). OpenVEX, CycloneDX-VEX and CSAF are published (EDR-COMMUNICATION-01 D7, D13). |
| AI | DD Pro advertises AI features; no open-source source was checked | **have**: an advisory Gateway with three capabilities, where an AI proposal can never be auto-accepted (EDR-GOVERNANCE-01 D15 note). |
| API | REST API v2 with token auth (DD's main integration surface) | **have**: OpenAPI written first, one spec per context (`api/*.openapi.yaml`). |

## 3. Gaps and differences — verdicts

**3.1 Reimport closes what is missing (`close_old_findings`).** *Out of scope under Themis doctrine,
"absence is not `not_affected`" and "a Finding is never auto-resolved"* (EV-CURRENT-SBOM-1; delivery
stop rules N-M2i). DD's default auto-mitigates every Finding a new report omits. A partial scan then
becomes a silent closure, which is exactly the trap EV-CURRENT-SBOM-1 names. **Port the vocabulary, not
the action.** The four buckets (new, reactivated, closed, untouched) are a clear way to report what one
upload changed. In Themis, "closed" would become "no longer present, pending a decision", which is a
proposal or projection and never a mitigation.

**3.2 `do_not_reactivate`.** *Out of scope*, and it is a lesson worth keeping. The flag exists to
silence "triage-less scanners". Dependency-Track's own integration notes warn that with it set, a
vulnerability re-introduced by a downgrade stays closed
([docs.dependencytrack.org/integrations/defectdojo/](https://docs.dependencytrack.org/integrations/defectdojo/)).
Themis already reopens through a governed path (EDR-GOVERNANCE-01 D7). Keep it that way.

**3.3 Hash-based deduplication per parser.** *Already covered by EDR-GOVERNANCE-01 D1 + EDR-KNOWLEDGE-01
D1.* DD has to tune hash fields per scanner because its Finding is a report row. Themis keys a Finding
on (Release, CVE card), so two scanners reporting one CVE already land on one Finding, with the detection
origin kept as provenance. DD's `legacy` algorithm (title + severity) is the loose matching that Themis
avoids. DD's hash-field choices are still useful reading as a record of which fields each tool keeps
stable: Trivy uses title, severity, vulnerability_ids, cwe and description; Grype uses title, severity,
component_name and component_version (settings.dist.py).

**3.4 Status flags versus Positions.** *Deliberately different, keep Themis.* DD's flags are independent
and can be overwritten, and the history is notes. Themis keeps the investigation lifecycle separate from
an append-only, immutable decision record with provenance (EDR-GOVERNANCE-01 D2, D3, D11). `verified` and
`under_review` have no Themis equivalent and need none: "has a Position" and "has open Proposals" carry
the same information with an author attached.

**3.5 False-positive history.** *Already covered by EDR-ROLLFORWARD-01*, which is the safer version:
scoped to one project, carrying only a human judgement, raised as a proposal at Inferred trust, and never
accepted by policy. DD's retroactive mode, which rewrites matches with no preview, is exactly the silent
mutation Themis forbids.

**3.6 Risk acceptance fields.** *Port the idea (partly).* Themis already beats DD on the hard part: an
acceptance expires when its premise moves (KEV, EPSS, exploit), not only on a date (D14). DD carries four
things Themis lacks, and REP-2 already asks for them: a named **owner** who is not necessarily the person
who recorded the decision; a **treatment** distinct from the stance (accept, avoid, mitigate, fix,
transfer); a **proof** attachment; and a **warning before expiry** (`expiration_date_warned`). DD's
`reactivate_expired=false` option has no Themis equivalent and should not get one. An expired
acceptance must come back (RF-2).

**3.7 SLA.** *Port the idea. DD is simply better here today.* Themis has the timestamps and no policy
(REP-1a). DD's model is small and proven: days per severity, an enforce flag per severity, a clock from
Finding creation, a negative count after breach, and a restart option on reactivation. Doctrine
constraint: a breach is information. It re-surfaces and notifies. It never changes a Position or the
Finding lifecycle.

**3.8 Jira both ways.** *Out of scope under D-N-7 (EDR-DELIVERY-01: "no Themis state follows from a Jira
transition").* DD lets a Jira Resolution set risk accepted or false positive. That makes Jira workflow
configuration an authority over Themis state, and it bypasses the Proposal → human → Position line.
Taking Jira **comments** in as read-only notes would not violate doctrine, but nothing needs it yet.
One issue per Finding is also out: RC-2 chose one ticket per release on purpose.

**3.9 Notification channels.** *Port the idea (one channel, plus health).* A generic outbound webhook
with a recorded health state (DD's `active` → `active_tmp` → `inactive_tmp` → `inactive_permanent`) fits
Communication's delivery intents and dead-letter model. Slack and Teams both accept an incoming webhook,
so one generic channel covers them. DD's `scan_added_empty` ("an import ran and changed nothing") and
`sla_breach_combined` (one digest per product) are good event choices. The doctrine constraint: a
notification is a projection, like Jira (D-N-7).

**3.10 Metrics.** *Port the idea, inside REP-1 and REP-2.* DD's open-source metrics are counts by Asset,
Organization and tag, plus an engineer view. Themis's posture numbers are more meaningful per release,
but it has nothing that rolls up across the estate over time: mean time to remediate, share mitigated
within SLA, open counts by age. These belong as Communication Publications (REP-1 home). An engineer
leaderboard is not worth porting.

**3.11 Parser breadth.** *Port the idea, one dialect at a time. DD is far ahead* (about 360 against 4).
EDR-INTAKE-01 D4 allows exactly one converter per dialect, built and tested server-side, and a second
converter counts as a defect. DD's parsers (`dojo/tools/<tool>/parser.py`) are useful references for
field mapping and for the edge cases they handle. Each new dialect must keep the abstention rule (ambiguous identity is never
invented, EDR-IDENTITY-01 D6). Candidates by fit: OSV-Scanner, Dependency-Track FPF, Snyk, OWASP
Dependency-Check, JFrog Xray, npm/yarn audit. SAST and DAST parsers do not fit: they report no
package identity.

**3.12 Global Vulnerability record.** *Already covered by EDR-KNOWLEDGE-01 D1, D2.* DD's new
`Vulnerability` table is a step toward the Faultline: one row per id with EPSS and KEV cached on it. It
lacks alias normalization, source proposals and a lifecycle. Two of its rules are worth noting because
Themis should already hold them: NULL means "not enriched", which is different from false, and the
Finding takes the worst value across its ids.

**3.13 Benchmarks (ASVS).** *Out of scope.* Themis is a supply-chain risk system, and a manual
verification checklist is application-security assurance, outside every bounded context. The license
and EOL "component compliance" idea (LIC-1, REP-1b) is the right home for anything like this.

**3.14 Endpoints / Locations.** *Out of scope.* There are no host or URL findings. The estate graph
answers "where is this deployed" (EDR-ESTATE-01).

**3.15 Tags.** *Port the idea, low priority.* A free label on Product, Project and Release, used to
filter and report (for example "internet-facing" or "regulated"), is cheap and useful in reports. The
constraint: a tag is a filter only. It must never feed `effective_priority`. Blast radius already does
that from facts (EDR-ESTATE-01 D5), and a priority driven by tags would be unreviewable.

**3.16 KEV detail.** *Port the idea.* DD stores `kev_date`, `kev_due_date` and `ransomware_used`. The KEV
catalog publishes all three. The due date is a natural default SLA for KEV-listed CVEs (the CISA
deadline), and the ransomware flag is a stronger drift signal than the KEV listing alone.

**3.17 Authorization.** *Already covered by EDR-SECURITY-01 (machines)*; human roles are thin.
Open-source DD 3.x dropped its roles in favour of lists, so it is no stronger here. Pro's "API Importer"
role (can import, cannot delete or manage members) matches what Themis's `product:<id>` scope gives a
CI bot. Adding a new scope would be a security model change (Must ask), and nothing yet shows a need for
one.

**3.18 Engagement level.** *Out of scope.* Themis has no "testing effort" object, and it does not need
one: a Release accumulates its evidence (EDR-INTAKE-01 D8). DD's CI/CD Engagement roughly corresponds to
a Themis Release under rebuild.

## 4. Ranked port list

Ordered by value to Themis divided by cost, highest first.

1. **SLA policy and breach projection (REP-1a).**
   - *What:* a fix-within-N-days policy per severity (a per-product override is optional), with an
     enforce flag per severity. The clock starts when the Finding is created. The posture shows days
     remaining or days overdue, and a release rollup shows the share fixed within SLA.
   - *Why it fits:* the timestamps exist, the gap is already filed, and DD's model is small and proven.
   - *Where:* the policy and its computation live in Governance as a read projection beside
     `residual_priority`; the report lives in Communication.
   - *Scope:* M.
   - *Constraint:* a breach never changes a Position or the lifecycle; it re-surfaces only. Two
     questions must be decided explicitly: whether the clock pauses during `accepted_risk` (DD restarts
     it on expiry when `restart_sla_expired` is set), and whether `disposition_stale` restarts it.
     Domain model change: Must ask.
2. **Risk-acceptance enrichment.**
   - *What:* on an `accepted_risk` or `deferred` Position, add an owner (accountable person), a
     treatment (accept, transfer, avoid), an optional proof reference, and a warning before `review_by`
     (for example N days ahead).
   - *Why it fits:* these are three of the REP-2 gaps, and the warning finishes RF-2 (today a person
     learns of an expiry only after it happens).
   - *Where:* Governance (`PositionInputs`); Communication delivers the warning.
   - *Scope:* S–M.
   - *Constraint:* Positions stay append-only, so changing the owner means a new Position version.
     Never offer DD's `reactivate_expired=false`. Domain model change and API change: Must ask.
3. **Upload outcome buckets: new / reappeared / no longer present / unchanged.**
   - *What:* the receipt for each SBOM or report, and the release comparison, say what one upload
     changed in DD's four-bucket terms.
   - *Why it fits:* it gives EV-CURRENT-SBOM-1 a precise output vocabulary, and it lets the rebuild
     loop's mail say "3 no longer present" without closing anything.
   - *Where:* Governance compare (D16) and N-M2e baseline; Evidence intake receipt (EDR-INTAKE-01 D9).
   - *Scope:* M.
   - *Constraint:* "no longer present" is never mitigated or `not_affected`. It is at most a proposal
     or a projection, and the EV-CURRENT-SBOM-1 design gate still decides what a decided Finding
     becomes.
4. **Generic outbound webhook channel with recorded health.**
   - *What:* a delivery intent kind `webhook` with the four health states, used for posture events,
     `disposition_stale`, SLA breach digests (one per product), and "import changed nothing".
   - *Why it fits:* it covers Slack and Teams without two more senders, and it reuses the intent,
     retry and dead-letter machinery.
   - *Where:* Communication (`internal/communication/adapters/delivery/`).
   - *Scope:* M.
   - *Constraint:* the webhook is a projection with no inbound authority (D-N-7). Secrets come from the
     environment (M1b-2). Payloads are materialized when enqueued (M1b-3). This is a new delivery kind,
     so it needs a CHECK-constraint migration (Must ask).
5. **KEV detail on the exploit signal.**
   - *What:* carry KEV `dateAdded`, `dueDate` and `knownRansomwareCampaignUse` beside the KEV boolean.
     Add "ransomware use became known" as a drift reason, and use the due date as the SLA default for
     KEV CVEs.
   - *Why it fits:* the data comes from the same feed Themis already sweeps, within the relevance
     bound.
   - *Where:* Knowledge (`epsskev.go`, the exploit-signal proposal); Governance reads it.
   - *Scope:* S.
   - *Constraint:* D5 (per-CVE over the carded set only); the field is additive on the event; drift
     stays one-directional.
6. **Intake dialects modelled on DD parsers.**
   - *What:* add OSV-Scanner, Dependency-Track FPF, Snyk and Dependency-Check as converters, studying
     DD's `dojo/tools/<tool>/parser.py` and their sample files for field mappings and edge cases.
   - *Why it fits:* parser breadth is DD's biggest real advantage, and EDR-INTAKE-01 already has the
     registry and the acceptance gate.
   - *Where:* Evidence (`internal/evidence/adapters/report/`).
   - *Scope:* M per dialect, added on demand.
   - *Constraint:* one converter per dialect (D4); byte-equal golden fixtures plus named semantic
     invariants; abstain on ambiguous identity (EDR-IDENTITY-01 D6); no converter before a real
     customer file exists (D16 "by demand").
7. **Estate-wide remediation metrics as a Publication (part of REP-1).**
   - *What:* mean time to Position and mean time to fix per product, open Findings by age band, share
     fixed within SLA.
   - *Why it fits:* Themis has strong numbers per release and no trend view. DD's metric pages show the
     questions managers ask.
   - *Where:* Communication (a serializer) over Governance reads.
   - *Scope:* M (after port 1).
   - *Constraint:* deterministic materialization, triggered by a human (EDR-COMMUNICATION-01 D3, D4).
     AI may add only a labelled summary, never the figures.
8. **Tags on Registry entities.**
   - *What:* free labels on Product, Project and Release, usable as a posture and report filter.
   - *Where:* Registry (storage), with read filters in Governance and Communication.
   - *Scope:* S–M.
   - *Constraint:* tags filter and never weight. Priority stays fact-derived (EDR-ESTATE-01 D5). API
     change: Must ask.

Not ported, on purpose: auto-close on reimport, `do_not_reactivate`, Jira-driven status, one ticket per
Finding, retroactive false-positive history, independent status flags, the legacy title+severity dedup,
ASVS benchmarks, endpoints.

## 5. Licensing

DefectDojo is BSD-3-Clause ([LICENSE.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/LICENSE.md)).
The license allows reuse of the code itself, as long as the copyright notice, the conditions and the
disclaimer are kept, and the DefectDojo name is not used to endorse derived work. Themis is Go and DD is
Python/Django, so nothing is copied in practice. What carries over is ideas and data facts: the SLA and
risk-acceptance field sets, the four-bucket reimport vocabulary, the webhook health states, and per-tool
parser field mappings, read as a reference for which report field means what. If a parser's sample files
(`unittests/scans/<tool>/`) are ever copied into Themis test fixtures, they come under the same notice:
keep DD's copyright line in the fixture directory. Better still, use fixtures from the tool's own
project or from the user's estate. Several of DD's documented features (Universal Parser, cross-tool
dedup, EPSS/KEV auto-enrichment, roles, SLA dashboards) are **Pro** and closed source. Study only what
the public docs describe, and do not read them as part of the BSD code.
