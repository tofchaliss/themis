# Design — phase3-incident-b

- **Computed on read, never stored.** `WatchService.Status` resolves each identifier through
  Knowledge (CVE → card; advisory → cards by recorded `advisory`), walks each card's Findings
  through the Repository, and classifies each with `domain.WatchStateOf`. The order is the
  fail-safe one: a standing `not_affected` or accepting Position answers first (the human's
  answer), then the mirrored occurrence verdicts (every active component cleared ⇒ `fixed`,
  any open ⇒ open), then "no active component" ⇒ `not_affected`. `open_fix_available` means
  `selectFixesFor(card.Fixes, components)` is non-empty — the same selection the posture's fix
  column uses, so the two never disagree.
- **Every (release, CVE) is a row.** The release set is the union over the watched cards'
  Findings; a release with no Finding for one of the CVEs gets a `not_affected` row for it ("no
  component matches"), so the table has no holes. A carded CVE with no Finding anywhere is one
  row with no release; an unresolved identifier is one `unknown` row.
- **Seams fail the right way.** Knowledge failing is an error (a 500), never an empty table —
  "cannot tell" must not read as "nothing is affected"; no Knowledge seam is a 503. Registry
  (names) and Evidence (last proof) failing leave those columns blank; ids are always present.
- **The advisory alias is the one the feed already records.** EDR-VEX-02 D14 put `advisory` on
  every `fixed` statement of the reconciled view; the lookup is a JSONB scan of
  `view -> 'applicabilities'` upper-cased on both sides. Feeds that record no advisory resolve to
  nothing, and the EDR's "not decided" list keeps multi-vendor advisories out of scope.
- **Authority.** Reads need any key; create and add need a write-capable key (the router's method
  floor); delete is admin, because a Watch is somebody's working list. The creator is the key's
  name (its id when unnamed); on an auth-off node `created_by` is required.
- **D2a is stored, not acted on.** `notify` round-trips so the flag survives until the emitter
  arrives; nothing evaluates on `release_evaluated` / `fix_available` yet.
