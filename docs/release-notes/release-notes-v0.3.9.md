# Themis v0.3.9 — Feed registry (user-defined feeds)

Release tag: `v0.3.9` (**non-breaking** — additive config; existing `themis.yaml` files work
unchanged, rebuild + restart). Operators can now **add, override, or disable** vendor feeds instead
of being limited to the hardcoded set.

## What's new

A `vexfeed.feeds:` delta list, merged over the built-in defaults **by name**:

```yaml
vexfeed:
  feeds:
    - name: rocky            # disable a built-in by name
      enabled: false
    - name: my-distro        # add a custom correlation feed
      type: zip-osv          # url | zip-osv | csaf-dir
      class: correlation     # correlation (default) | overlay
      url: https://example.com/osv/all.zip
      ecosystem: mydistro
```

Built-in feed names: `rhel-vex` (overlay); `rhel-csaf`, `alpine`, `rocky`, `wolfi` (correlation).
Each delta entry can:

- **disable** a built-in — `enabled: false`;
- **override** a built-in's fields — set `url`, `type`, etc. under its name;
- **add** a custom feed — a new name with `type` + `url` (defaults to `class: correlation`).

## How it works

- `config.FeedConfig` + a new `Feeds []FeedConfig` field on `VEXFeedConfig` carry the delta list.
- `httpserver.ResolveVEXFeeds` derives the built-in defaults from the legacy `*_url` fields (so
  existing configs are unchanged), merges the delta list by name, and returns the two runtime feed
  lists: the **overlay** feeds (true Red Hat CSAF VEX) and the **correlation** feeds (distro OSV +
  RHSA advisories). `type` selects the source constructor (`csaf-dir`/`zip-osv`/`url`); `class`
  routes the feed to the overlay service vs the correlation loader.
- Enabled feeds with an unknown `type` or a missing `url` are **skipped with a logged warning**
  (they never silently misbehave). `api_wiring.go` consumes the resolved lists instead of
  hardcoding them.

The CR-4 feed *class* taxonomy (overlay vs correlation) and per-feed observability/health are
preserved — custom feeds get the same `degraded_feeds[]` reporting as built-ins.

## Notes

- **Non-breaking, no schema change.** A config that only sets the `*_url` fields behaves exactly as
  before.
- The deprecated `rhel_url` alias for `rhel_csaf_url` still works.
- See the README "Upstream vendor feeds" section and `themis.yaml.example`.

## Added (since v0.3.8)

- `feat(feeds)` — user-defined feed registry: `vexfeed.feeds` delta list (add / override / disable
  by name) merged over built-in defaults; `type`/`class` dispatch; skipped-feed warnings.
