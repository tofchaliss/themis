# Tasks — phase3-correlation-sanity

No `specs/` deltas — archive with `openspec archive phase3-correlation-sanity --skip-specs -y`.

- [x] 1.1 Kernel `VersionParsable` + test.
- [x] 1.2 Guard in correlation (both roads), verdict stamp, recorder port; tests (flag, stamp,
  nothing dropped, parseable long history not flagged, below threshold, guard off, recorder
  failure, scanner road).
- [x] 1.3 Store table + upsert/list + integration test; `GET /sanity` [API] + handler test;
  census section 0; config + env template.
- [x] 1.4 EDR-CORRELATION-01 D9, BACKLOG, CLAUDE.md.
- [ ] 1.5 VM: deploy knowledge; `GET /sanity` empty on the current estate (go1.27.1 is now
  parseable); census section 0 reads "no fan-out flag standing".
