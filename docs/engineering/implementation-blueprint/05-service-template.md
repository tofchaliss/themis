# Blueprint 05 — Application-Service Template

Pattern (realized: `evidence/app`):

- Define **ports** (interfaces) in `app`, typed in domain/kernel terms — the adapters implement them; the
  app never imports adapters.
- The use case orchestrates ports and returns domain results + typed sentinel errors
  (e.g. `ErrUnknownSubject`, `ErrRejected`).
- Inject an `IDGenerator` and `Clock` port so the app stays free of `uuid` / wall-clock dependencies.
- The composition root (`cmd/<ctx>`) bridges concrete adapters onto the ports.

## Example — `EvidenceService.Register` (EDR-EVIDENCE-01 D1)

1. validate the subject Release exists (`SubjectRefValidator`) — reject unknown;
2. trust-gate (`TrustGate`) — fingerprint + validate;
3. parse an SBOM → canonical inventory (`Parser`); non-SBOM kinds carry none;
4. build the immutable aggregate (`domain.NewEvidence`);
5. persist + emit the event atomically (`Repository.Save`) and return the stable id.

Test the use case with **fakes** implementing the ports — 100% coverage, no database required. The
adapters' own tests cover their concrete behavior (golden files, integration).
