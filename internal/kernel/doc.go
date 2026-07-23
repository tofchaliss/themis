// Package kernel documents the Themis Shared Kernel — the common foundation every
// bounded context depends on (EDR-KERNEL-01). It has no code of its own; its members
// live in subpackages:
//
//   - value/ — behavior-free ubiquitous-language value objects (CVE-ID, PURL,
//     ContentFingerprint, CVSS, Severity), standard-library only;
//   - id/    — base primitives: opaque UUID identity + an injectable clock;
//   - event/ — the integration-event envelope contract crossing context boundaries.
//
// Admission rule (D3 · CON-0001): a member enters the kernel only if it is
// (1) used by every stage, (2) stable, (3) owned by no single context, and
// (4) behavior-free (no business behavior). This keeps the kernel from becoming the
// "central shared repository" CON-0001 rejects. The registry (internal/registry) is
// deliberately NOT here — it is stateful and has behavior; it is a supporting
// context beside the kernel.
//
// Import rule: internal/kernel imports nothing from any bounded context or from the
// registry (it is the leaf); everyone may import it. Enforced by depguard and the
// module architecture test (TestKernelIsLeaf).
package kernel
