// Package app is the registry's application ring: the register + lookup use cases
// over the Repository port, including ReleaseExists — the query that backs Evidence's
// SubjectRef (EDR-KERNEL-01 D1; EDR-EVIDENCE-01 D5). It orchestrates the domain
// aggregates and enforces the membership invariants (a Project's Product must exist; a
// Release's Project must exist); it depends only on the domain and the kernel.
package app
