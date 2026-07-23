// Package domain is the Communication context's domain ring (EDR-COMMUNICATION-01 D12):
// the Publication aggregate — Communication's immutable record of one materialized
// artifact (VEX / advisory / notification / audit report) from one Enterprise Position
// version, with its own identity, permanent lineage handles (Position → Finding →
// Faultline → Evidence), audience/channel/format, a capped regenerable payload, a mutable
// delivery outcome, and append-and-supersede links. It also holds the pure, deterministic
// materialization rule (Position → artifact, with the stance-equality invariant — an
// artifact never states a conclusion different from the Position) and the terminal
// Communication events. The ring is pure: it depends only on the standard library.
package domain
