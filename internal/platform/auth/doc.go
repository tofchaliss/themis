// Package auth is the platform-owned inbound edge security concern — the third shared
// platform package after observability and eventbus (EDR-SECURITY-01). It provides API-key
// authentication, scope-based authorization, and HMAC-verified webhook trust as HTTP
// middleware, plus the identity store that backs them.
//
// It is business-agnostic: it depends only on the standard library, infrastructure drivers
// (pgx, bcrypt), and nothing else under internal/ — no bounded context and not the registry
// (D1). Only a context's adapters ring and the cmd composition root may import it; the domain
// and app rings never see auth (a resolved Principal is passed in as data, if at all). The
// depguard rule platform-auth-infra-only and the arch test TestPlatformAuthIsBusinessAgnostic
// enforce both halves of that boundary.
package auth
