# Bigger picture

## Flow for themis

Product
    │
    ▼
Project
    │
    ▼
Release
    │
    ├───────────────┐
    ▼               ▼
Deployable Unit(s)
    │
    ▼
Product Evidence
    ├── CycloneDX SBOM
    └── Scanner Report(s)

              │

              ▼

Security Intelligence
(NVD, KEV, EPSS, OSV,
Vendor Advisories,
Vendor VEX)

              │

              ▼

Enterprise Knowledge

              │

              ▼

Assessment Engine

              │

              ▼

Deployable Unit Assessment

              │

              ▼

Release Assessment

              │

              ▼

Product Security Posture

              │

              ▼

Outputs
(VEX, Reports,
Customer Advisory,
AI)

## Layers

+------------------------------------------------------+
|                  AI Capability Layer                 |
+------------------------------------------------------+
|            Deterministic Assessment Engine           |
+------------------------------------------------------+
|               Enterprise Knowledge Layer             |
+------------------------------------------------------+
|       Authoritative Security Intelligence Layer      |
+------------------------------------------------------+
|               Product Evidence Layer                 |
+------------------------------------------------------+
