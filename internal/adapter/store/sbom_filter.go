package store

// sbomActiveFilter is applied at the store layer for all SBOM-backed reads.
const sbomActiveFilter = "s.deleted_at IS NULL"
