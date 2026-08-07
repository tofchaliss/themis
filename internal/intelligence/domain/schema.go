package domain

// recommendPositionSchema is the JSON Schema for the raw model output of the
// recommend_position capability (stage-1 structural validation, D7). It pins the
// exact shape the Gateway prompt asks the model to return, and constrains the stance
// at the schema level (belt-and-suspenders with the stage-2 business rule). The
// field names are the wire keys the model emits; BuildProposal maps them onto the
// Proposal envelope.
const recommendPositionSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["finding_id", "recommended_stance", "confidence", "evidence", "reasoning"],
  "properties": {
    "finding_id": { "type": "string", "minLength": 1 },
    "recommended_stance": { "type": "string", "enum": ["affected", "not_affected", "mitigated", "insufficient"] },
    "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
    "evidence": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["kind", "ref"],
        "properties": {
          "kind": { "type": "string", "minLength": 1 },
          "ref": { "type": "string", "minLength": 1 }
        }
      }
    },
    "reasoning": { "type": "string" }
  }
}`

// planRemediationSchema is the JSON Schema for plan_remediation@v1's raw model output.
//
// It carries no stance and no confidence: an Information Response makes no claim that aspires to
// become enterprise truth (T7), so there is nothing to be confident ABOUT and nothing for
// Governance to accept. What it must carry is `evidence` — the citations Grounding Verification
// checks, which on this path is the only gate the output passes through (T8).
const planRemediationSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["subject_id", "evidence", "reasoning"],
  "properties": {
    "subject_id": { "type": "string", "minLength": 1 },
    "evidence": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["kind", "ref"],
        "properties": {
          "kind": { "type": "string", "minLength": 1 },
          "ref": { "type": "string", "minLength": 1 }
        }
      }
    },
    "reasoning": { "type": "string", "minLength": 1 }
  }
}`
