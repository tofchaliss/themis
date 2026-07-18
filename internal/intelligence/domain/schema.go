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
    "recommended_stance": { "type": "string", "enum": ["affected", "not_affected", "mitigated"] },
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
