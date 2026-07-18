// Strong typing: these types are auto-derived from the backend OpenAPI schema.
// Regenerate after API changes:
//   1. python scripts/gen_openapi.py   (dumps frontend/openapi.json)
//   2. npm run gen:types               (writes src/api/schema.ts)
import type { components } from "./api/schema"

type Schemas = components["schemas"]

// EventRecord / TraceStep have Pydantic defaults, so the schema marks those
// fields optional; Required<> restores them to required (matching how the app
// consumes them) while keeping `| null` for genuinely nullable fields.
export type EventStatus = Required<Schemas["EventRecord"]>["status"]
export type TraceStep = Required<Schemas["TraceStep"]>
export type ApprovalEntry = Schemas["ApprovalEntry"]
export type EventRecord = Required<Schemas["EventRecord"]>
export type Metrics = Schemas["MetricsResponse"]
export type TimelinePoint = Schemas["TimelinePoint"]
export type TraceResponse = Schemas["TraceResponse"]

// Pending-approval items are returned as dynamic Redis-hash dicts (no Pydantic
// model on the backend yet); hand-written until an ApprovalItem model is added.
export interface Approval {
  approval_id: string
  event_id: string
  operation_level: string
  status: string
  required: number
  approvals: { actor: string }[]
  created_at: string
}
