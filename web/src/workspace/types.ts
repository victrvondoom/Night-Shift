export type Lifecycle = "DETECTED" | "CORRELATED" | "ANALYZED" | "PROPOSED" | "APPROVED" | "EXECUTING" | "VERIFYING" | "VERIFIED" | "VERIFICATION_FAILED" | "ESCALATED";
export interface Ev {
  event_id: string;
  source: string;
  source_event_id: string;
  event_type: string;
  observed_at: string;
  received_at: string;
  resource: { namespace: string; kind: string; name: string; target_app: string };
  summary: string;
  source_mode: "LIVE" | "DEMO_SIMULATOR";
  payload_reference: string;
}
export interface Corr {
  correlation_id: string;
  rule: string;
  included_event_ids: string[];
  symptom_types: string[];
  resource: string;
  target_app: string;
  window_start: string;
  window_end: string;
  window_seconds: number;
  strength: string;
  explanation: string;
  missing_evidence: string[];
  processed_at: string;
  engine: string;
}
export interface ResearchItem {
  evidence_id: string;
  query: string;
  title: string;
  url: string;
  excerpt: string;
  score: number | null;
  published_date: string | null;
  updated_date: string | null;
  retrieved_at: string;
  classification: string;
  classification_reason: string;
  extraction_status: string;
}
export interface Analysis {
  analysis_id: string;
  origin: "BIFROST_MODEL" | "RULES_ONLY";
  status: string;
  error_category: string | null;
  downgrade_reasons: string[];
  bifrost_request_id: string | null;
  provider: string | null;
  model: string | null;
  latency_ms: number | null;
  usage: Record<string, number> | null;
  cost: number | null;
  evidence_set_hash: string;
  created_at: string;
  structured: null | {
    incident_summary: string;
    root_cause_hypothesis: string;
    supporting_event_ids: string[];
    external_evidence_ids: string[];
    what_is_confirmed: { text: string; evidence_ids: string[] }[];
    what_is_unknown: string[];
    recommended_action_id: string | null;
    reasoning_summary: string;
    risk_summary: string;
  };
}
export interface Proposal {
  fix_id: number;
  action: string;
  params: Record<string, unknown>;
  target: string;
  blast_radius: string;
  expected_effect: string;
  dry_run: { ok: boolean; code?: string; detail?: string };
  expires_at: string;
  state: "PENDING_APPROVAL" | "APPROVED" | "EXPIRED" | "CANCELLED";
  params_hash: string;
  confirmation_phrase: string;
  required_approver: string;
  supporting_evidence_ids: string[];
  approval?: { user: string; approved_at: string; evidence: string } | null;
}
export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  checked_at: string;
}
export interface View {
  incident_id: string;
  source_mode: "LIVE" | "DEMO_SIMULATOR";
  severity: string;
  affected_service: string;
  alarm_name: string;
  lifecycle: Lifecycle;
  detected_at: string;
  events: Ev[];
  correlations: Corr[];
  research: ResearchItem[];
  analyses: Analysis[];
  proposals: Proposal[];
  execution: { t: string; event: string; detail?: Record<string, unknown> }[];
  verification: { attempts: number; all_passed: boolean; categories: Record<string, { status: string; checks: Check[] }> };
  provenance: { at: string; stage: string; ref: string }[];
}
export interface Integration {
  integration: string;
  state: string;
  mode: string;
  detail: string;
  last_success_at: string | null;
  last_error_category: string | null;
  observed_activity: number | null;
}
