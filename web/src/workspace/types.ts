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
  domain?: string;
  published_at?: string | null;
  date_status?: string;
  query: string;
  title: string;
  url: string;
  excerpt: string;
  score: number | null;
  published_date: string | null;
  updated_date: string | null;
  retrieved_at: string;
  request_id?: string | null;
  credits?: number | null;
  classification: string;
  age_days?: number | null;
  date_known?: boolean;
  classification_reason: string;
  extraction_status: string;
}
export interface Staleness {
  stale: boolean;
  new_evidence_count: number;
  reason: string;
  analysed_at?: string;
}
export interface StaleReason {
  rule: string;
  evidence_id: string;
  kind: string;
  detail: string;
  at?: string | null;
}
export interface BriefStaleness {
  status: "FRESH" | "STALE" | "SUPERSEDED" | "NO_SNAPSHOT";
  reasons: StaleReason[];
  ignored: { evidence_id: string; kind: string; reason: string; detail: string }[];
  invalidated_at: string | null;
  summary?: string;
  brief_version?: number;
}
export interface Attempt {
  attempt_id: string;
  op: string;
  query: string;
  outcome: "ok" | "failed";
  http_status: number | null;
  error_category: string | null;
  request_id: string | null;
  credits_reported: number | null;
  retry: boolean;
  sent_at: string;
}
export interface ResearchState {
  status: "NOT_STARTED" | "RESEARCHING" | "COMPLETED" | "PARTIAL" | "FAILED" | "BUDGET_EXHAUSTED";
  brief_status: "NEVER_RESEARCHED" | "FRESH" | "STALE" | "SUPERSEDED" | "NO_SNAPSHOT";
  budget: { operations_used: number; max_operations: number; operations_remaining: number; credits_reserved: number; credits_reported: number; max_credits: number; exhausted: boolean };
  attempts: Attempt[];
  runs: { run_id: string; status: string; failures?: { op: string; category: string }[]; started_at?: string; finished_at?: string }[];
  active: boolean;
}
export interface Brief {
  version?: number;
  previous_brief_id?: string | null;
  snapshot_id?: string;
  schema_version?: string;
  evidence_strength?: "STRONG" | "MODERATE" | "WEAK" | "INSUFFICIENT";
  evidence_strength_reason?: string;
  incident_summary?: string;
  likely_explanation?: string;
  structured_findings?: { claim: string; kind: "SOURCE_ESTABLISHED" | "MODEL_INFERENCE" | "HYPOTHESIS"; evidence_ids: string[]; source_dates: (string | null)[] }[];
  hypotheses?: string[];
  missing_evidence?: string[];
  alternative_explanations?: string[];
  next_steps?: string[];
  limitations?: string[];
  staleness?: BriefStaleness;
  created_at?: string;
  brief_id: string;
  origin: "BIFROST_MODEL" | "RULES_ONLY";
  status: string;
  error_category: string | null;
  brief: string;
  findings: { text: string; evidence_ids: string[] }[];
  gaps: string[];
  follow_up_queries: string[];
  bifrost_request_id: string | null;
  provider: string | null;
  model: string | null;
  downgrade_reasons: string[];
}
export interface Analysis {
  staleness?: Staleness;
  analysis_id: string;
  origin: "BIFROST_MODEL" | "RULES_ONLY";
  status: string;
  error_category: string | null;
  downgrade_reasons: string[];
  bifrost_request_id: string | null;
  bifrost_trace_id?: string | null;
  fallback_used?: boolean | null;
  fallback_index?: number | null;
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
  research_briefs?: Brief[];
  research_state?: ResearchState;
  analysis_stale?: boolean;
  analyses: Analysis[];
  proposals: Proposal[];
  execution: { t: string; event: string; detail?: Record<string, unknown> }[];
  verification: { attempts: number; all_passed: boolean; categories: Record<string, { status: string; checks: Check[] }> };
  provenance: { at: string; stage: string; ref: string }[];
}
export interface Capability {
  capability: string;
  state: string;
  detail: string;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_error_category: string | null;
  success_count: number;
  failure_count: number;
}
export interface Integration {
  integration: string;
  capabilities?: Capability[];
  last_failure_at?: string | null;
  state: string;
  mode: string;
  detail: string;
  last_success_at: string | null;
  last_error_category: string | null;
  observed_activity: number | null;
}
