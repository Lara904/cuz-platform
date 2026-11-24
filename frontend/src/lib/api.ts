// Client de l'API CUz. Le token JWT est lu depuis localStorage (clé cuz_token) :
// aucun secret n'est embarqué dans le bundle. Dev : copier un token généré par
// l'API dans localStorage.setItem("cuz_token", "...") depuis la console.

export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function token(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem("cuz_token");
}

export async function apiGet<T>(path: string, params?: Record<string, string | number>): Promise<T> {
  const url = new URL(path, API_URL);
  for (const [k, v] of Object.entries(params ?? {})) url.searchParams.set(k, String(v));
  const t = token();
  const res = await fetch(url, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
  if (!res.ok) throw new ApiError(res.status, `${res.status} ${res.statusText} : ${path}`);
  return res.json() as Promise<T>;
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const t = token();
  const res = await fetch(new URL(path, API_URL), {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(t ? { Authorization: `Bearer ${t}` } : {}) },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new ApiError(res.status, `${res.status} ${res.statusText} : ${path}`);
  return res.json() as Promise<T>;
}

export interface DashboardStats {
  node_count: number;
  by_severity: Record<string, number>;
  by_tier?: Record<string, number>;
  /** Erreurs du dernier calcul complet (OPA injoignable, règle en échec). Non vide = détection dégradée. */
  detection_errors?: string[];
  open: number;
  health_score: number | null;
}

export interface Finding {
  id: string;
  rule_id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  /** Tier opérationnel (P2.9) : 0 alerte, 1 PR GitOps, 2 jumeau, 3 canary + humain, 4 humain seul */
  tier: 0 | 1 | 2 | 3 | 4;
  title: string;
  affected_node_names: string[];
  confidence_score: number;
  remediation_hint: string;
  status: string;
}

export interface FreshnessRow {
  source: string;
  nodes: number;
  avg_freshness: number;
  fresh: number;
  aging: number;
  stale: number;
}

export const fetchStats = (tenant: string) =>
  apiGet<DashboardStats>(`/api/v1/tenants/${tenant}/dashboard/stats`);

export const fetchFindings = (tenant: string, opts: { size?: number; status?: string } = {}) =>
  apiGet<Finding[]>(`/api/v1/tenants/${tenant}/findings/`, {
    size: opts.size ?? 20,
    ...(opts.status ? { status: opts.status } : {}),
  });

export const fetchFreshness = (tenant: string) =>
  apiGet<FreshnessRow[]>(`/api/v1/tenants/${tenant}/dashboard/freshness`);

export interface TimelineEvent {
  finding_id: string;
  rule_id: string;
  action: string;
  actor: string;
  created_at: string;
}

export const fetchTimeline = (tenant: string) =>
  apiGet<TimelineEvent[]>(`/api/v1/tenants/${tenant}/dashboard/timeline`);

export interface GraphNode {
  id: string;
  name: string;
  node_type: string;
  sources: string[] | null;
  confidence_score: number;
  freshness_score: number;
  owner: string | null;
  attributes: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source_id: string;
  target_id: string;
  edge_type: string;
  confidence_score: number;
}

export interface GraphFinding {
  id: string;
  rule_id: string;
  severity: string;
  affected_nodes: string[];
}

export interface TenantGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: GraphFinding[];
}

export const fetchGraph = (tenant: string) =>
  apiGet<TenantGraph>(`/api/v1/tenants/${tenant}/graph/`);

// ── Entity Resolution : validation humaine des paires (P2.6) ─────────────────
export interface ErNode {
  id: string;
  name: string;
  node_type: string;
  sources: string[] | null;
  confidence_score: number;
  freshness_score: number;
  attributes: Record<string, unknown>;
  tags: Record<string, string>;
}

export interface ErPair {
  pair_id: string;
  match_probability: number;
  node_a: ErNode;
  node_b: ErNode;
  flagged: boolean;
}

export interface ErPairsPage {
  total: number;
  page: number;
  size: number;
  pairs: ErPair[];
}

export interface ErDecisionStats {
  total_reviewed: number;
  total_decisions: number;
  merged: number;
  rejected: number;
  flagged: number;
}

export type ErDecision = "merge" | "reject" | "flag";

export const fetchPendingPairs = (tenant: string, page = 1, size = 20) =>
  apiGet<ErPairsPage>(`/api/v1/tenants/${tenant}/entity-resolution/pairs`, { page, size });

export const fetchErDecisionStats = (tenant: string) =>
  apiGet<ErDecisionStats>(`/api/v1/tenants/${tenant}/entity-resolution/decisions/stats`);

// Le relecteur est l'identité du token côté serveur : jamais envoyé par le client.
export const decidePair = (tenant: string, pairId: string, decision: ErDecision, note?: string) =>
  apiPost<{ status: string; pair_id: string; decision: ErDecision; graph_merge_applied: boolean }>(
    `/api/v1/tenants/${tenant}/entity-resolution/pairs/${pairId}/decide`, { decision, note },
  );

// ── Module DORA complet (P2.13) ───────────────────────────────────────────────
export interface DoraProvider {
  provider_name: string;
  provider_type: string;
  exit_plan_status: string;
  last_review_date: string;
  supported_functions: string[];
}

export interface DoraRegister {
  register: DoraProvider[];
}

// rule_id est toujours "DORA-CONCENTRATION-001" ici, mais on réutilise Finding pour ne pas
// dupliquer un type déjà posé plus haut dans ce fichier.
export interface DoraConcentrationFindings {
  findings: Finding[];
}

export const fetchDoraRegister = (tenant: string) =>
  apiGet<DoraRegister>(`/api/v1/tenants/${tenant}/compliance/dora/register`);

export const fetchDoraConcentrationRisk = (tenant: string) =>
  apiGet<DoraConcentrationFindings>(`/api/v1/tenants/${tenant}/compliance/dora/concentration-risk`);

// L'export est protégé par Bearer token (RBAC VIEWER, services/api/routers/dora_compliance.py) :
// un simple <a href> ne porterait pas l'en-tête Authorization, d'où ce téléchargement via blob.
export async function downloadDoraEsaCsv(tenant: string): Promise<void> {
  const t = token();
  const res = await fetch(new URL(`/api/v1/tenants/${tenant}/compliance/dora/export/esa`, API_URL), {
    headers: t ? { Authorization: `Bearer ${t}` } : {},
  });
  if (!res.ok) throw new ApiError(res.status, `${res.status} ${res.statusText} : export ESA`);
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `dora_esa_${tenant}.csv`;
  a.click();
  window.URL.revokeObjectURL(url);
}
