// API 유틸리티: JWT 인증 + 프록시 경유 요청

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("access_token");
}

export function setToken(token: string): void {
  localStorage.setItem("access_token", token);
}

export function setUsername(username: string): void {
  localStorage.setItem("username", username);
}

export function removeToken(): void {
  localStorage.removeItem("access_token");
  localStorage.removeItem("username");
}

/** 기본 RequestInit에 더해, 401 시 전역 로그인 리다이렉트를 끌 수 있다(백그라운드 요청 충돌 방지). */
export type ApiFetchOptions = RequestInit & {
  redirectOn401?: boolean;
};

export async function apiFetch(
  path: string,
  options: ApiFetchOptions = {}
): Promise<Response> {
  const { redirectOn401 = true, ...init } = options;
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init.headers as Record<string, string>) || {}),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(path, { ...init, headers });

  if (res.status === 401) {
    removeToken();
    if (redirectOn401 && typeof window !== "undefined") {
      window.location.href = "/login";
    }
    throw new Error("Unauthorized");
  }

  return res;
}

// --- Auth ---
export async function login(
  username: string,
  password: string
): Promise<{ access_token: string }> {
  const formData = new URLSearchParams();
  formData.append("username", username);
  formData.append("password", password);

  const res = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formData.toString(),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "로그인에 실패했습니다.");
  }

  return res.json();
}

export async function register(data: {
  email: string;
  username: string;
  password: string;
}): Promise<{ message: string }> {
  const res = await fetch("/api/v1/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "회원가입에 실패했습니다.");
  }

  return res.json();
}

export async function getMe(): Promise<{ username: string; role: string }> {
  const res = await apiFetch("/api/v1/auth/me");
  if (!res.ok) throw new Error("사용자 정보를 가져올 수 없습니다.");
  return res.json();
}

// --- Scan ---
export async function startScan(
  target_url: string,
  project_name: string,
  target_api_key?: string,
  max_phase?: number,
  categories?: string[],
): Promise<{ session_id: string; status: string }> {
  const res = await apiFetch("/api/v1/scan/llm-security", {
    method: "POST",
    body: JSON.stringify({ target_url, project_name, target_api_key, max_phase, categories }),
  });
  if (!res.ok) throw new Error("스캔을 시작할 수 없습니다.");
  return res.json();
}

export async function getScanStatus(sessionId: string): Promise<{
  session_id: string;
  status: string;
  phase: number;
  total_tests: number;
  completed_tests: number;
  vulnerable_count: number;
  safe_count: number;
  ambiguous_count?: number;
  elapsed_seconds?: number;
  termination_reason?: string;
  attempted_count?: number;
  failed_attempts?: number;
  attack_success?: boolean;
  error_message?: string;
}> {
  const res = await apiFetch(`/api/v1/scan/${sessionId}/status`);
  if (!res.ok) throw new Error("스캔 상태를 가져올 수 없습니다.");
  return res.json();
}

export async function getPhase1Seeds(
  category?: string,
  limit?: number,
): Promise<{
  category: string;
  count: number;
  items: Array<{
    id?: number | string | null;
    attack_prompt: string;
    category?: string;
    subcategory?: string;
    seed_id?: string;
  }>;
}> {
  const qs = new URLSearchParams();
  if (category) qs.set("category", category);
  if (limit != null) qs.set("limit", String(limit));
  const url = `/api/v1/scan/phase1-seeds${qs.toString() ? "?" + qs.toString() : ""}`;
  const res = await apiFetch(url, { redirectOn401: false });
  if (!res.ok) throw new Error("공격 시드 목록을 가져올 수 없습니다.");
  return res.json();
}

export async function getSitegptConfig(): Promise<{ phase2_max_rounds: number }> {
  const res = await apiFetch("/api/v1/scan/sitegpt/config", { redirectOn401: false });
  if (!res.ok) throw new Error("SiteGPT 설정을 불러올 수 없습니다.");
  return res.json();
}

export async function postSitegptRedMutation(payload: {
  category: string;
  attack_prompt: string;
  target_response: string;
  round: number;
  subcategory?: string;
  judge_detail?: string;
  used_techniques?: string[];
  used_failure_modes?: string[];
  cross_category_intel?: Record<string, string>;
  target_url?: string;
}): Promise<{
  mutated_prompt: string;
  techniques: string[];
  failure_mode?: string | null;
  detail: string;
}> {
  const res = await apiFetch("/api/v1/scan/sitegpt/red-mutation", {
    method: "POST",
    body: JSON.stringify({
      category: payload.category,
      attack_prompt: payload.attack_prompt,
      target_response: payload.target_response,
      round: payload.round,
      subcategory: payload.subcategory ?? "",
      judge_detail: payload.judge_detail ?? "",
      used_techniques: payload.used_techniques ?? [],
      used_failure_modes: payload.used_failure_modes ?? [],
      cross_category_intel: payload.cross_category_intel,
      target_url: payload.target_url,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { detail?: string }).detail || "Red 변형 요청에 실패했습니다.");
  }
  return res.json();
}

export async function postSitegptBlueDefense(payload: {
  category: string;
  attack_prompt: string;
  target_response: string;
  judge_detail?: string;
  max_attempts?: number;
}): Promise<{
  defended_response: string;
  defense_rationale: string;
  attack_judge: Record<string, unknown>;
  defense_judge: Record<string, unknown>;
  raw_blue?: string;
  attempt_count?: number;
  final_judgment?: string;
  attempt_logs?: Array<{
    attempt: number;
    judgment: string;
    detail?: string;
  }>;
}> {
  const res = await apiFetch("/api/v1/scan/sitegpt/blue-defense", {
    method: "POST",
    body: JSON.stringify({
      category: payload.category,
      attack_prompt: payload.attack_prompt,
      target_response: payload.target_response,
      judge_detail: payload.judge_detail ?? "",
      max_attempts: payload.max_attempts ?? 3,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { detail?: string }).detail || "Blue 방어 생성에 실패했습니다.");
  }
  return res.json();
}

export async function manualCheck(payload: {
  attack_prompt: string;
  target_response: string;
  category?: string;
}): Promise<{
  judgment: string;
  severity?: string | null;
  detail?: string;
  confidence?: number;
  manual_review_needed?: boolean;
  p_vulnerable?: number | null;
  p_safe?: number | null;
  probability_judgment?: string | null;
  consensus_judgment?: string | null;
  judgment_alignment?: string | null;
  reason_sources?: {
    final_reason?: string;
    consensus_reason?: string;
    safe_side_reason?: string;
    vulnerable_side_reason?: string;
  } | null;
  matched_patterns?: unknown[];
  mitre_technique_id?: string | null;
}> {
  const res = await apiFetch("/api/v1/scan/manual-check", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error("수동 판정 요청에 실패했습니다.");
  return res.json();
}

export async function cancelScan(sessionId: string): Promise<{ session_id: string; status: string }> {
  const res = await apiFetch(`/api/v1/scan/${sessionId}/cancel`, { method: "POST" });
  if (!res.ok) throw new Error("스캔을 취소할 수 없습니다.");
  return res.json();
}

export async function getLatestScan(): Promise<{
  session_id: string;
  status: string;
  project_name: string;
  target_url: string;
  created_at?: string;
  completed_at?: string;
}> {
  const res = await apiFetch("/api/v1/scan/latest");
  if (!res.ok) throw new Error("최근 스캔을 가져올 수 없습니다.");
  return res.json();
}

export async function getFrrStats(sessionId: string): Promise<{
  session_id: string;
  total_legitimate_requests: number;
  false_refusals: number;
  frr_rate: number;
  frr_percentage: number;
}> {
  const res = await apiFetch(`/api/v1/scan/${sessionId}/frr`);
  if (!res.ok) throw new Error("FRR 통계를 가져올 수 없습니다.");
  return res.json();
}

export async function getScanReviewQueue(sessionId: string): Promise<ScanResult[]> {
  const res = await apiFetch(`/api/v1/scan/${sessionId}/review-queue`);
  if (!res.ok) throw new Error("리뷰 큐를 가져올 수 없습니다.");
  return res.json();
}

export async function getScanResult(sessionId: string, resultId: number): Promise<ScanResult> {
  const res = await apiFetch(`/api/v1/scan/${sessionId}/results/${resultId}`);
  if (!res.ok) throw new Error("결과를 가져올 수 없습니다.");
  return res.json();
}

export async function getScanResults(
  sessionId: string,
  params?: { category?: string; severity?: string; phase?: number }
): Promise<ScanResult[]> {
  const qs = new URLSearchParams();
  if (params?.category) qs.set("category", params.category);
  if (params?.severity) qs.set("severity", params.severity);
  if (params?.phase) qs.set("phase", String(params.phase));

  const url = `/api/v1/scan/${sessionId}/results${qs.toString() ? "?" + qs.toString() : ""}`;
  const res = await apiFetch(url);
  if (!res.ok) throw new Error("스캔 결과를 가져올 수 없습니다.");
  return res.json();
}

export interface ScanResult {
  id: number;
  session_id: string;
  phase: number;
  attack_prompt: string;
  target_response: string;
  judgment: string;
  severity: string;
  category: string;
  defense_code?: string;
  defended_response?: string;
  defense_rationale?: string;
  verify_result?: string;
  created_at: string;
  summary?: string;
  danger_highlight?: string;
}

// --- Monitoring ---
export async function getMonitoringDashboard(): Promise<{
  daily_requests: number;
  violations_count: number;
  blocked_count: number;
  active_employees: number;
  total_employees: number;
}> {
  const res = await apiFetch("/api/v1/monitoring/dashboard");
  if (!res.ok) throw new Error("대시보드 데이터를 가져올 수 없습니다.");
  return res.json();
}

export async function getViolations(params?: {
  department?: string;
  violation_type?: string;
}): Promise<Violation[]> {
  const qs = new URLSearchParams();
  if (params?.department) qs.set("department", params.department);
  if (params?.violation_type) qs.set("violation_type", params.violation_type);

  const url = `/api/v1/monitoring/violations${qs.toString() ? "?" + qs.toString() : ""}`;
  const res = await apiFetch(url);
  if (!res.ok) throw new Error("위반 내역을 가져올 수 없습니다.");
  return res.json();
}

export interface Violation {
  id: number;
  employee_id: string;
  employee_name?: string;
  department?: string;
  violation_type: string;
  severity: string;
  description: string;
  sanction: string;
  resolved: boolean;
  created_at: string;
}

export async function getEmployees(): Promise<Employee[]> {
  const res = await apiFetch("/api/v1/monitoring/employees");
  if (!res.ok) throw new Error("직원 목록을 가져올 수 없습니다.");
  return res.json();
}

export interface Employee {
  id: string;
  employee_id: string;
  name: string;
  department: string;
  role: string;
  status: string;
}

export async function getPolicies(): Promise<Policy[]> {
  const res = await apiFetch("/api/v1/monitoring/policies");
  if (!res.ok) throw new Error("정책 목록을 가져올 수 없습니다.");
  return res.json();
}

export async function createPolicy(data: {
  rule_name: string;
  rule_type: string;
  pattern: string;
  severity: string;
  action: string;
}): Promise<Policy> {
  const res = await apiFetch("/api/v1/monitoring/policies", {
    method: "POST",
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error("정책을 생성할 수 없습니다.");
  return res.json();
}

export interface Policy {
  id: number;
  rule_name: string;
  rule_type: string;
  pattern: string;
  severity: string;
  action: string;
  is_active: boolean;
  created_at: string;
}

// --- Phase 5 가드레일 정책 패키지 ---

export interface PolicyPackageManifest {
  session_id: string;
  generated_at: string;
  included_result_ids: number[];
  excluded_result_ids: number[];
  total_findings: number;
  verified_safe_count: number;
  package_status: "validated" | "empty" | "invalid";
}

export interface PolicyPackageBundle {
  session_id: string;
  manifest: PolicyPackageManifest;
  middleware_policy: {
    input_policy?: Record<string, boolean>;
    output_policy?: Record<string, boolean>;
    category_actions?: Record<string, string>;
  } | null;
  masking_rules: Array<{ id: string; target: string; pattern_family: string; replacement: string }> | null;
  refusal_templates: Array<{ category: string; template: string; verified_result_id: number }> | null;
  regression_tests: Array<{
    test_id: string;
    source_result_id: number;
    category: string;
    attack_prompt: string;
    must_not_contain: string[];
    expected_action: string;
  }> | null;
  validation: { valid: boolean; errors?: string[]; warnings?: string[] } | null;
  zip_available: boolean;
  download_url: string | null;
  reports?: {
    executive_summary_pdf?: string;
    executive_summary_html?: string;
    full_report_pdf?: string;
    full_report_html?: string;
  };
}

export async function getPolicyPackage(sessionId: string): Promise<PolicyPackageBundle | null> {
  const res = await apiFetch(`/api/v1/policy-export/${sessionId}`, { redirectOn401: false });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error("정책 패키지를 불러올 수 없습니다.");
  return res.json();
}

// data/owasp_guidance.yaml 의 카테고리 권고. 대시보드 ACTION_GUIDE의 단일 소스.
export interface OwaspGuidanceCategory {
  name: string;
  default_action: string;
  action_label_ko: string;
  fix_targets: string[];
  must_not_contain: string[];
  input_policy_flag: string | null;
  output_policy_flag: string | null;
  reference_url: string;
  severity_baseline: string;
}

export interface OwaspGuidanceBundle {
  source: string;
  categories: Record<string, OwaspGuidanceCategory>;
}

export async function getOwaspGuidance(): Promise<OwaspGuidanceBundle | null> {
  const res = await apiFetch(`/api/v1/policy-export/guidance`, { redirectOn401: false });
  if (!res.ok) return null;
  return res.json();
}

// 브라우저는 <a href> 클릭 시 Authorization 헤더를 안 붙이기 때문에 보호된 다운로드 URL은 401을 받는다.
// fetch로 JWT를 함께 보내 Blob을 만든 뒤 임시 URL로 저장한다.
export async function downloadAuthenticated(url: string, filename: string): Promise<void> {
  const res = await apiFetch(url, { redirectOn401: false });
  if (!res.ok) {
    throw new Error(`다운로드 실패 (${res.status})`);
  }
  const blob = await res.blob();
  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = blobUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
}
