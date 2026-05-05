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

export async function apiFetch(
  path: string,
  options: RequestInit = {}
): Promise<Response> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((options.headers as Record<string, string>) || {}),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(path, { ...options, headers });

  if (res.status === 401) {
    removeToken();
    if (typeof window !== "undefined") {
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
): Promise<{ session_id: string; status: string }> {
  const res = await apiFetch("/api/v1/scan/llm-security", {
    method: "POST",
    body: JSON.stringify({ target_url, project_name, target_api_key }),
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
  elapsed_seconds?: number;
}> {
  const res = await apiFetch(`/api/v1/scan/${sessionId}/status`);
  if (!res.ok) throw new Error("스캔 상태를 가져올 수 없습니다.");
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
  verify_result?: string;
  created_at: string;
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
