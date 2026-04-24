# 대시보드(프론트엔드) 작업 지시서 — MITRE ATT&CK & FRR 시각화

> 작성일: 2026-04-23  
> 관련 브랜치: `EPOCH-12-AgentShield-red-agent-judge`  
> 담당: 대시보드(Next.js/React) 팀원

---

## 1. 배경 및 목적

백엔드에 두 가지 신규 기능이 추가되었습니다. 대시보드에 이를 시각화하는 섹션을 추가해야 합니다.

| 기능 | API 엔드포인트 | 표시 위치 |
|---|---|---|
| MITRE ATT&CK 매핑 테이블 | `GET /api/v1/scan/mitre-mapping` | Overview 페이지 |
| FRR(오탐률) 통계 | `GET /api/v1/scan/{session_id}/frr` | Overview 또는 Scan 결과 페이지 |

---

## 2. API 스펙

### 2-1. MITRE 매핑 테이블

**엔드포인트**: `GET /api/v1/scan/mitre-mapping`  
**인증**: Bearer Token 불필요 (공개 엔드포인트)

**응답 예시**:
```json
{
  "mapping": [
    {
      "category": "LLM01",
      "failure_mode": null,
      "primary_technique_id": "T1190",
      "primary_technique_name": "Exploit Public-Facing Application",
      "tactic": "Initial Access",
      "url": "https://attack.mitre.org/techniques/T1190/",
      "secondary": [
        {"technique_id": "T1059", "name": "Command and Scripting Interpreter"},
        {"technique_id": "T1203", "name": "Exploitation for Client Execution"}
      ],
      "notes": "Prompt injection exploits..."
    },
    ...
  ]
}
```

### 2-2. FRR 통계

**엔드포인트**: `GET /api/v1/scan/{session_id}/frr`  
**인증**: Bearer Token 필요

**응답 예시**:
```json
{
  "session_id": "3f9b422c-...",
  "total_legitimate_requests": 27,
  "false_refusals": 2,
  "frr_rate": 0.0741,
  "frr_percentage": 7.41
}
```

---

## 3. 구현 항목

### 3-1. FRR 게이지 카드 — Overview 페이지 (`dashboard/app/overview/page.tsx`)

기존 취약점 카운트 카드들 옆에 FRR 카드를 추가합니다.

**컴포넌트 위치**: `dashboard/components/FrrGauge.tsx` (신규 생성)

```tsx
// dashboard/components/FrrGauge.tsx
interface FrrData {
  total_legitimate_requests: number;
  false_refusals: number;
  frr_percentage: number;
}

export function FrrGauge({ data }: { data: FrrData }) {
  const color = data.frr_percentage > 15 ? "text-red-500" 
              : data.frr_percentage > 5  ? "text-yellow-500" 
              : "text-green-500";

  return (
    <div className="rounded-lg border p-4 bg-white shadow-sm">
      <h3 className="text-sm font-medium text-gray-500">오탐률 (FRR)</h3>
      <p className={`text-3xl font-bold mt-1 ${color}`}>
        {data.frr_percentage.toFixed(1)}%
      </p>
      <p className="text-xs text-gray-400 mt-1">
        정상 요청 {data.total_legitimate_requests}건 중 {data.false_refusals}건 오탐
      </p>
      <div className="mt-2 text-xs text-gray-400">
        ✅ 5% 미만: 양호 &nbsp;|&nbsp; ⚠️ 5~15%: 주의 &nbsp;|&nbsp; ❌ 15%+: 위험
      </div>
    </div>
  );
}
```

**Overview 페이지 데이터 패칭**:
```tsx
// dashboard/app/overview/page.tsx 내 기존 useEffect 또는 fetch 로직에 추가

const [frrData, setFrrData] = useState(null);

useEffect(() => {
  if (!sessionId) return;
  fetch(`/api/v1/scan/${sessionId}/frr`, {
    headers: { Authorization: `Bearer ${token}` }
  })
    .then(r => r.json())
    .then(setFrrData);
}, [sessionId]);

// JSX에 추가
{frrData && <FrrGauge data={frrData} />}
```

---

### 3-2. MITRE ATT&CK 매핑 테이블 — Overview 페이지 하단

**컴포넌트 위치**: `dashboard/components/MitreTable.tsx` (신규 생성)

```tsx
// dashboard/components/MitreTable.tsx
interface MitreRow {
  category: string;
  failure_mode: string | null;
  primary_technique_id: string;
  primary_technique_name: string;
  tactic: string;
  url: string;
  secondary: { technique_id: string; name: string }[];
}

export function MitreTable({ rows }: { rows: MitreRow[] }) {
  // failure_mode가 null인 카테고리 대표 행만 표시 (세분화 행 숨김)
  const displayRows = rows.filter(r => !r.failure_mode);
  
  return (
    <div className="mt-6">
      <h2 className="text-lg font-semibold mb-3">MITRE ATT&CK 매핑</h2>
      <div className="overflow-x-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="bg-gray-50 text-gray-600">
              <th className="px-3 py-2 text-left border">카테고리</th>
              <th className="px-3 py-2 text-left border">대표 기법</th>
              <th className="px-3 py-2 text-left border">전술(Tactic)</th>
              <th className="px-3 py-2 text-left border">보조 기법</th>
            </tr>
          </thead>
          <tbody>
            {displayRows.map((row) => (
              <tr key={row.category} className="hover:bg-gray-50">
                <td className="px-3 py-2 border font-mono font-semibold text-blue-700">
                  {row.category}
                </td>
                <td className="px-3 py-2 border">
                  <a
                    href={row.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-600 hover:underline"
                  >
                    {row.primary_technique_id}
                  </a>
                  <span className="text-gray-600 ml-1">— {row.primary_technique_name}</span>
                </td>
                <td className="px-3 py-2 border text-gray-600">{row.tactic}</td>
                <td className="px-3 py-2 border text-gray-500 text-xs">
                  {row.secondary.map(s => s.technique_id).join(", ") || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-gray-400 mt-2">
        출처: MITRE ATT&CK Enterprise v16 · CyberSecEval 4 (Meta PurpleLlama) 기준
      </p>
    </div>
  );
}
```

**Overview 페이지 데이터 패칭**:
```tsx
const [mitreRows, setMitreRows] = useState([]);

useEffect(() => {
  fetch("/api/v1/scan/mitre-mapping")
    .then(r => r.json())
    .then(d => setMitreRows(d.mapping || []));
}, []); // 세션 무관 — 공통 데이터

// JSX에 추가 (페이지 하단)
{mitreRows.length > 0 && <MitreTable rows={mitreRows} />}
```

---

### 3-3. Scan 결과 테이블에 MITRE 컬럼 추가 (`dashboard/app/scan/[id]/page.tsx`)

기존 결과 테이블에 `mitre_technique_id` 컬럼을 추가합니다.

```tsx
// 기존 테이블 헤더에 추가
<th>MITRE T-ID</th>

// 기존 테이블 행에 추가
<td>
  {result.mitre_technique_id ? (
    <a
      href={`https://attack.mitre.org/techniques/${result.mitre_technique_id.replace(".", "/")}/`}
      target="_blank"
      rel="noopener noreferrer"
      className="font-mono text-xs text-blue-600 hover:underline"
    >
      {result.mitre_technique_id}
    </a>
  ) : (
    <span className="text-gray-400">—</span>
  )}
</td>
```

---

### 3-4. Next.js API 프록시 — 이미 설정됨 (추가 작업 불필요)

`dashboard/app/api/[...path]/route.ts`에 범용 프록시가 이미 구현되어 있습니다.  
프런트에서 `/api/v1/scan/mitre-mapping`을 `fetch`하면 자동으로 `백엔드:8000/api/v1/scan/mitre-mapping`으로 포워딩됩니다.

**`next.config.js` 수정 불필요 — 기존 프록시 그대로 사용하면 됩니다.**

---

## 4. 스타일 가이드

- 기존 컴포넌트 스타일(`rounded-lg border p-4 bg-white shadow-sm`) 일관성 유지
- Tailwind CSS 사용 (기존 프로젝트와 동일)
- FRR 색상 기준: `green(< 5%)` / `yellow(5~15%)` / `red(> 15%)`
- MITRE T-ID는 반드시 링크로 표시 (`https://attack.mitre.org/techniques/T1190/` 형식)

---

## 5. 파일 수정 목록 요약

| 파일 | 작업 |
|---|---|
| `dashboard/components/FrrGauge.tsx` | **신규 생성** |
| `dashboard/components/MitreTable.tsx` | **신규 생성** |
| `dashboard/app/overview/page.tsx` | FrrGauge + MitreTable 컴포넌트 삽입 |
| `dashboard/app/scan/[id]/page.tsx` | MITRE T-ID 컬럼 추가 |

---

## 6. 완료 기준 체크리스트

- [ ] `FrrGauge` 컴포넌트 생성 및 Overview 페이지에 표시
- [ ] FRR 수치 색상 조건(5% / 15% 기준) 정상 작동
- [ ] `MitreTable` 컴포넌트 생성 및 Overview 페이지 하단에 표시
- [ ] 테이블 MITRE T-ID 클릭 시 attack.mitre.org 링크로 이동
- [ ] Scan 결과 테이블에 `mitre_technique_id` 컬럼 표시
- [ ] `next.config.js` 프록시 설정 확인
- [ ] 브랜치 `EPOCH-12`에 커밋 후 PR 요청

---

## 7. 테스트용 API 직접 호출 예시

```bash
# MITRE 매핑 확인
curl -s http://localhost:8000/api/v1/scan/mitre-mapping | python3 -m json.tool

# FRR 통계 확인 (토큰 필요)
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -F "username=admin" -F "password=admin1234" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

SESSION_ID=$(psql postgresql://agentshield:agentshield@localhost:5432/agentshield \
  -t -c "SELECT id FROM test_sessions ORDER BY created_at DESC LIMIT 1;")

curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/scan/$(echo $SESSION_ID | tr -d ' ')/frr | python3 -m json.tool
```
