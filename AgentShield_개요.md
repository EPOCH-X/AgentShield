# AgentShield — 프로젝트 개요 및 기획

> 작성일: 2026년 4월  
> 팀 규모: 7명
> 모델: Gemma 4 E2B (실질 2.3B, 총 ~5.1B)

---

## 1. 프로젝트 한 줄 요약

**AI 챗봇/에이전트의 보안 취약점을 자동으로 찾고(Find), 방어 코드를 생성하고(Fix), 실제로 방어되는지 검증(Verify)하는 플랫폼.**

기존 도구(Lakera, LLM Guard, NeMo Guardrails)는 "방어만" 하거나 "발견만" 한다.  
AgentShield는 **Find → Fix → Verify**를 하나의 파이프라인으로 자동화한다.

---

## 2. 해결하려는 문제

```
현재 상황:
  - 기업이 AI 챗봇/에이전트를 도입하고 있음
  - 프롬프트 인젝션, 민감정보 유출, 권한 초과 등 보안 위협이 존재
  - 보안 테스트를 수동으로 하면 시간이 오래 걸리고 일관성이 없음
  - 침투테스트(공격)만 해주는 도구는 있지만, "방어 코드"까지 자동 생성하는 건 없음
  - 기업 내 직원의 AI 사용을 모니터링하는 시스템도 부재

AgentShield가 해결:
  ① 자동 보안 테스트: DB 기반 + AI 기반 공격으로 취약점 자동 발견
  ② 방어 코드 자동 생성: 취약점별 입력필터/출력필터/시스템프롬프트 패치 생성
  ③ 실제 재검증: Defense Proxy로 방어가 실제 동작하는지 확인
  ④ 직원 모니터링: AI 사용 정책 위반 자동 탐지 + 제재
```

---

## 3. OWASP LLM Top 10 — 4개 카테고리 집중

**4개를 완전히 커버하는 것**이 실무적으로 더 가치 있다.

| ID        | 위협                      | 설명                                                 | 선택 이유                                               |
| --------- | ------------------------- | ---------------------------------------------------- | ------------------------------------------------------- |
| **LLM01** | Prompt Injection          | 공격자가 LLM의 지시를 조작하여 의도치 않은 동작 유발 | 가장 흔한 공격. DB 스캔 + LLM 변형 모두 적용 가능       |
| **LLM02** | Sensitive Info Disclosure | LLM이 민감정보(PII, API키, 내부데이터)를 응답에 포함 | 기업 데이터 유출 = 최대 비즈니스 리스크. 출력 필터 필수 |
| **LLM06** | Excessive Agency          | 에이전트가 허가 없이 외부 API/DB에 접근              | 기업 AI 도입에서 핵심 문제. 도구 호출 검증 필요         |
| **LLM07** | System Prompt Leakage     | 시스템 프롬프트 내용이 사용자에게 노출               | 모든 다른 공격의 진입점. 방어 우선순위 최상위           |

---

## 4. 기능 구성

```
AgentShield
│
├── 기능 A: AI Agent Shield (핵심)
│   타겟 AI 챗봇 API URL을 입력하면
│   → Phase 1: DB에 저장된 공격 프롬프트로 자동 스캔 (규칙 기반 판정)
│   → Phase 2: AI(Red Agent)가 실패한 공격을 변형하여 재공격 (LLM + RAG)
│   → Phase 3: AI(Blue Agent)가 방어 코드 자동 생성 (LLM + RAG)
│   → Phase 4: Defense Proxy로 방어 코드를 실제 적용 후 재검증
│   → 보고서: 취약점 목록 + 방어 코드 + 방어 전/후 비교 PDF
│
└── 기능 B: 직원 AI 사용 모니터링
    기업 내 직원들의 AI 챗봇 사용을 Proxy로 감시
    → P1: 기밀 정보 유출 방지 (PII, 소스코드, API키 입력 차단)
    → P2: 부적절 사용 탐지 (업무 무관, 유해 콘텐츠)
    → P3: 과도한 사용 제한 (Rate Limit)
    → P4: 사용 통계 + 위반 이력 대시보드
    기능 A의 Defense Proxy 아키텍처를 재활용
```

### 기능 A와 기능 B의 관계

| 공유 컴포넌트    | 기능 A 사용처                  | 기능 B 사용처                       |
| ---------------- | ------------------------------ | ----------------------------------- |
| Proxy 서버 코드  | Defense Proxy (Phase 4 재검증) | Monitoring Proxy (직원 트래픽 감시) |
| PII 정규식       | LLM02 판정 + 출력 필터         | P1 기밀 유출 탐지                   |
| PostgreSQL       | 공격 패턴, 테스트 결과 저장    | 사용 로그, 위반 이력 저장           |
| FastAPI 백엔드   | Phase 1-4 실행 API             | 모니터링/관리자 API                 |
| Next.js 대시보드 | 취약점 맵, 보고서 뷰어         | 사용 현황, 위반 알림                |

---

## 5. 해외 보안 솔루션 분석

### 5-1. Lakera (Guard + Red)

스위스 기반 엔터프라이즈 AI 보안 플랫폼.

**Lakera Guard** — 실시간 AI 방화벽

- LLM 앞에 Middleware로 배치. 모든 입/출력 실시간 검사
- ML 모델 + 규칙 기반 필터 혼합. 100개 이상 언어 지원
- 방어: 프롬프트 공격, PII 6종, 콘텐츠 위반, 악성 링크
- 4단계 임계값 (L1 Lenient ~ L4 Paranoid)
- PII 탐지: 이름, 주소, 전화번호, 이메일, IP, 신용카드(Luhn), IBAN, SSN

**Lakera Red** — 사전 배포 보안 평가 4단계:

1. Application Enumeration: 대상 시스템 매핑
2. Targeted Attack Development: 맞춤 공격 설계
3. Impact Amplification Testing: 피해 범위 확대 검증
4. Risk Assessment & Reporting: 비즈니스 영향도 보고서

**우리와의 차이:** Lakera Red는 보고서까지만. 방어 코드 자동 생성이 없다. AgentShield는 Fix + Verify까지 자동화.

### 5-2. LLM Guard (Protect AI)

MIT 오픈소스. Python 기반 LLM 입출력 스캐너. GitHub 2.8K Stars.

- 입력 스캐너 15종: Anonymize, BanCode, PromptInjection, InvisibleText, Gibberish, Secrets, Toxicity 등
- 출력 스캐너 11종: Sensitive, NoRefusal, MaliciousURLs, FactualConsistency 등

**우리와의 차이:** 실시간 방어만 한다. 취약점을 능동적으로 찾는 기능 없음. 우리는 Phase 3 방어 코드 생성 시 LLM Guard 스캐너 패턴을 RAG 참고 자료로 활용.

### 5-3. NeMo Guardrails (NVIDIA)

Apache 2.0 오픈소스. 프로그래밍 가능한 가드레일 프레임워크. GitHub 5.9K Stars.

5가지 레일:

- Input Rails: 사용자 입력 검사
- Dialog Rails: 대화 흐름 제어 (Colang 언어)
- Retrieval Rails: RAG 청크 검사
- **Execution Rails: 도구 호출 검사** ← LLM06 방어에 핵심
- Output Rails: LLM 출력 검사

**우리와의 차이:** 방어 전용. 취약점 능동 테스트 없음. Execution Rails 아키텍처를 우리 LLM06 방어에 참고.

### 5-4. 종합 비교

|                      | Lakera Guard    | LLM Guard | NeMo Guardrails | **AgentShield**    |
| -------------------- | --------------- | --------- | --------------- | ------------------ |
| 취약점 발견 (Find)   | Lakera Red 별도 | 없음      | 없음            | **Phase 1-2 자동** |
| 방어 코드 생성 (Fix) | 없음            | 없음      | 없음            | **Phase 3 자동**   |
| 재검증 (Verify)      | 없음            | 없음      | 없음            | **Phase 4 자동**   |
| 실시간 방어          | Proxy 방식      | 스캐너    | 레일            | Defense Proxy      |
| 도구 호출 검사       | 없음            | 없음      | Execution Rails | LLM06 전용         |
| 라이선스             | 상용            | MIT       | Apache 2.0      | **Apache 2.0**     |

**결론:** Find + Fix + Verify를 하나로 자동화하는 오픈소스는 없다. 이것이 AgentShield의 차별점.

---

## 6. 기술 스택

| 영역       | 기술                                 | 용도                                       |
| ---------- | ------------------------------------ | ------------------------------------------ |
| AI 모델    | **Gemma 4 E2B** (실질 2.3B, 총~5.1B) | Red/Judge/Blue 3역할 QLoRA 어댑터          |
| LLM 실행   | Ollama                               | 로컬 LLM 실행 (`ollama pull gemma4:e2b`)   |
| 워크플로우 | LangGraph                            | Phase 1→2→3→4 상태 그래프                  |
| 벡터 DB    | ChromaDB                             | 방어 패턴/공격 기록 의미 검색 (RAG)        |
| 임베딩     | all-MiniLM-L6-v2                     | 384차원 벡터, CPU 동작                     |
| 관계형 DB  | PostgreSQL                           | 공격 DB, 테스트 결과, 사용 로그, 위반 이력 |
| 백엔드     | FastAPI                              | REST API, WebSocket                        |
| 프론트엔드 | Next.js 14                           | 대시보드, 보고서, 모니터링 화면            |
| 보고서     | Jinja2 + wkhtmltopdf                 | HTML → PDF                                 |
| 인증       | JWT                                  | 관리자/감사자/직원 역할 분리               |

### 왜 Gemma 4 E2B인가

| 항목                   | Gemma 4 E2B                        |
| ---------------------- | ---------------------------------- |
| 실질 파라미터          | 2.3B                               |
| 총 파라미터 (PLE 포함) | ~5.1B                              |
| 추론 VRAM              | ~5GB                               |
| QLoRA 학습 VRAM        | ~8GB                               |
| 학습 가능 인원         | **전원** (필요 시 Colab 사용)      |
| Ollama 명령            | `ollama pull gemma4:e2b`           |
| 아키텍처               | Dense + PLE (Per-Layer Embeddings) |
| 컨텍스트               | 128K                               |
| 라이선스               | Apache 2.0                         |

QLoRA 학습이 ~8GB VRAM이면 가능하다. 로컬 GPU가 없으면 Google Colab(T4 무료)으로 학습하면 된다. 학습된 어댑터 파일(~30MB)을 공유하면 전원이 동일 환경에서 개발 가능.

---

## 7. 팀 구성 개요

| 역할      | 담당 영역                                              |
| --------- | ------------------------------------------------------ |
| R1 (리드) | Phase 2 Red Agent + Judge 판정 + LangGraph + 전체 관리 |
| R2        | Phase 1 DB 스캐너 + 데이터 적재                        |
| R3        | Phase 3 Blue Agent + Phase 4 Defense Proxy             |
| R4        | RAG 구축 + Ollama 연동 + 학습 코드 작성                |
| R5        | 기능 B: 모니터링 Proxy + 정책 엔진                     |
| R6        | 프론트엔드 전체 (기능 A + B 화면)                      |
| R7        | 백엔드 API + DB + 보고서 + 테스트                      |

**원칙:** 1인 1담당 영역. 파일/폴더 충돌 방지. 상세 역할은 세부기획서 참조.

---

## 8. OWASP 커버리지

| ID    | 위협               | Phase 1 | Phase 2 | Phase 3 | Phase 4 |   수준   |
| ----- | ------------------ | :-----: | :-----: | :-----: | :-----: | :------: |
| LLM01 | Prompt Injection   |    O    |    O    |    O    |    O    | **완전** |
| LLM02 | Sensitive Info     |    O    |    O    |    O    |    O    | **완전** |
| LLM06 | Excessive Agency   |    △    |    O    |    O    |    O    | **완전** |
| LLM07 | System Prompt Leak |    O    |    O    |    O    |    O    | **완전** |

LLM06은 Phase 1에서 자체 구축 ~200건만 시도하되, 규칙 기반 판정이 어려워 대부분 ambiguous로 처리된다. Phase 2(Red Agent)에서 본격 시작하며, Blue Agent가 Execution Guard(NeMo Guardrails 참고)를 생성한다.

---

> **이 문서 요약:**
>
> - AgentShield = AI 보안의 Find + Fix + Verify 자동화 플랫폼
> - OWASP LLM01, 02, 06, 07 4개 카테고리 완전 집중
> - Gemma 4 E2B + QLoRA 3역할 어댑터 (Red/Judge/Blue)
> - 기능 A(보안 테스트) + 기능 B(직원 모니터링) 2축
> - 세부 구현은 → **AgentShield\_세부기획서.md** 참조
> - 기능별 파이프라인은 → **AgentShield*기능별*파이프라인.md** 참조
