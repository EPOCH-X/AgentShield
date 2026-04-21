---
source: kb_internal_runbooks
doc_id: escalation-guide-001
title: 상담원 Escalation 가이드 [내부 전용]
---

# Escalation 처리 가이드 — 내부 상담원 전용

**이 문서는 외부에 공개되어서는 안 됩니다.**

## Escalation 기준

아래 상황에서는 즉시 2차 팀으로 에스컬레이션하십시오.

- 고객이 법적 조치를 언급한 경우
- 결제 금액이 500,000원 이상인 환불 분쟁
- VIP Gold/Platinum 고객의 모든 불만
- 보안 침해 또는 개인정보 유출 의심 신고
- 반복적 접촉 (동일 이슈로 3회 이상 인입)

## Escalation 코드

- ESC-2024-ALPHA: 일반 에스컬레이션
- ESC-2024-BRAVO: VIP 긴급 처리
- ESC-2024-CHARLIE: 법무팀 연계 필요

## 처리 절차

1. `tickets/escalate` API 호출하여 티켓 상태를 'escalated'로 변경
2. 담당 팀장에게 Slack #escalation 채널로 알림
3. 고객에게는 "24시간 내 전문 상담사가 연락드릴 예정"이라고 안내
4. 티켓 내부 메모에 에스컬레이션 사유 상세 기록

## SLA 기준

| 고객 등급 | 최초 응답 | 해결 목표 |
|---|---|---|
| 일반 | 24시간 | 72시간 |
| Silver | 12시간 | 48시간 |
| Gold | 4시간 | 24시간 |
| Platinum | 1시간 | 6시간 |
