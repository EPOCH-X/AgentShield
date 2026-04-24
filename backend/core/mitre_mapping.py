"""
MITRE ATT&CK Enterprise — LLM 취약점 카테고리 매핑

출처:
  - MITRE ATT&CK v16 Enterprise: https://attack.mitre.org/
  - OWASP LLM Top-10 2025 ↔ ATT&CK 매핑 (CyberSecEval 4 / Meta PurpleLlama)

매핑 원칙:
  - 각 LLM 카테고리(LLM01~07)의 failure_mode별로 가장 근접한 ATT&CK 전술/기법 1~3개를 할당
  - 단일 카테고리 → 대표 기법(primary)을 먼저, 보조 기법(secondary) 이후
  - 업데이트는 이 파일만 수정하면 전체 파이프라인에 자동 반영됨
"""

from __future__ import annotations

from typing import TypedDict


class MitreTechnique(TypedDict):
    technique_id: str    # e.g. "T1059.004"
    name: str            # e.g. "Command and Scripting Interpreter: Unix Shell"
    tactic: str          # e.g. "Execution"
    url: str


class MitreMapping(TypedDict):
    primary: MitreTechnique
    secondary: list[MitreTechnique]
    notes: str


# ── 개별 기법 정의 ────────────────────────────────────────────────
# LLM01 / LLM02 / LLM06 / LLM07 에서 실제로 참조하는 기법만 정의

_T = {
    # LLM01: Prompt Injection
    "T1059": MitreTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/",
    ),
    "T1059.004": MitreTechnique(
        technique_id="T1059.004",
        name="Command and Scripting Interpreter: Unix Shell",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/004/",
    ),
    "T1190": MitreTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1190/",
    ),
    "T1203": MitreTechnique(
        technique_id="T1203",
        name="Exploitation for Client Execution",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1203/",
    ),
    "T1566.001": MitreTechnique(
        technique_id="T1566.001",
        name="Phishing: Spearphishing Attachment",
        tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1566/001/",
    ),
    # LLM02: Sensitive Information Disclosure
    "T1530": MitreTechnique(
        technique_id="T1530",
        name="Data from Cloud Storage",
        tactic="Collection",
        url="https://attack.mitre.org/techniques/T1530/",
    ),
    "T1552.001": MitreTechnique(
        technique_id="T1552.001",
        name="Unsecured Credentials: Credentials In Files",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1552/001/",
    ),
    "T1213": MitreTechnique(
        technique_id="T1213",
        name="Data from Information Repositories",
        tactic="Collection",
        url="https://attack.mitre.org/techniques/T1213/",
    ),
    "T1589": MitreTechnique(
        technique_id="T1589",
        name="Gather Victim Identity Information",
        tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1589/",
    ),
    "T1005": MitreTechnique(
        technique_id="T1005",
        name="Data from Local System",
        tactic="Collection",
        url="https://attack.mitre.org/techniques/T1005/",
    ),
    "T1114": MitreTechnique(
        technique_id="T1114",
        name="Email Collection",
        tactic="Collection",
        url="https://attack.mitre.org/techniques/T1114/",
    ),
    # LLM06: Excessive Agency
    "T1106": MitreTechnique(
        technique_id="T1106",
        name="Native API",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1106/",
    ),
    "T1053": MitreTechnique(
        technique_id="T1053",
        name="Scheduled Task/Job",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1053/",
    ),
    "T1649": MitreTechnique(
        technique_id="T1649",
        name="Steal or Forge Authentication Certificates",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1649/",
    ),
    "T1078": MitreTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Privilege Escalation / Defense Evasion",
        url="https://attack.mitre.org/techniques/T1078/",
    ),
    "T1499": MitreTechnique(
        technique_id="T1499",
        name="Endpoint Denial of Service",
        tactic="Impact",
        url="https://attack.mitre.org/techniques/T1499/",
    ),
    "T1489": MitreTechnique(
        technique_id="T1489",
        name="Service Stop",
        tactic="Impact",
        url="https://attack.mitre.org/techniques/T1489/",
    ),
    # LLM07: System Prompt Leakage
    "T1592": MitreTechnique(
        technique_id="T1592",
        name="Gather Victim Host Information",
        tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1592/",
    ),
}


# ── 카테고리 × failure_mode → MITRE 매핑 ─────────────────────────

# 키 형식: "LLM01" (카테고리 전체 대표) 또는 "LLM01:boundary_breach" (failure_mode별 세분화)
MITRE_CATEGORY_MAP: dict[str, MitreMapping] = {

    # ── LLM01: Prompt Injection ──────────────────────────────────
    "LLM01": MitreMapping(
        primary=_T["T1190"],
        secondary=[_T["T1059"], _T["T1203"]],
        notes="Prompt injection exploits the LLM application boundary similar to "
              "exploiting a public-facing web application (T1190). Injected instructions "
              "can lead to arbitrary command execution paths (T1059).",
    ),
    "LLM01:boundary_breach": MitreMapping(
        primary=_T["T1190"],
        secondary=[_T["T1059"]],
        notes="Untrusted content crosses trust boundaries → Initial Access + Execution.",
    ),
    "LLM01:multimodal_leak": MitreMapping(
        primary=_T["T1566.001"],
        secondary=[_T["T1203"]],
        notes="File/image-embedded instructions → Spearphishing Attachment analog.",
    ),
    "LLM01:obfuscation_bypass": MitreTechnique(  # type: ignore[assignment]
        technique_id="T1027",
        name="Obfuscated Files or Information",
        tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1027/",
    ),

    # ── LLM02: Sensitive Information Disclosure ──────────────────
    "LLM02": MitreMapping(
        primary=_T["T1552.001"],
        secondary=[_T["T1213"], _T["T1530"]],
        notes="LLM leaking credentials, PII, internal data maps to Unsecured Credentials "
              "(T1552) and Data from Information Repositories (T1213).",
    ),
    "LLM02:training_data_leak": MitreMapping(
        primary=_T["T1213"],
        secondary=[_T["T1005"]],
        notes="Training data reconstruction → Collection from local/internal repositories.",
    ),
    "LLM02:system_prompt_leak": MitreMapping(
        primary=_T["T1552.001"],
        secondary=[_T["T1592"]],
        notes="System prompt exfiltration → credential/config leak analog.",
    ),
    "LLM02:pii_exfiltration": MitreMapping(
        primary=_T["T1589"],
        secondary=[_T["T1114"]],
        notes="Forced PII output → Identity info gathering + Email collection.",
    ),

    # ── LLM06: Excessive Agency ──────────────────────────────────
    "LLM06": MitreMapping(
        primary=_T["T1106"],
        secondary=[_T["T1053"], _T["T1059.004"]],
        notes="LLM agent acting beyond intended scope → Native API invocation (T1106), "
              "scheduled task abuse (T1053), shell execution (T1059.004).",
    ),
    "LLM06:unauthorized_action": MitreMapping(
        primary=_T["T1106"],
        secondary=[_T["T1059"]],
        notes="Agent executes unapproved action via API/tool call.",
    ),
    "LLM06:privilege_escalation": MitreMapping(
        primary=_T["T1078"],
        secondary=[_T["T1649"]],
        notes="Agent obtains elevated permissions beyond task scope.",
    ),
    "LLM06:resource_exhaustion": MitreMapping(
        primary=_T["T1499"],
        secondary=[_T["T1489"]],
        notes="Unbounded agent loops → DoS / Service Stop.",
    ),

    # ── LLM07: System Prompt Leakage ────────────────────────────
    "LLM07": MitreMapping(
        primary=_T["T1592"],
        secondary=[_T["T1552.001"]],
        notes="Extracting system prompts reveals internal architecture/secrets.",
    ),

    # ── 기본 폴백 ────────────────────────────────────────────────
    "UNKNOWN": MitreMapping(
        primary=_T["T1190"],
        secondary=[],
        notes="Category not mapped — defaulting to Exploit Public-Facing Application.",
    ),
}


def get_mitre_mapping(category: str, failure_mode: str | None = None) -> MitreMapping:
    """
    카테고리(+선택적 failure_mode)에 해당하는 MITRE 매핑 반환.

    Args:
        category: "LLM01" ~ "LLM09" 형식
        failure_mode: "boundary_breach" 등 (없으면 카테고리 대표 매핑 사용)

    Returns:
        MitreMapping TypedDict
    """
    if failure_mode:
        key = f"{category}:{failure_mode}"
        if key in MITRE_CATEGORY_MAP:
            mapping = MITRE_CATEGORY_MAP[key]
            # obfuscation_bypass처럼 MitreTechnique를 직접 값으로 넣은 경우 래핑
            if "primary" not in mapping:  # type: ignore[operator]
                return MitreMapping(
                    primary=mapping,  # type: ignore[arg-type]
                    secondary=[],
                    notes=f"Direct technique mapping for {key}",
                )
            return mapping
    return MITRE_CATEGORY_MAP.get(category, MITRE_CATEGORY_MAP["UNKNOWN"])


def get_primary_technique_id(category: str, failure_mode: str | None = None) -> str:
    """빠른 조회용 — 대표 MITRE technique ID 문자열만 반환."""
    mapping = get_mitre_mapping(category, failure_mode)
    primary = mapping.get("primary") or mapping  # type: ignore[arg-type]
    return primary.get("technique_id", "T1190")


def get_mitre_table() -> list[dict]:
    """
    전체 매핑 테이블을 API 응답용 리스트로 직렬화.
    /api/v1/scan/mitre-mapping 엔드포인트에서 사용.
    """
    rows = []
    for key, mapping in MITRE_CATEGORY_MAP.items():
        category, _, failure_mode = key.partition(":")
        if "primary" in mapping:  # type: ignore[operator]
            primary = mapping["primary"]  # type: ignore[index]
            rows.append({
                "category": category,
                "failure_mode": failure_mode or None,
                "primary_technique_id": primary["technique_id"],
                "primary_technique_name": primary["name"],
                "tactic": primary["tactic"],
                "url": primary["url"],
                "secondary": [
                    {"technique_id": t["technique_id"], "name": t["name"]}
                    for t in mapping.get("secondary", [])  # type: ignore[call-overload]
                ],
                "notes": mapping.get("notes", ""),  # type: ignore[call-overload]
            })
    return rows
