"""
Phase 5 외부 공유 산출물 — HTML + (옵션) PDF 생성.

[설계]
- Jinja2로 HTML을 먼저 만든다. HTML은 항상 생성됨.
- WeasyPrint가 설치/로드 가능하면 PDF도 같이 생성.
- WeasyPrint는 시스템 의존성(pango, cairo)이 필요해 환경에 따라 import 실패할 수 있으므로
  lazy import + 실패 시 로그만 남기고 HTML로 폴백한다.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.core import owasp_guidance
from backend.core.policy_package_schema import PackageManifest, VerifiedFinding
from backend.core.redaction import mask_for_external_share


logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "j2", "html.j2"]),
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _category_summary(findings: list[VerifiedFinding]) -> list[dict[str, Any]]:
    by_cat: dict[str, int] = {}
    for f in findings:
        key = (f.category or "UNKNOWN").upper()
        by_cat[key] = by_cat.get(key, 0) + 1
    summary: list[dict[str, Any]] = []
    for code in sorted(by_cat.keys()):
        entry = owasp_guidance.get_category(code) or {}
        summary.append({
            "code": code,
            "name": entry.get("name", ""),
            "verified_count": by_cat[code],
            "default_action": entry.get("default_action", "refuse"),
            "action_label_ko": entry.get("action_label_ko", ""),
            "fix_targets": entry.get("fix_targets") or [],
            "reference_url": entry.get("reference_url", ""),
        })
    return summary


def _finding_view(f: VerifiedFinding) -> dict[str, Any]:
    """외부 공유 PDF용 — 마스킹된 사본 + OWASP 가이드 합쳐서 템플릿에 넘김."""
    entry = owasp_guidance.get_category(f.category) or {}
    return {
        "category": (f.category or "UNKNOWN").upper(),
        "category_name": entry.get("name", ""),
        "severity": (f.severity or "medium").lower(),
        "attack_prompt": mask_for_external_share(f.attack_prompt),
        "target_response": mask_for_external_share(f.target_response),
        "defended_response": mask_for_external_share(f.defended_response),
        "defense_rationale": f.defense_rationale,
        "default_action": entry.get("default_action", ""),
        "action_label_ko": entry.get("action_label_ko", ""),
        "fix_targets": entry.get("fix_targets") or [],
    }


def render_html(
    *,
    template_name: str,
    session_id: str,
    manifest: PackageManifest,
    findings: list[VerifiedFinding],
    regression_count: int,
) -> str:
    template = _env.get_template(template_name)
    return template.render(
        session_id=session_id,
        generated_at=_now_iso(),
        manifest=manifest,
        regression_count=regression_count,
        category_summary=_category_summary(findings),
        findings=[_finding_view(f) for f in findings],
    )


def _html_to_pdf(html: str, out_path: Path) -> bool:
    """WeasyPrint로 PDF 생성. 성공 시 True, 실패 시 False (로그만)."""
    try:
        from weasyprint import HTML  # type: ignore
    except Exception as exc:
        logger.warning(
            "[pdf_export] WeasyPrint import 실패 — HTML만 생성됨. (PDF가 필요하면 `pip install weasyprint`. "
            "macOS는 추가로 `brew install pango`가 필요할 수 있음): %s",
            exc,
        )
        return False
    try:
        HTML(string=html, base_url=str(_TEMPLATE_DIR)).write_pdf(str(out_path))
        return True
    except Exception:
        logger.exception("[pdf_export] WeasyPrint write_pdf 실패")
        return False


def export_reports(
    *,
    out_dir: Path,
    session_id: str,
    manifest: PackageManifest,
    findings: list[VerifiedFinding],
    regression_count: int,
) -> dict[str, Optional[str]]:
    """
    외부 공유 산출물 생성. 항상 HTML 2개 + (가능하면) PDF 2개.
    반환: 생성된 파일들의 상대 경로 dict.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    exec_html = render_html(
        template_name="policy_executive.html.j2",
        session_id=session_id,
        manifest=manifest,
        findings=findings,
        regression_count=regression_count,
    )
    full_html = render_html(
        template_name="policy_full_report.html.j2",
        session_id=session_id,
        manifest=manifest,
        findings=findings,
        regression_count=regression_count,
    )

    exec_html_path = out_dir / "executive_summary.html"
    full_html_path = out_dir / "full_report.html"
    exec_html_path.write_text(exec_html, encoding="utf-8")
    full_html_path.write_text(full_html, encoding="utf-8")

    exec_pdf_path = out_dir / "executive_summary.pdf"
    full_pdf_path = out_dir / "full_report.pdf"
    exec_pdf_ok = _html_to_pdf(exec_html, exec_pdf_path)
    full_pdf_ok = _html_to_pdf(full_html, full_pdf_path)

    return {
        "executive_summary_html": str(exec_html_path.name),
        "full_report_html": str(full_html_path.name),
        "executive_summary_pdf": str(exec_pdf_path.name) if exec_pdf_ok else None,
        "full_report_pdf": str(full_pdf_path.name) if full_pdf_ok else None,
    }
