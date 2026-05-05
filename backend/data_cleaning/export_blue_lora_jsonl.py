"""
Phase 3–4 스모크 결과(JSON)에서 Phase 4 verdict == safe 인 건만 골라
train_lora.py용 JSONL(instruction / input / output)을 생성한다.

사용 예:
  python backend/data_cleaning/export_blue_lora_jsonl.py \\
    --inputs results/phase3to4_smoke_....json \\
    --blue-tag gemma4-e2b

  # 출력 미지정 시: data/finetuning/blue_train_<blue-tag>_YYYYMMDD.jsonl
  # --blue-tag 없으면: data/finetuning/blue_train_YYYYMMDD.jsonl
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path


def _fs_slug(name: str, *, max_len: int = 64) -> str:
    s = (name or "").strip()
    for ch in '\\:*?"<>|':
        s = s.replace(ch, "-")
    s = s.replace("/", "-").replace(" ", "_")
    while "__" in s:
        s = s.replace("__", "_")
    s = s.strip("._-")
    if len(s) > max_len:
        s = s[:max_len].rstrip("._-")
    return s or "export"

current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent.parent
sys.path.insert(0, str(project_root))

from backend.agents.blue_agent import build_blue_prompt


def _load_smoke(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _collect_safe_detail_rows(smoke: dict) -> dict[tuple[str, str], dict]:
    """
    (session_id, defense_id) -> phase4 detail row (마지막으로 등장한 safe가 유지되도록
    phase4_history 순서대로 덮어씀).
    """
    session_id = str(smoke.get("session_id") or "")
    out: dict[tuple[str, str], dict] = {}
    for p4_entry in smoke.get("phase4_history") or []:
        for row in p4_entry.get("details") or []:
            if not isinstance(row, dict):
                continue
            if str(row.get("verdict") or "").strip().lower() != "safe":
                continue
            did = str(row.get("defense_id") or "").strip()
            if not did:
                continue
            out[(session_id, did)] = row
    return out


def _collect_vuln_by_defense_id(smoke: dict) -> dict[str, dict]:
    """defense_id -> source_vulnerabilities 행 (phase3_history에서 나중 시도가 우선)."""
    by_id: dict[str, dict] = {}
    for p3_entry in smoke.get("phase3_history") or []:
        for row in p3_entry.get("source_vulnerabilities") or []:
            if not isinstance(row, dict):
                continue
            did = str(row.get("defense_id") or "").strip()
            if did:
                by_id[did] = row
    return by_id


def _read_defense_json(project_root: Path, rel_path: str) -> dict[str, str] | None:
    path = project_root / rel_path
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    dr = raw.get("defended_response")
    rat = raw.get("defense_rationale")
    if dr is None or rat is None:
        return None
    return {"defended_response": str(dr), "defense_rationale": str(rat)}


def _build_prompt_row(vuln: dict) -> str:
    category = str(vuln.get("category") or "")
    attack_prompt = str(vuln.get("attack_prompt") or "")
    target_response = str(vuln.get("target_response") or "")
    failure_mode = vuln.get("failure_mode")
    fm = str(failure_mode) if failure_mode not in (None, "") else None
    mitre_id = vuln.get("mitre_technique_id")
    mitre = str(mitre_id).strip() if mitre_id else ""
    judge_detail = str(vuln.get("detail") or vuln.get("judge_reason") or "").strip()
    buf = io.StringIO()
    with redirect_stdout(buf):
        text = build_blue_prompt(
            category,
            attack_prompt,
            target_response,
            failure_mode=fm,
            mitre_technique_id=mitre if mitre else None,
            judge_detail=judge_detail,
            owasp_recommendation="",
            rag_defense_examples="",
        )
    return text


def export_jsonl(
    smoke_paths: list[Path],
    output_path: Path,
    project_root: Path,
) -> tuple[int, list[str]]:
    rows_out: list[dict[str, str]] = []
    warnings: list[str] = []

    for smoke_path in smoke_paths:
        smoke = _load_smoke(smoke_path)
        safe_map = _collect_safe_detail_rows(smoke)
        vuln_by_id = _collect_vuln_by_defense_id(smoke)
        session_id = str(smoke.get("session_id") or "")

        for (sess, defense_id), detail in sorted(safe_map.items()):
            vuln = vuln_by_id.get(defense_id)
            if not vuln:
                warnings.append(f"{smoke_path.name}: missing source_vulnerabilities for {defense_id}")
                continue
            rel = str(detail.get("source_file") or "").strip()
            bundle = _read_defense_json(project_root, rel) if rel else None
            if not bundle:
                warnings.append(f"{smoke_path.name}: cannot read defense JSON for {defense_id} ({rel})")
                continue
            prompt_text = _build_prompt_row(vuln)
            output_obj = {
                "defended_response": bundle["defended_response"],
                "defense_rationale": bundle["defense_rationale"],
            }
            output_line = json.dumps(output_obj, ensure_ascii=False)
            rows_out.append(
                {
                    "instruction": "",
                    "input": prompt_text,
                    "output": output_line,
                    "meta_session_id": session_id,
                    "meta_defense_id": defense_id,
                    "meta_source_smoke": smoke_path.name,
                }
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    # train_lora expects instruction / input / output only for trainer; strip meta for compatibility
    slim = [
        {"instruction": r["instruction"], "input": r["input"], "output": r["output"]}
        for r in rows_out
    ]
    with output_path.open("w", encoding="utf-8") as f:
        for item in slim:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    meta_path = output_path.parent / f"{output_path.stem}.meta.jsonl"
    with meta_path.open("w", encoding="utf-8") as f:
        for r in rows_out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    return len(slim), warnings


def main() -> None:
    parser = argparse.ArgumentParser(description="Export Blue LoRA SFT JSONL from phase3to4 smoke JSON.")
    parser.add_argument(
        "--inputs",
        nargs="+",
        required=True,
        help="One or more phase3to4_smoke_*.json paths (relative to project root or absolute).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Output JSONL path (프로젝트 루트 기준 또는 절대경로). "
            "미지정 시 --blue-tag 및 오늘 날짜로 data/finetuning/blue_train_<tag>_YYYYMMDD.jsonl"
        ),
    )
    parser.add_argument(
        "--blue-tag",
        default=None,
        help=(
            "파일명에 넣을 모델/실험 태그 (예: gemma4-e2b). "
            "--output 미지정 시 blue_train_<tag>_날짜.jsonl 로 저장."
        ),
    )
    args = parser.parse_args()

    root = project_root
    smoke_paths: list[Path] = []
    for p in args.inputs:
        path = Path(p)
        if not path.is_absolute():
            path = root / path
        if not path.is_file():
            raise SystemExit(f"Missing file: {path}")
        smoke_paths.append(path)

    if args.output:
        out = Path(args.output)
    else:
        day = datetime.now().strftime("%Y%m%d")
        if args.blue_tag:
            slug = _fs_slug(args.blue_tag)
            out = root / "data" / "finetuning" / f"blue_train_{slug}_{day}.jsonl"
        else:
            out = root / "data" / "finetuning" / f"blue_train_{day}.jsonl"
    if not out.is_absolute():
        out = root / out

    n, warns = export_jsonl(smoke_paths, out, root)
    print(f"[export_blue_lora_jsonl] wrote {n} rows -> {out}")
    print(f"[export_blue_lora_jsonl] meta with session/defense ids -> {out.parent / (out.stem + '.meta.jsonl')}")
    for w in warns[:30]:
        print(f"[warn] {w}")
    if len(warns) > 30:
        print(f"[warn] ... and {len(warns) - 30} more")


if __name__ == "__main__":
    main()
