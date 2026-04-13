"""
[R2] 공격 프롬프트 수집 + 정제 스크립트
실행: python data/attack_patterns/collect_data.py

처리 데이터셋:
  1. JailbreakBench (100건)
  2. HarmBench (추후 추가)
  3. Necent (추후 추가)

출력: data/attack_patterns/collected_attacks.json
"""

import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


# ── 카테고리 매핑 테이블 ──────
JBB_CATEGORY_MAP = {
    "Harassment/Discrimination": "LLM01",
    "Malware/Hacking":           "LLM01",
    "Physical harm":             "LLM01",
    "Fraud/Deception":           "LLM01",
    "Disinformation":            "LLM01",
    "Sexual/Adult content":      "LLM01",
    "Expert advice":             "LLM01",
    "Government decision-making":"LLM01",
    "Privacy":                   "LLM02",
    "Economic harm":             "LLM06",
}

JBB_SEVERITY_MAP = {
    "LLM01": "High",
    "LLM02": "High",
    "LLM06": "Critical",
    "LLM07": "High",
}


# ── 1. JailbreakBench 수집 
def collect_jailbreakbench() -> list[dict]:
    print("📥 JailbreakBench 수집 중...")
    try:
        import jailbreakbench as jbb
        data = jbb.read_dataset()
        df = data.df

        results = []
        for _, row in df.iterrows():
            prompt = str(row["Goal"]).strip()

            # 길이 필터 (10~2000자)
            if not (10 <= len(prompt) <= 2000):
                continue

            category = JBB_CATEGORY_MAP.get(row["Category"], "LLM01")

            results.append({
                "prompt_text": prompt,
                "category": category,
                "subcategory": str(row["Behavior"]).strip(),
                "severity": JBB_SEVERITY_MAP.get(category, "High"),
                "source": "jailbreakbench",
                "language": "en",
            })

        print(f"  ✅ JailbreakBench: {len(results)}건 수집")
        return results

    except ImportError:
        print("  ❌ jailbreakbench 패키지 없음. pip install jailbreakbench")
        return []


# ── 2. HarmBench 수집 (추후 구현) 
def collect_harmbench() -> list[dict]:
    print("📥 HarmBench 수집 중... (미구현, 추후 추가)")
    return []


# ── 3. Necent 수집 (추후 구현) 
def collect_necent() -> list[dict]:
    print("📥 Necent 수집 중... (미구현, 추후 추가)")
    return []


# 중복 제거
def remove_duplicates(attacks: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for item in attacks:
        key = item["prompt_text"].lower().strip()
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


# ── 메인 실행
def main():
    print("=" * 50)
    print("AgentShield 공격 프롬프트 수집 시작")
    print("=" * 50)

    all_attacks = []
    all_attacks.extend(collect_jailbreakbench())
    all_attacks.extend(collect_harmbench())
    all_attacks.extend(collect_necent())

    # 중복 제거
    before = len(all_attacks)
    all_attacks = remove_duplicates(all_attacks)
    print(f"\n🔄 중복 제거: {before}건 → {len(all_attacks)}건")

    # 카테고리별 통계
    print("\n📊 카테고리별 통계:")
    from collections import Counter
    stats = Counter(item["category"] for item in all_attacks)
    for cat, count in sorted(stats.items()):
        print(f"  {cat}: {count}건")

    # JSON 저장
    output_path = os.path.join(os.path.dirname(__file__), "collected_attacks.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_attacks, f, ensure_ascii=False, indent=2)

    print(f"\n✅ 총 {len(all_attacks)}건 저장 완료!")
    print(f"📁 저장 위치: {output_path}")
    print("=" * 50)


if __name__ == "__main__":
    main()