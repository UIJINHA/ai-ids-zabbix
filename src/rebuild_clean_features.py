#!/usr/bin/env python3
"""
rebuild_clean_features.py
전체 metrics로 Feature를 재생성하되, 알려진 공격 구간(+30분 롤링 bleed)을
제외하고 features 테이블에 저장한다. (재학습용 정상 데이터 갱신)
build_features 의 load_raw/build/save 를 그대로 재사용.
"""
import pandas as pd
from datetime import timedelta
import build_features as B

LOOKBACK = 30  # 분. 30분 롤링 창이 공격을 '보는' 범위까지 제외

# 2026-10-07 공격 구간 (evaluate.py 와 동일 기준)
ATTACKS = [
    ("2026-10-07 10:18", "2026-10-07 10:22"),  # SSH brute v1
    ("2026-10-07 10:24", "2026-10-07 10:25"),  # nmap scan
    ("2026-10-07 10:50", "2026-10-07 11:17"),  # SSH brute v2
    ("2026-10-07 13:25", "2026-10-07 14:17"),  # SSH brute v3
    ("2026-10-07 14:24", "2026-10-07 14:45"),  # DoS web(ab)
    ("2026-10-07 15:43", "2026-10-07 16:28"),  # CPU mining(stress-ng)
    ("2026-10-07 21:32", "2026-10-07 22:05"),  # data exfil(nc)
]


def main():
    df = B.load_raw()
    out = B.build(df)  # columns include 'clock'
    out["clock"] = pd.to_datetime(out["clock"])
    before = len(out)

    mask = pd.Series(False, index=out.index)
    for s, e in ATTACKS:
        s = pd.Timestamp(s)
        e = pd.Timestamp(e) + timedelta(minutes=LOOKBACK)
        mask |= (out["clock"] >= s) & (out["clock"] <= e)
    removed = int(mask.sum())
    clean = out[~mask].reset_index(drop=True)

    n_rows, n_cols = B.save(clean)
    print(f"[INFO] 전체 Feature {before}개 → 공격구간 {removed}개 제외 → 정상 {n_rows}개 저장")
    print(f"[INFO] 기간: {clean['clock'].min()} ~ {clean['clock'].max()}, 컬럼 {n_cols}개")
    # 날짜별 분포(최근 데이터가 늘었는지 확인)
    byday = clean["clock"].dt.date.value_counts().sort_index()
    print("[INFO] 날짜별 샘플 수:")
    for d, n in byday.items():
        print(f"   {d}: {n}")


if __name__ == "__main__":
    main()
