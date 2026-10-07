#!/usr/bin/env python3
"""
evaluate.py
라벨된 공격 구간에 대해 현재 하이브리드 탐지기(모델+룰)의 성능을 측정한다.
- detect_anomaly.rule_check / model_grade 를 그대로 재사용(실제 탐지기와 동일 로직)
- eval_attack.build_all 로 전체 타임라인 Feature 생성
결과 요약 1행을 results/tuning-log.csv 에 append, 상세는 콘솔 출력.

usage: PYTHONPATH=src python src/evaluate.py "튜닝노트"
"""
import sys, os, csv, json
import joblib, numpy as np, pandas as pd
from datetime import timedelta

import config
import detect_anomaly as D
import eval_attack as E

GRADE = D.GRADE_ORDER  # 정상0 경고1 위험2
LOOKBACK_MIN = 30      # 30분 롤링 창이 공격 신호를 보는 범위

# ground truth 공격 구간 (2026-10-07). (이름, 시작, 끝, 기대탐지원)
ATTACKS = [
    ("SSH무차별 v1", "2026-10-07 10:18", "2026-10-07 10:22", "rule"),
    ("SSH무차별 v2", "2026-10-07 10:50", "2026-10-07 11:17", "rule"),
    ("SSH무차별 v3", "2026-10-07 13:25", "2026-10-07 14:17", "rule"),
    ("DoS 웹(ab)",   "2026-10-07 14:24", "2026-10-07 14:45", "model"),
    ("채굴형 CPU",   "2026-10-07 15:43", "2026-10-07 16:28", "model"),
    ("데이터 유출",  "2026-10-07 21:32", "2026-10-07 22:05", "rule"),
]


def classify(row, model, scaler, feature_cols):
    X = row[feature_cols].values.astype(float)
    score = float(model.decision_function(scaler.transform(X))[0])
    m_grade = D.model_grade(score)
    rule_hits = D.rule_check(row)
    cands = [(m_grade, "model", f"score {score:+.4f}")]
    for g, why in rule_hits:
        cands.append((g, "rule", why))
    g, src, why = max(cands, key=lambda x: GRADE[x[0]])
    return score, g, src, why


def main():
    note = sys.argv[1] if len(sys.argv) > 1 else "baseline"
    # 선택: argv[2]=DANGER_TH, argv[3]=WARN_TH 오버라이드(모델 임계 튜닝 실험용)
    if len(sys.argv) > 2:
        D.DANGER_TH = float(sys.argv[2])
    if len(sys.argv) > 3:
        D.WARN_TH = float(sys.argv[3])
    model = joblib.load("model/iforest.pkl")
    scaler = joblib.load("model/scaler.pkl")
    with open("model/feature_cols.json") as f:
        feature_cols = json.load(f)
    contamination = getattr(model, "contamination", "?")

    out, _ = E.build_all()
    recs = []
    for t in out.index:
        row = out.loc[[t]]
        score, g, src, why = classify(row, model, scaler, feature_cols)
        recs.append((t, score, g, src, why))

    def attacks_seen(t):
        hit = []
        for name, s, e, _ in ATTACKS:
            s, e = pd.Timestamp(s), pd.Timestamp(e)
            if t >= s and (t - timedelta(minutes=LOOKBACK_MIN)) <= e:
                hit.append(name)
        return hit

    # 공격별 탐지 결과
    print("=== 공격별 탐지 결과 ===")
    detected = 0
    per_attack = []
    for name, s, e, exp in ATTACKS:
        s, e = pd.Timestamp(s), pd.Timestamp(e)
        wins = [r for r in recs if r[0] >= s and (r[0] - timedelta(minutes=LOOKBACK_MIN)) <= e]
        if not wins:
            print(f"  [N/A ] {name:12s} : 데이터 없음")
            per_attack.append((name, "NA", "-"))
            continue
        best = max(wins, key=lambda r: (GRADE[r[2]], -r[1]))
        ok = GRADE[best[2]] >= GRADE["경고"]
        detected += 1 if ok else 0
        mark = {"정상": "미탐", "경고": "탐지(경고)", "위험": "탐지(위험)"}[best[2]]
        print(f"  [{'OK ' if ok else 'MISS'}] {name:12s} : {mark:10s} via {best[3]:5s} "
              f"(기대 {exp}) @ {best[0].strftime('%H:%M')} score={best[1]:+.4f} | {best[4]}")
        per_attack.append((name, best[2], best[3]))

    # 오탐(FP): 어떤 공격 창에도 속하지 않는데 경고/위험
    fp_warn = fp_danger = 0
    normal = 0
    fp_list = []
    for t, score, g, src, why in recs:
        if attacks_seen(t):
            continue
        normal += 1
        if g == "위험":
            fp_danger += 1; fp_list.append((t, g, src, why, score))
        elif g == "경고":
            fp_warn += 1; fp_list.append((t, g, src, why, score))
    fp_total = fp_warn + fp_danger
    fp_rate = round(100.0 * fp_total / normal, 2) if normal else 0.0

    print(f"\n=== 오탐(FP): 정상 {normal}창 중 {fp_total}건 ({fp_rate}%) "
          f"[위험 {fp_danger}, 경고 {fp_warn}] ===")
    for t, g, src, why, score in fp_list[:20]:
        print(f"  {t} [{g}] via {src} score={score:+.4f} | {why}")

    n_real = sum(1 for p in per_attack if p[1] != "NA")
    print(f"\n=== 요약 : 공격 {n_real}종 중 탐지 {detected} / 미탐 {n_real-detected}, "
          f"오탐 {fp_total}건({fp_rate}%) ===")

    # tuning-log.csv append
    os.makedirs("results", exist_ok=True)
    path = "results/tuning-log.csv"
    header = ["date","note","contamination","warn_th","danger_th",
              "netout_warn_mb","netout_danger_mb","attacks","detected","missed",
              "fp_danger","fp_warn","normal_windows","fp_rate_pct"]
    newfile = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if newfile:
            w.writerow(header)
        w.writerow([pd.Timestamp.now().strftime("%Y-%m-%d %H:%M"), note,
                    contamination, D.WARN_TH, D.DANGER_TH, 50, 25,
                    n_real, detected, n_real-detected,
                    fp_danger, fp_warn, normal, fp_rate])
    print(f"\n[기록] {path} 에 1행 append")


if __name__ == "__main__":
    main()
