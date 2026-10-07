#!/usr/bin/env python3
"""
eval_attack.py
과거 특정 구간을 대상으로 모델 이상점수를 계산해 탐지 여부를 검증한다.
detect_anomaly.py 의 Feature 생성 로직을 그대로 재사용하되,
시간 제한(최근 90분) 없이 전체 타임라인을 점수화하고 지정 구간을 출력한다.

usage: python eval_attack.py "2026-10-07 15:30:00" "2026-10-07 16:40:00"
"""
import sys
import json
import joblib
import numpy as np
import pandas as pd
import pymysql
import config

MODEL_DIR = "model"
HOST = "vm2-target"
WINDOW = "30min"
WARN_TH = 0.0
DANGER_TH = -0.05

METRIC_KEYS = [
    "system.cpu.util[,user]",
    "system.cpu.load[all,avg1]",
    "vm.memory.util",
    'net.if.in["ens33"]',
    'net.if.out["ens33"]',
    "security.ssh.failed",
    "security.ssh.accepted",
    "security.net.conn_total",
    "security.net.conn_synrecv",
    "proc.num",
]
SHORT = {
    "system.cpu.util[,user]": "cpu_user",
    "system.cpu.load[all,avg1]": "load1",
    "vm.memory.util": "mem",
    'net.if.in["ens33"]': "net_in",
    'net.if.out["ens33"]': "net_out",
    "security.ssh.failed": "ssh_fail",
    "security.ssh.accepted": "ssh_ok",
    "security.net.conn_total": "conn",
    "security.net.conn_synrecv": "synrecv",
    "proc.num": "proc",
}


def grade(score):
    if score < DANGER_TH:
        return "위험"
    if score < WARN_TH:
        return "경고"
    return "정상"


def build_all():
    conn = pymysql.connect(**config.DB)
    try:
        sql = """
            SELECT clock, item_key, value FROM metrics
            WHERE host=%s AND item_key IN %s
            ORDER BY clock
        """
        df = pd.read_sql(sql, conn, params=(HOST, tuple(METRIC_KEYS)))
    finally:
        conn.close()
    df["clock"] = pd.to_datetime(df["clock"])
    wide = df.pivot_table(index="clock", columns="item_key", values="value", aggfunc="mean")
    wide = wide.rename(columns=SHORT).sort_index()
    wide = wide.resample("5min").mean().ffill(limit=2)
    feats = {}
    for col in wide.columns:
        r = wide[col].rolling(WINDOW, min_periods=3)
        feats[f"{col}_mean"] = r.mean()
        feats[f"{col}_max"] = r.max()
        feats[f"{col}_std"] = r.std()
    out = pd.DataFrame(feats)
    hour = out.index.hour + out.index.minute / 60.0
    out["hour_sin"] = np.sin(2 * np.pi * hour / 24)
    out["hour_cos"] = np.cos(2 * np.pi * hour / 24)
    return out.dropna(), wide


def main():
    t0, t1 = sys.argv[1], sys.argv[2]
    model = joblib.load(f"{MODEL_DIR}/iforest.pkl")
    scaler = joblib.load(f"{MODEL_DIR}/scaler.pkl")
    with open(f"{MODEL_DIR}/feature_cols.json") as f:
        feature_cols = json.load(f)

    out, wide = build_all()
    X = out[feature_cols].values.astype(float)
    Xs = scaler.transform(X)
    scores = model.decision_function(Xs)
    out = out.copy()
    out["score"] = scores
    out["grade"] = [grade(s) for s in scores]

    print(f"=== 전체 윈도우 {len(out)}개, score 범위 {scores.min():+.4f} ~ {scores.max():+.4f} ===")
    print(f"=== 최저 점수 상위 5개 (가장 이상한 구간) ===")
    worst = out.sort_values("score").head(5)
    for t, r in worst.iterrows():
        print(f"  {t}  score={r['score']:+.4f}  {r['grade']}  cpu_mean={r['cpu_user_mean']:.1f} cpu_max={r['cpu_user_max']:.1f}")

    sel = out[(out.index >= t0) & (out.index <= t1)]
    print(f"\n=== 지정 구간 {t0} ~ {t1} ({len(sel)}개 윈도우) ===")
    for t, r in sel.iterrows():
        mark = {"정상": "[OK]", "경고": "[WARN]", "위험": "[DANGER]"}[r["grade"]]
        print(f"  {mark} {t}  score={r['score']:+.4f}  cpu_user mean={r['cpu_user_mean']:.1f} max={r['cpu_user_max']:.1f} std={r['cpu_user_std']:.1f}  load1_mean={r['load1_mean']:.2f}")

    if len(sel):
        best = sel.sort_values("score").iloc[0]
        bt = sel.sort_values("score").index[0]
        print(f"\n구간 내 최저점수: {bt}  score={best['score']:+.4f}  판정={best['grade']}")
        # top contributing features at that worst window
        row = sel.sort_values("score").iloc[[0]]
        xs = scaler.transform(row[feature_cols].values.astype(float))[0]
        idx = np.argsort(-np.abs(xs))[:5]
        print("기여 Feature:", ", ".join(f"{feature_cols[i]}({xs[i]:+.1f})" for i in idx))


if __name__ == "__main__":
    main()
