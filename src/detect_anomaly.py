#!/usr/bin/env python3
"""
detect_anomaly.py
최신 지표로 Feature를 만들어 두 가지 방식으로 이상을 판정한다.
  1) Isolation Forest 모델  - 자원을 흔드는 공격 (DoS, 채굴, 유출)
  2) 룰 기반 규칙            - 로그에만 흔적이 남는 공격 (무차별 대입, 스캔)
최종 등급은 두 결과 중 더 심각한 쪽을 택한다.
"""

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

GRADE_ORDER = {"정상": 0, "경고": 1, "위험": 2}

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


def load_recent_features():
    conn = pymysql.connect(**config.DB)
    try:
        sql = """
            SELECT clock, item_key, value FROM metrics
            WHERE host=%s AND item_key IN %s
              AND clock > now() - interval 90 minute
            ORDER BY clock
        """
        df = pd.read_sql(sql, conn, params=(HOST, tuple(METRIC_KEYS)))
    finally:
        conn.close()
    if df.empty:
        return None

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
    out = out.dropna()
    if out.empty:
        return None
    return out.iloc[[-1]]


def model_grade(score):
    if score < DANGER_TH:
        return "위험"
    if score < WARN_TH:
        return "경고"
    return "정상"


def rule_check(row):
    g = lambda c: float(row[c].iloc[0]) if c in row.columns else 0.0
    hits = []

    ssh_fail = g("ssh_fail_mean")
    ssh_ok = g("ssh_ok_mean")
    synrecv = g("synrecv_max")

    if ssh_fail >= 30 and ssh_ok < 1:
        hits.append(("위험", f"SSH 무차별 대입 의심 (실패 평균 {ssh_fail:.0f}, 성공 없음)"))
    elif ssh_fail >= 15 and ssh_ok < 1:
        hits.append(("경고", f"SSH 로그인 실패 급증 (실패 평균 {ssh_fail:.0f})"))

    if synrecv >= 20:
        hits.append(("위험", f"포트 스캔 의심 (SYN-RECV 최대 {synrecv:.0f})"))
    elif synrecv >= 8:
        hits.append(("경고", f"비정상 연결 시도 (SYN-RECV 최대 {synrecv:.0f})"))

    return hits


def top_contributors(row, feature_cols, scaler, n=3):
    x = row[feature_cols].values.astype(float)
    xs = scaler.transform(x.reshape(1, -1))[0]
    idx = np.argsort(-np.abs(xs))[:n]
    return ", ".join(f"{feature_cols[i]}({xs[i]:+.1f})" for i in idx)


def ensure_table():
    conn = pymysql.connect(**config.DB)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    time DATETIME NOT NULL,
                    host VARCHAR(50) NOT NULL,
                    score DOUBLE NOT NULL,
                    grade VARCHAR(10) NOT NULL,
                    source VARCHAR(20),
                    reason VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uq (time, host)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
        conn.commit()
    finally:
        conn.close()


def main():
    model = joblib.load(f"{MODEL_DIR}/iforest.pkl")
    scaler = joblib.load(f"{MODEL_DIR}/scaler.pkl")
    with open(f"{MODEL_DIR}/feature_cols.json") as f:
        feature_cols = json.load(f)

    row = load_recent_features()
    if row is None:
        print("[WARN] 최근 데이터가 부족해 판정할 수 없습니다.")
        return

    t = pd.to_datetime(row.index[0]).to_pydatetime()

    X = row[feature_cols].values.astype(float)
    Xs = scaler.transform(X)
    score = float(model.decision_function(Xs)[0])
    m_grade = model_grade(score)

    rule_hits = rule_check(row)

    candidates = [(m_grade, f"모델 이상점수 {score:+.4f}")]
    for g, why in rule_hits:
        candidates.append((g, why))
    final_grade, final_reason = max(candidates, key=lambda x: GRADE_ORDER[x[0]])

    if final_grade == m_grade and not any(GRADE_ORDER[g] >= GRADE_ORDER[m_grade] for g, _ in rule_hits):
        source = "model"
        reason = top_contributors(row.iloc[0], feature_cols, scaler) if m_grade != "정상" else "-"
    else:
        source = "rule"
        reason = final_reason

    ensure_table()
    conn = pymysql.connect(**config.DB)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO anomalies (time, host, score, grade, source, reason) "
                "VALUES (%s,%s,%s,%s,%s,%s) "
                "ON DUPLICATE KEY UPDATE score=VALUES(score), grade=VALUES(grade), "
                "source=VALUES(source), reason=VALUES(reason)",
                (t, HOST, score, final_grade, source, reason),
            )
        conn.commit()
    finally:
        conn.close()

    mark = {"정상": "[OK]", "경고": "[WARN]", "위험": "[DANGER]"}[final_grade]
    print(f"{mark} {t}  최종판정={final_grade}  (모델점수 {score:+.4f})")
    print(f"       근거[{source}]: {reason}")
    if rule_hits:
        for g, why in rule_hits:
            print(f"       룰감지: [{g}] {why}")


if __name__ == "__main__":
    main()
