#!/usr/bin/env python3
"""
build_features.py
metrics 테이블의 원시 지표를 30분 창(5분 슬라이딩)으로 집계해
평균·최대·표준편차 Feature를 만들고 features 테이블에 저장한다.
"""

import sys
import numpy as np
import pandas as pd
import pymysql
import config

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

HOST = "vm2-target"
WINDOW = "30min"


def load_raw():
    conn = pymysql.connect(**config.DB)
    try:
        sql = """
            SELECT clock, item_key, value
            FROM metrics
            WHERE host=%s AND item_key IN %s
            ORDER BY clock
        """
        df = pd.read_sql(sql, conn, params=(HOST, tuple(METRIC_KEYS)))
    finally:
        conn.close()
    return df


def build(df):
    df["clock"] = pd.to_datetime(df["clock"])
    wide = df.pivot_table(index="clock", columns="item_key", values="value", aggfunc="mean")
    wide = wide.rename(columns=SHORT)
    wide = wide.sort_index()

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
    out = out.reset_index().rename(columns={"index": "clock"})
    return out


def save(out):
    conn = pymysql.connect(**config.DB)
    try:
        with conn.cursor() as cur:
            cols = [c for c in out.columns if c != "clock"]
            cur.execute("DROP TABLE IF EXISTS features")
            coldef = ",\n".join([f"`{c}` DOUBLE" for c in cols])
            cur.execute(f"""
                CREATE TABLE features (
                    clock DATETIME PRIMARY KEY,
                    {coldef}
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            placeholders = ",".join(["%s"] * (len(cols) + 1))
            collist = "`clock`," + ",".join([f"`{c}`" for c in cols])
            rows = [tuple([r["clock"]] + [float(r[c]) for c in cols]) for _, r in out.iterrows()]
            cur.executemany(
                f"INSERT INTO features ({collist}) VALUES ({placeholders})",
                rows,
            )
        conn.commit()
    finally:
        conn.close()
    return len(out), len([c for c in out.columns if c != "clock"])


def main():
    df = load_raw()
    if df.empty:
        print("[ERROR] 원시 데이터가 없습니다.")
        sys.exit(1)
    print(f"[INFO] 원시 데이터 {len(df)}건 로드")
    out = build(df)
    if out.empty:
        print("[WARN] 생성된 Feature가 없습니다. 데이터 양을 확인하세요.")
        return
    n_rows, n_cols = save(out)
    print(f"[INFO] Feature 생성 완료 - 샘플 {n_rows}개, 컬럼 {n_cols}개")
    print(f"[INFO] 기간: {out['clock'].min()} ~ {out['clock'].max()}")


if __name__ == "__main__":
    main()
