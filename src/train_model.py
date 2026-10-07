#!/usr/bin/env python3
"""
train_model.py
features 테이블의 정상 데이터로 Isolation Forest를 학습한다.
스케일러와 모델, 사용한 컬럼 목록을 파일로 저장한다.
"""

import os
import sys
import json
import joblib
import pandas as pd
import pymysql
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import config

CONTAMINATION = 0.01
MODEL_DIR = "model"


def load_features():
    conn = pymysql.connect(**config.DB)
    try:
        df = pd.read_sql("SELECT * FROM features ORDER BY clock", conn)
    finally:
        conn.close()
    return df


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    df = load_features()
    if df.empty:
        print("[ERROR] features 테이블이 비어 있습니다.")
        sys.exit(1)

    feature_cols = [c for c in df.columns if c != "clock"]
    X = df[feature_cols].values
    print(f"[INFO] 학습 데이터 {len(df)}개, Feature {len(feature_cols)}개")

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(Xs)

    joblib.dump(model, f"{MODEL_DIR}/iforest.pkl")
    joblib.dump(scaler, f"{MODEL_DIR}/scaler.pkl")
    with open(f"{MODEL_DIR}/feature_cols.json", "w") as f:
        json.dump(feature_cols, f, ensure_ascii=False, indent=2)

    scores = model.decision_function(Xs)
    preds = model.predict(Xs)
    n_out = int((preds == -1).sum())

    print(f"[INFO] contamination={CONTAMINATION}")
    print(f"[INFO] 학습 데이터 중 이상 판정: {n_out}개 ({n_out/len(df)*100:.1f}%)")
    print(f"[INFO] 이상점수 범위: {scores.min():.4f} ~ {scores.max():.4f}")
    print(f"[INFO] 모델 저장 완료 - {MODEL_DIR}/iforest.pkl, scaler.pkl, feature_cols.json")


if __name__ == "__main__":
    main()
