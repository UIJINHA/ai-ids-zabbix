#!/usr/bin/env python3
"""collect.py - Zabbix API로 수집한 지표를 MariaDB(aiids.metrics)에 저장한다."""

import sys
from datetime import datetime, timedelta

import requests
import pymysql

import config


def zbx(method, params):
    """Zabbix JSON-RPC 호출. 토큰은 Authorization 헤더로 전달한다."""
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    headers = {
        "Content-Type": "application/json-rpc",
        "Authorization": f"Bearer {config.ZABBIX_TOKEN}",
    }
    res = requests.post(config.ZABBIX_URL, json=payload, headers=headers, timeout=30)
    res.raise_for_status()
    data = res.json()
    if "error" in data:
        raise RuntimeError(f"Zabbix API 오류: {data['error']}")
    return data["result"]


def get_hosts():
    """설정에 적힌 호스트들의 hostid를 조회한다."""
    hosts = zbx("host.get", {
        "output": ["hostid", "host"],
        "filter": {"host": config.TARGET_HOSTS},
    })
    return {h["hostid"]: h["host"] for h in hosts}


def get_items(hostids):
    """숫자형 아이템만 가져온다. value_type 0=실수, 3=정수."""
    return zbx("item.get", {
        "output": ["itemid", "key_", "hostid", "value_type"],
        "hostids": list(hostids),
        "filter": {"value_type": [0, 3]},
        "monitored": True,
    })


def get_history(itemids, value_type, time_from):
    """지정 기간의 이력 데이터를 가져온다."""
    if not itemids:
        return []
    return zbx("history.get", {
        "output": "extend",
        "history": value_type,
        "itemids": itemids,
        "time_from": time_from,
        "sortfield": "clock",
        "sortorder": "ASC",
        "limit": 200000,
    })


def main():
    time_from = int((datetime.now() - timedelta(minutes=config.COLLECT_MINUTES)).timestamp())
    print(f"[INFO] 최근 {config.COLLECT_MINUTES}분 데이터를 수집합니다.")

    hosts = get_hosts()
    if not hosts:
        print("[ERROR] 대상 호스트를 찾지 못했습니다. config.TARGET_HOSTS 를 확인하세요.")
        sys.exit(1)
    print(f"[INFO] 호스트 {len(hosts)}개: {', '.join(hosts.values())}")

    items = get_items(hosts.keys())
    print(f"[INFO] 수집 대상 아이템 {len(items)}개")

    item_map = {i["itemid"]: (hosts[i["hostid"]], i["key_"]) for i in items}

    rows = []
    for value_type in (0, 3):
        itemids = [i["itemid"] for i in items if int(i["value_type"]) == value_type]
        history = get_history(itemids, value_type, time_from)
        print(f"[INFO] value_type={value_type} 이력 {len(history)}건")
        for h in history:
            host, key = item_map[h["itemid"]]
            rows.append((host, key, datetime.fromtimestamp(int(h["clock"])), float(h["value"])))

    if not rows:
        print("[WARN] 수집된 데이터가 없습니다. 잠시 후 다시 실행하세요.")
        return

    conn = pymysql.connect(**config.DB)
    try:
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT IGNORE INTO metrics (host, item_key, clock, value) VALUES (%s, %s, %s, %s)",
                rows,
            )
            inserted = cur.rowcount
        conn.commit()
        print(f"[INFO] 저장 완료 - 조회 {len(rows)}건, 신규 저장 {inserted}건")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
