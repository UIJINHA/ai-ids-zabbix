#!/bin/bash
# 평상시의 정상 SSH 로그인을 발생시킨다.
# 로그인 실패만 있고 성공이 전혀 없는 상태는 현실적이지 않기 때문이다.

TARGET="uijin@192.168.199.20"
HOUR=$((10#$(date +%H)))

# 시간대별로 로그인이 일어날 확률(%)
if   [ "$HOUR" -lt 7 ];  then CHANCE=10
elif [ "$HOUR" -lt 19 ]; then CHANCE=60
else                          CHANCE=30
fi

[ $((RANDOM % 100)) -ge "$CHANCE" ] && exit 0

COUNT=$(( RANDOM % 3 + 1 ))
for _ in $(seq 1 "$COUNT"); do
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$TARGET" "uptime" > /dev/null 2>&1
    sleep $(( RANDOM % 30 + 5 ))
done
