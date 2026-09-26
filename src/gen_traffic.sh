#!/bin/bash
# 감시 대상 서버에 평상시 웹 트래픽을 발생시킨다.
# 시간대별로 요청량을 다르게 주어 일간 주기를 만든다.

URL="http://192.168.199.20/"
HOUR=$((10#$(date +%H)))

if   [ "$HOUR" -lt 7 ];  then BASE=5      # 새벽: 거의 없음
elif [ "$HOUR" -lt 10 ]; then BASE=25     # 출근 시간
elif [ "$HOUR" -lt 19 ]; then BASE=80     # 업무 시간
elif [ "$HOUR" -lt 23 ]; then BASE=40     # 저녁
else                          BASE=12     # 심야
fi

# 같은 시간대라도 매번 조금씩 다르게
COUNT=$(( BASE + RANDOM % (BASE / 2 + 1) - BASE / 4 ))
[ "$COUNT" -lt 1 ] && COUNT=1

# 5분 주기 실행이므로 270초에 걸쳐 분산시킨다
for _ in $(seq 1 "$COUNT"); do
    curl -s -o /dev/null --max-time 5 "$URL"
    sleep "$(awk -v w=270 -v c="$COUNT" 'BEGIN{srand(); print (w/c)*(0.5+rand())}')"
done
