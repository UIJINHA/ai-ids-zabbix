#!/bin/bash
# 감시 대상 서버에 평상시 웹 트래픽을 발생시킨다.
# 시간대별로 부하 강도를 달리해 일간 주기를 만든다.
# ab로 app.php(연산 포함)를 호출하므로 CPU/네트워크가 함께 움직인다.

URL="http://192.168.199.20/app.php"
HOUR=$((10#$(date +%H)))

# 시간대별 동시 접속 수(부하 강도)
if   [ "$HOUR" -lt 7 ];  then CONC=2
elif [ "$HOUR" -lt 10 ]; then CONC=5
elif [ "$HOUR" -lt 19 ]; then CONC=10
elif [ "$HOUR" -lt 23 ]; then CONC=6
else                          CONC=3
fi

# 매번 조금씩 흔들어 같은 시간대라도 변동이 생기게 한다
CONC=$(( CONC + RANDOM % 3 - 1 ))
[ "$CONC" -lt 1 ] && CONC=1

# 5분 주기 안에서 60~120초 정도만 부하를 준다(계속 100%가 되지 않도록)
DURATION=$(( 60 + RANDOM % 60 ))

ab -c "$CONC" -t "$DURATION" -n 1000000 "$URL" > /dev/null 2>&1
