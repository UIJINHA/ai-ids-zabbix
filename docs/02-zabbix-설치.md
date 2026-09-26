# 02. Zabbix 설치 및 DB 연동

## 설치 구성
- Zabbix 7.0 LTS (공식 저장소)
- 패키지: zabbix-server-mysql, zabbix-frontend-php, zabbix-apache-conf, zabbix-sql-scripts, zabbix-agent
- DB: MariaDB (DB명 zabbix, 전용 계정 zabbix@localhost)
- 웹: Apache2, http://192.168.199.10/zabbix

## 진행 순서
1. 공식 저장소 등록 후 패키지 설치
2. zabbix 전용 DB와 계정 생성, 권한 부여
3. 스키마 임포트 (server.sql.gz)
4. zabbix_server.conf 에 DB 비밀번호 설정
5. 설치 마법사에서 DB 연결 정보 입력, 타임존 Asia/Seoul 지정
6. 서비스 기동 및 자동 시작 등록

## 트러블슈팅: Zabbix server is not running

### 증상
웹 화면은 정상적으로 떴으나 하단에 Zabbix server is not running 배너가 표시되었다.
이 상태에서는 호스트를 등록해도 실제 데이터가 수집되지 않는다.

### 원인 확인
/var/log/zabbix/zabbix_server.log 를 확인한 결과 아래 로그가 10초 간격으로 반복되고 있었다.

    [Z3001] connection to database 'zabbix' failed: [1045] Access denied for user 'zabbix'@'localhost'

DB 계정 생성 시 지정한 비밀번호와 zabbix_server.conf 에 기입한 값이 일치하지 않았다.

한편 웹 프론트엔드는 정상 동작하고 있었는데, Zabbix가 DB 접속 정보를
두 곳에서 따로 관리하기 때문이었다.

- 서버 데몬: /etc/zabbix/zabbix_server.conf
- 웹 프론트엔드: /etc/zabbix/web/zabbix.conf.php

웹 화면이 뜬다고 해서 서버 데몬의 DB 연결까지 정상인 것은 아니었다.

### 조치
DB 계정의 비밀번호를 재설정하고, 두 설정 파일의 값을 동일하게 맞춘 뒤 서비스를 재시작했다.

### 배운 점
화면에 보이는 증상만으로 원인을 추정하지 않고 로그를 먼저 확인한 것이 해결의 시작이었다.
웹 화면이 떴으니 DB 연동도 됐다고 넘어갔다면 원인을 찾지 못했을 것이다.

또한 하나의 서비스가 같은 정보를 여러 설정 파일에 나눠 갖는 경우가 있어,
설정을 바꿀 때는 관련된 파일을 모두 확인해야 한다는 것을 알게 되었다.

## 결과
- Zabbix 서버 정상 기동, 웹 대시보드 접속 확인
- 기본 관리자 계정 Admin 의 초기 비밀번호 변경
