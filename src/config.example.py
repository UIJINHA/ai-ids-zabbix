# Zabbix API
ZABBIX_URL = "http://192.168.199.10/zabbix/api_jsonrpc.php"
ZABBIX_TOKEN = "여기에_발급받은_토큰"

# MariaDB
DB = {
    "host": "localhost",
    "user": "aiids",
    "password": "여기에_DB_비밀번호",
    "database": "aiids",
    "charset": "utf8mb4",
}

# 수집 대상 호스트 (Zabbix에 등록된 이름과 동일해야 함)
TARGET_HOSTS = ["vm2-target", "Zabbix server"]

# 한 번 실행할 때 몇 분치를 가져올지
COLLECT_MINUTES = 60
