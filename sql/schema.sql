USE aiids;

-- Zabbix에서 수집한 원시 지표
CREATE TABLE IF NOT EXISTS metrics (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    host        VARCHAR(100) NOT NULL,
    item_key    VARCHAR(255) NOT NULL,
    clock       DATETIME     NOT NULL,
    value       DOUBLE,
    created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_metric (host, item_key, clock),
    INDEX idx_clock (clock),
    INDEX idx_host_key (host, item_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
